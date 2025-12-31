#!/usr/bin/env bash

# N3ttrace

# Linux network watcher using only /proc + shell/coreutils.
# Displays a live, htop-like table (top 10 by risk) and logs the same table to ./net-apt-watch.log.txt
#
# What this tries to implement (within "bash + /proc" reality):
# - Connection lifetime histogram (tracks per-socket birth time).
# - "Connection birth certificate" (records once per new outbound socket inode).
# - Socket ancestry tracing (PID lineage + start-times to reduce restart lies).
# - "Zero-knowledge" audit trail (hashes endpoints in the persistent trail).
# - "Network time travel" (reconstruct snapshots from the log by timestamp).
# - Connection purpose inference (timing + context heuristics; no payload inspection).
#
# Notes:
# - Best results require root (to map sockets to processes reliably).
# - Linux only. No pcap, no DPI, no DNS lookups.

set -u
shopt -s extglob

LOG_FILE="${PWD}/n3ttrace.log.txt"
STATE_DIR="${PWD}/.n3ttrace_state"
mkdir -p "$STATE_DIR"

BIRTH_DB="${STATE_DIR}/birth_records.tsv"      # append-only, one record per inode
SEEN_DB="${STATE_DIR}/seen_inodes.txt"         # inode set
SNAP_DB="${STATE_DIR}/snapshots.tsv"           # reconstructable “network state timeline”

REFRESH_SEC="${REFRESH_SEC:-1}"
TOP_N="${TOP_N:-10}"

# Color map (Blue=Normal, Yellow=Anomaly, Red=Threat)
C_RESET=$'\033[0m'
C_BLUE=$'\033[34m'
C_YEL=$'\033[33m'
C_RED=$'\033[31m'
C_DIM=$'\033[2m'
C_BOLD=$'\033[1m'

# ---------- helpers ----------
now_epoch() { date +%s; }
now_iso()   { date +"%Y-%m-%d %H:%M:%S"; }

strip_ansi() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }

sha256_hex() {
  # stdin -> sha256 hex
  sha256sum 2>/dev/null | awk '{print $1}'
}

hex_to_ip() {
  # /proc/net/tcp stores IP little-endian hex (8 chars)
  local h="${1^^}"
  local a=$((16#${h:6:2})) b=$((16#${h:4:2})) c=$((16#${h:2:2})) d=$((16#${h:0:2}))
  printf "%d.%d.%d.%d" "$a" "$b" "$c" "$d"
}

hex_to_port() {
  local h="${1^^}"
  printf "%d" "$((16#$h))"
}

is_private_ipv4() {
  # RFC1918 + loopback + link-local
  local ip="$1"
  [[ "$ip" == 10.* ]] && return 0
  [[ "$ip" == 192.168.* ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  [[ "$ip" == 127.* ]] && return 0
  [[ "$ip" == 169.254.* ]] && return 0
  return 1
}

mask_endpoint() {
  # "zero-knowledge-ish": mask identity in persistent trail by hashing endpoint.
  # For display, show /24 + short hash so humans can correlate without revealing the IP outright.
  local ip="$1" port="$2"
  local subnet="${ip%.*}.0/24"
  local short
  short="$(printf "%s:%s" "$ip" "$port" | sha256_hex | cut -c1-8)"
  printf "%s #%s:%s" "$subnet" "$short" "$port"
}

pid_comm() { cat "/proc/$1/comm" 2>/dev/null | tr -d '\n' || echo "?"; }

pid_cmdline() {
  tr '\0' ' ' <"/proc/$1/cmdline" 2>/dev/null | sed 's/[[:space:]]\+$//' || echo ""
}

pid_cwd() {
  readlink "/proc/$1/cwd" 2>/dev/null || echo ""
}

pid_ppid_start() {
  # outputs: ppid starttime_ticks tty_nr
  # /proc/[pid]/stat: pid (comm) state ppid ... tty_nr ... starttime ...
  # We avoid parsing comm with spaces by cutting around ')'
  local stat
  stat="$(cat "/proc/$1/stat" 2>/dev/null || true)"
  [[ -z "$stat" ]] && { echo "0 0 0"; return; }
  local after="${stat#*) }"
  # fields in $after: state(1) ppid(2) pgrp(3) session(4) tty_nr(5) ...
  local ppid tty start
  ppid="$(awk '{print $2}' <<<"$after")"
  tty="$(awk '{print $5}' <<<"$after")"
  start="$(awk '{print $20}' <<<"$after")"
  echo "$ppid $start $tty"
}

env_hash() {
  # Hash /proc/pid/environ without storing it (privacy)
  local pid="$1"
  if [[ -r "/proc/$pid/environ" ]]; then
    tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sha256_hex
  else
    echo ""
  fi
}

get_ancestry() {
  # outputs: lineage_string ancestry_id
  # lineage_string: pid:comm[start] <- ppid:comm[start] <- ...
  local pid="$1"
  local max=12
  local lineage=""
  local entropy=""
  local cur="$pid"
  for ((i=0;i<max;i++)); do
    [[ "$cur" -le 1 ]] && break
    local comm ppid start tty
    comm="$(pid_comm "$cur")"
    read -r ppid start tty < <(pid_ppid_start "$cur")
    lineage+="${cur}:${comm}[${start}]"
    entropy+="${cur}:${comm}:${start}|"
    [[ "$ppid" =~ ^[0-9]+$ ]] || break
    [[ "$ppid" -le 1 ]] && { lineage+=" <- ${ppid}:init"; break; }
    lineage+=" <- "
    cur="$ppid"
  done
  local aid
  aid="$(printf "%s" "$entropy" | sha256_hex | cut -c1-12)"
  printf "%s\t%s" "$lineage" "$aid"
}

purpose_infer() {
  # heuristics based on cmdline, tty, comm
  local comm="$1" cmd="$2" tty="$3"
  local c="${cmd,,}"
  local p="background service"
  if [[ "$tty" != "0" && "$tty" != "-1" ]]; then
    p="user action"
  fi
  [[ "$c" =~ (apt|dnf|yum|pacman|zypper|snap|flatpak|packagekit|unattended) ]] && p="update check"
  [[ "$c" =~ (telemetry|metrics|sentry|datadog|newrelic|prometheus|opentelemetry|statsd|segment) ]] && p="telemetry"
  [[ "$comm" =~ ^(sshd|systemd|cron|crond|dbus|NetworkManager|dockerd|containerd)$ ]] && p="background service"
  printf "%s" "$p"
}

risk_score_and_level() {
  # Inputs: duration_sec remote_port remote_ip comm cmd ppid_lineage
  local dur="$1" rport="$2" rip="$3" comm="$4" cmd="$5" ancestry="$6"
  local score=0
  local c="${cmd,,}"
  local k="${comm,,}"

  # lifetime heuristic: if 90% < 3s, long-lived ones are interesting
  (( dur > 3 )) && ((score+=15))
  (( dur > 30 )) && ((score+=20))
  (( dur > 300 )) && ((score+=25))
  (( dur > 3600 )) && ((score+=30))

  # public egress tends to be higher scrutiny
  if ! is_private_ipv4 "$rip"; then
    ((score+=10))
  fi

  # “classic” suspicious ports (defensive heuristic)
  case "$rport" in
    22|23|2323|3389|4444|5555|6666|1337|31337) ((score+=25));;
    53|123) ((score+=5));;
    80|443) ((score+=0));;
    *) ((score+=5));;
  esac

  # suspicious processes (defensive: catching living-off-the-land reverse shells/tunnels)
  [[ "$k" =~ ^(bash|sh|dash|zsh|ksh)$ ]] && ((score+=25))
  [[ "$k" =~ ^(python|perl|ruby|php|node|java)$ ]] && ((score+=10))
  [[ "$k" =~ ^(nc|ncat|netcat|socat|curl|wget)$ ]] && ((score+=25))
  [[ "$c" =~ (ssh.*-R|ssh.*-D|socat|/dev/tcp|mkfifo|pty|powershell) ]] && ((score+=25))

  # ancestry oddities: if lineage includes shells/interactive + network utils
  [[ "${ancestry,,}" =~ (bash|sh|zsh).*(curl|wget|nc|socat|python|perl) ]] && ((score+=15))

  local level="NORMAL"
  if (( score >= 70 )); then level="THREAT"
  elif (( score >= 35 )); then level="ANOMALY"
  fi
  printf "%s\t%d" "$level" "$score"
}

ensure_header_files() {
  if [[ ! -f "$BIRTH_DB" ]]; then
    printf "ts_iso\tinode\tlocal\tremote\tpid\tcomm\tppid\tcwd\tcmdline\tenv_sha256\tancestry_id\n" >"$BIRTH_DB"
  fi
  [[ -f "$SEEN_DB" ]] || : >"$SEEN_DB"
  if [[ ! -f "$SNAP_DB" ]]; then
    printf "ts_iso\tinode\tr_state\tduration_s\tlocal\tremote_masked\tpid\tcomm\tancestry_id\tlevel\tscore\tpurpose\n" >"$SNAP_DB"
  fi
  if [[ ! -f "$LOG_FILE" ]]; then
    {
      echo "net-apt-watch log started: $(now_iso)"
      echo
    } >"$LOG_FILE"
  fi
}

build_inode_pid_map() {
  # Prints lines: inode<TAB>pid
  # Expensive; root recommended.
  # We only need current sockets, but /proc doesn't give inode->pid directly, so we scan fd links.
  local pid fd link inode
  for pid in /proc/[0-9]*; do
    pid="${pid##*/}"
    [[ -d "/proc/$pid/fd" ]] || continue
    for fd in /proc/"$pid"/fd/*; do
      link="$(readlink "$fd" 2>/dev/null || true)"
      [[ "$link" == socket:\[*\] ]] || continue
      inode="${link#socket:[}"
      inode="${inode%]}"
      printf "%s\t%s\n" "$inode" "$pid"
    done
  done
}

parse_proc_net_tcp_established() {
  # Emits: inode<TAB>local_ip:port<TAB>remote_ip:port<TAB>state_hex
  # We treat outbound candidates where remote != 0.0.0.0 and state==01 (ESTABLISHED) or 02 (SYN_SENT) etc.
  # /proc/net/tcp columns:
  # sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ...
  awk 'NR>1 {print $2 "\t" $3 "\t" $4 "\t" $10}' /proc/net/tcp 2>/dev/null | while IFS=$'\t' read -r laddr raddr st inode; do
    local lip_hex="${laddr%:*}" lport_hex="${laddr#*:}"
    local rip_hex="${raddr%:*}" rport_hex="${raddr#*:}"
    local lip rip lport rport
    lip="$(hex_to_ip "$lip_hex")"
    rip="$(hex_to_ip "$rip_hex")"
    lport="$(hex_to_port "$lport_hex")"
    rport="$(hex_to_port "$rport_hex")"
    printf "%s\t%s:%s\t%s:%s\t%s\n" "$inode" "$lip" "$lport" "$rip" "$rport" "$st"
  done
}

inode_birth_time_get() {
  local inode="$1"
  local f="${STATE_DIR}/inode_${inode}.birth"
  [[ -f "$f" ]] && cat "$f" || echo ""
}

inode_birth_time_set_if_new() {
  local inode="$1"
  local t="$2"
  local f="${STATE_DIR}/inode_${inode}.birth"
  [[ -f "$f" ]] || echo "$t" >"$f"
}

seen_inode() {
  local inode="$1"
  grep -qxF "$inode" "$SEEN_DB" 2>/dev/null
}

mark_seen_inode() {
  local inode="$1"
  echo "$inode" >>"$SEEN_DB"
}

write_birth_certificate_once() {
  # inode local remote pid comm ppid cwd cmd envhash ancestry_id
  local ts="$1" inode="$2" local_ep="$3" remote_ep="$4" pid="$5" comm="$6" ppid="$7" cwd="$8" cmd="$9" envh="${10}" aid="${11}"
  if ! seen_inode "$inode"; then
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "$ts" "$inode" "$local_ep" "$remote_ep" "$pid" "$comm" "$ppid" "$cwd" "$cmd" "$envh" "$aid" >>"$BIRTH_DB"
    mark_seen_inode "$inode"
  fi
}

print_table() {
  # expects preformatted rows array (already colored for terminal)
  local ts="$1"; shift
  local -a rows=("$@")

  # Clear screen and draw header
  printf "\033[H\033[2J"
  printf "%s%snet-apt-watch%s  %s%s%s  (top %s, refresh %ss)\n" \
    "$C_BOLD" "$C_BLUE" "$C_RESET" "$C_DIM" "$ts" "$C_RESET" "$TOP_N" "$REFRESH_SEC"

  printf "%s\n" "┌────┬─────────┬───────────┬───────────────┬──────────────────────────┬──────┬──────────────┬──────────────┬──────────┬─────┬───────────────┐"
  printf "│ %-2s │ %-7s │ %-9s │ %-13s │ %-24s │ %-4s │ %-12s │ %-12s │ %-8s │ %-3s │ %-13s │\n" \
    "LV" "DUR(s)" "STATE" "REMOTE" "PROC" "PID" "ANCESTRY_ID" "PURPOSE" "RISK" "S" "LOCAL"
  printf "%s\n" "├────┼─────────┼───────────┼───────────────┼──────────────────────────┼──────┼──────────────┼──────────────┼──────────┼─────┼───────────────┤"

  local r
  for r in "${rows[@]}"; do
    printf "%s\n" "$r"
  done
  printf "%s\n" "└────┴─────────┴───────────┴───────────────┴──────────────────────────┴──────┴──────────────┴──────────────┴──────────┴─────┴───────────────┘"
}

log_table() {
  # log the exact same thing, but without ANSI color codes (still includes headers)
  local ts="$1"; shift
  local -a rows=("$@")
  {
    echo "=== ${ts} ==="
    echo "LV | DUR(s) | STATE | REMOTE(masked) | PROC | PID | ANCESTRY_ID | PURPOSE | RISK | S | LOCAL"
    local r
    for r in "${rows[@]}"; do
      echo "$r" | strip_ansi
    done
    echo
  } >>"$LOG_FILE"
}

render_row() {
  # Inputs:
  # level duration state remote_masked proc pid ancestry_id purpose score local
  local level="$1" dur="$2" state="$3" remote="$4" proc="$5" pid="$6" aid="$7" purpose="$8" score="$9" local_ep="${10}"

  local color="$C_BLUE"
  [[ "$level" == "ANOMALY" ]] && color="$C_YEL"
  [[ "$level" == "THREAT"  ]] && color="$C_RED"

  local lv
  case "$level" in
    NORMAL) lv="BL";;
    ANOMALY) lv="YL";;
    THREAT) lv="RD";;
    *) lv="??";;
  esac

  # fixed-width formatting inside the drawn box
  printf "│ %s%-2s%s │ %s%7s%s │ %-9s │ %-13s │ %-24s │ %-4s │ %-12s │ %-12s │ %s%-8s%s │ %3s │ %-13s │" \
    "$color" "$lv" "$C_RESET" \
    "$color" "$dur" "$C_RESET" \
    "$state" "$remote" \
    "$(printf "%.24s" "$proc")" "$pid" "$aid" "$(printf "%.12s" "$purpose")" \
    "$color" "$level" "$C_RESET" \
    "$score" "$(printf "%.13s" "$local_ep")"
}

histogram_summary() {
  # prints something like:
  # "90% < 3s" and "longest XhYm"
  # based on currently tracked inode birth times for active sockets (not all-time).
  local now="$1"
  local -a durs=()
  local f
  for f in "${STATE_DIR}"/inode_*.birth; do
    [[ -f "$f" ]] || continue
    local t; t="$(cat "$f" 2>/dev/null || true)"
    [[ "$t" =~ ^[0-9]+$ ]] || continue
    durs+=($((now - t)))
  done
  ((${#durs[@]}==0)) && { echo "No active durations tracked yet"; return; }

  # sort durations
  IFS=$'\n' read -r -d '' -a sorted < <(printf "%s\n" "${durs[@]}" | sort -n && printf '\0')
  local n="${#sorted[@]}"
  local idx=$(( (n*90 + 99)/100 - 1 )); ((idx<0)) && idx=0; ((idx>=n)) && idx=$((n-1))
  local p90="${sorted[$idx]}"
  local max="${sorted[$((n-1))]}"

  fmt_dur() {
    local s="$1"
    local h=$((s/3600)) m=$(((s%3600)/60)) sec=$((s%60))
    if ((h>0)); then printf "%dh%02dm" "$h" "$m"
    elif ((m>0)); then printf "%dm%02ds" "$m" "$sec"
    else printf "%ds" "$sec"
    fi
  }

  echo "Lifetime histogram (active set): p90=$(fmt_dur "$p90"), longest=$(fmt_dur "$max")"
}

# ---------- time travel query ----------
if [[ "${1:-}" == "--at" ]]; then
  ensure_header_files
  query="${2:-}"
  if [[ -z "$query" ]]; then
    echo "Usage: $0 --at 'YYYY-mm-dd HH:MM[:SS]'"
    exit 2
  fi
  # Find closest snapshot <= query time (lexicographic works for ISO timestamps)
  # Show top 50 lines of that snapshot time.
  ts="$query"
  echo "Reconstructing network state at or before: $ts"
  awk -F'\t' -v ts="$ts" 'NR>1 && $1<=ts {t=$1} END{print t}' "$SNAP_DB" | while read -r chosen; do
    if [[ -z "$chosen" ]]; then
      echo "No snapshots available before that time. Check $SNAP_DB"
      exit 1
    fi
    echo "Closest snapshot time: $chosen"
    echo
    awk -F'\t' -v c="$chosen" 'NR==1 || $1==c {print}' "$SNAP_DB" | column -t -s $'\t' | head -n 60
  done
  exit 0
fi

# ---------- main loop ----------
ensure_header_files

# Cursor control
tput civis 2>/dev/null || true
trap 'tput cnorm 2>/dev/null || true; echo; exit' INT TERM

while :; do
  TS_ISO="$(now_iso)"
  NOW="$(now_epoch)"

  # Build inode->pid map
  # (If not root, this may be incomplete; still useful for raw connection view.)
  declare -A INODE2PID=()
  while IFS=$'\t' read -r inode pid; do
    [[ -n "$inode" && -n "$pid" ]] || continue
    INODE2PID["$inode"]="$pid"
  done < <(build_inode_pid_map 2>/dev/null)

  # Parse current tcp sockets
  # We’ll rank by risk score and show top 10.
  # We’ll also write a snapshot line for every active connection (masked remote).
  tmp_rows="${STATE_DIR}/.rows.$$"
  : >"$tmp_rows"

  # Snapshot header not repeated in SNAP_DB (already has one)
  # but we append rows for each refresh.
  while IFS=$'\t' read -r inode local_ep remote_ep st_hex; do
    # Track birth time per inode for lifetime
    inode_birth_time_set_if_new "$inode" "$NOW"
    birth="$(inode_birth_time_get "$inode")"
    [[ "$birth" =~ ^[0-9]+$ ]] || birth="$NOW"
    dur=$((NOW - birth))

    # Determine pid (best-effort)
    pid="${INODE2PID[$inode]:-0}"
    comm="?"
    cmd=""
    cwd=""
    ppid="0"
    tty="0"
    ancestry=""
    aid="????????????"
    purpose="background service"
    envh=""

    if [[ "$pid" != "0" && -d "/proc/$pid" ]]; then
      comm="$(pid_comm "$pid")"
      cmd="$(pid_cmdline "$pid")"
      cwd="$(pid_cwd "$pid")"
      read -r ppid _start tty < <(pid_ppid_start "$pid")
      IFS=$'\t' read -r ancestry aid < <(get_ancestry "$pid")
      purpose="$(purpose_infer "$comm" "$cmd" "$tty")"
      envh="$(env_hash "$pid")"
      # Birth certificate (exactly once per inode)
      write_birth_certificate_once "$TS_ISO" "$inode" "$local_ep" "$remote_ep" "$pid" "$comm" "$ppid" "$cwd" "$cmd" "$envh" "$aid"
    fi

    # parse remote ip/port for scoring + masking
    rip="${remote_ep%:*}"
    rport="${remote_ep##*:}"
    remote_masked="$(mask_endpoint "$rip" "$rport")"

    # Risk scoring
    IFS=$'\t' read -r level score < <(risk_score_and_level "$dur" "$rport" "$rip" "$comm" "$cmd" "$ancestry")

    # State decode (we focus on ESTABLISHED but keep others)
    state="TCP"
    [[ "$st_hex" == "01" ]] && state="ESTABL"
    [[ "$st_hex" == "02" ]] && state="SYN-SNT"
    [[ "$st_hex" == "03" ]] && state="SYN-RCV"
    [[ "$st_hex" == "04" ]] && state="FIN-W1"
    [[ "$st_hex" == "05" ]] && state="FIN-W2"
    [[ "$st_hex" == "06" ]] && state="TIMEWT"
    [[ "$st_hex" == "07" ]] && state="CLOSE"
    [[ "$st_hex" == "08" ]] && state="CLOSEWT"
    [[ "$st_hex" == "09" ]] && state="LASTACK"
    [[ "$st_hex" == "0A" ]] && state="LISTEN"

    proc_disp="${comm}"
    [[ -n "$cmd" ]] && proc_disp="${comm} :: ${cmd}"

    # Write snapshot (masked remote)
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "$TS_ISO" "$inode" "$state" "$dur" "$local_ep" "$remote_masked" "$pid" "$comm" "$aid" "$level" "$score" "$purpose" >>"$SNAP_DB"

    # Prepare rank line: score<TAB>rendered_row<TAB>for table
    row="$(render_row "$level" "$dur" "$state" "$(printf "%.13s" "$remote_masked")" "$proc_disp" "$pid" "$aid" "$purpose" "$score" "$local_ep")"
    printf "%s\t%s\n" "$score" "$row" >>"$tmp_rows"
  done < <(parse_proc_net_tcp_established)

  # Sort by score desc, take TOP_N
  mapfile -t TOP_ROWS < <(sort -nr -k1,1 "$tmp_rows" | head -n "$TOP_N" | cut -f2-)

  # Add histogram line above table by reusing the main title line
  # (We keep it in the screen header; also log it.)
  hist="$(histogram_summary "$NOW")"

  # Print
  printf "\033[H\033[2J"
  printf "%s%snet-apt-watch%s  %s%s%s  (%s)\n" \
    "$C_BOLD" "$C_BLUE" "$C_RESET" "$C_DIM" "$TS_ISO" "$C_RESET" "$hist"
  printf "%s\n" "┌────┬─────────┬───────────┬───────────────┬──────────────────────────┬──────┬──────────────┬──────────────┬──────────┬─────┬───────────────┐"
  printf "│ %-2s │ %-7s │ %-9s │ %-13s │ %-24s │ %-4s │ %-12s │ %-12s │ %-8s │ %-3s │ %-13s │\n" \
    "LV" "DUR(s)" "STATE" "REMOTE" "PROC" "PID" "ANCESTRY_ID" "PURPOSE" "RISK" "S" "LOCAL"
  printf "%s\n" "├────┼─────────┼───────────┼───────────────┼──────────────────────────┼──────┼──────────────┼──────────────┼──────────┼─────┼───────────────┤"
  for r in "${TOP_ROWS[@]}"; do
    printf "%s\n" "$r"
  done
  printf "%s\n" "└────┴─────────┴───────────┴───────────────┴──────────────────────────┴──────┴──────────────┴──────────────┴──────────┴─────┴───────────────┘"

  # Also log (ANSI stripped, includes histogram note)
  {
    echo "=== ${TS_ISO} ==="
    echo "${hist}"
    echo "LV | DUR(s) | STATE | REMOTE(masked) | PROC | PID | ANCESTRY_ID | PURPOSE | RISK | S | LOCAL"
    for r in "${TOP_ROWS[@]}"; do
      echo "$r" | strip_ansi
    done
    echo
  } >>"$LOG_FILE"

  rm -f "$tmp_rows" 2>/dev/null || true
  sleep "$REFRESH_SEC"
done