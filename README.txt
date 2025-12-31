N3ttrace

N3ttrace is a host-based network ancestry and lifetime tracing tool designed for
defenders, incident responders, and blue teams who need ground-truth visibility
into outbound network behavior without relying on packet capture, deep packet
inspection, or external agents.

N3ttrace focuses on what cannot be hidden:
- time
- process lineage.
- execution context.
- persistence

It is intentionally minimal, dependency-free, and hard to evade.

Core Capabilities

1. Connection Lifetime Histogram
N3ttrace continuously tracks the birth time of every observed outbound socket and
computes live duration statistics.

Displayed in real time:
- 90th percentile (p90) connection lifetime.
- Longest-lived active connection.

This alone reliably surfaces:
- Hidden tunnels.
- Stuck backchannels.
- Reverse shells.
- Long-lived C2 channels.

No payload inspection is required.

2. Connection Birth Certificates
For every outbound connection, N3ttrace records exactly once:

- Process name.
- Parent PID.
- Current working directory.
- Full command line.
- Environment hash (SHA-256).
- Stable ancestry identifier.

These records are:
- Append-only.
- Verifiable
- Queryable long after the fact.

This data is written once per socket and never rewritten, providing incident-grade
forensic context that most teams only realize they needed after compromise.

3. Socket Ancestry Tracing
N3ttrace does not ask “who owns this socket now?”

It answers:
“Which process lineage caused this socket to exist?”

Process trees can lie after restarts or PID reuse.
Ancestry hashes derived from process start times do not.

This allows reliable attribution even across daemonization, re-parenting, or
user-driven execution chains.

4. Zero-Knowledge Network Audit Trail
N3ttrace records:
- Who talked to where.
- When
- For how long.

Without recording:
- Payloads
- Domains
- Raw endpoint identities.

Remote endpoints are masked and hashed, allowing correlation without exposing sensitive network or identity data.

This design supports long-term retention and compliance while remaining useful for threat hunting.

5. Network Time Travel
N3ttrace maintains a reconstructable timeline of network state.

You can query:
“What was this host allowed to talk to at 14:32 yesterday?”

This is not event logging and not packet capture.
It is a replayable state history built from invariant measurements.

6. Connection Purpose Inference
Using timing, execution context, and lineage, N3ttrace infers connection purpose:

- Update check.
- Telemetry
- User action.
- Background service.

This inference is content-agnostic and does not inspect traffic, relying instead on
how and when the connection was created.

Threat Detection Model

N3ttrace detects threats by combining:
- Connection longevity.
- Unusual process-to-network relationships.
- Living-off-the-land binaries.
- Background shell activity.
- Suspicious ancestry chains.

This approach is effective against:
- Backchannels
- Encrypted C2 over HTTPS.
- Reverse shells.
- Tunnels and beacons.
- User-driven intrusions.

It is not signature-based and does not rely on indicators of compromise.

Requirements

- Linux system.
- Bash shell.
- Access to /proc.
- Root privileges.

N3ttrace MUST be run with sudo to reliably map sockets to processes and
ancestry information.

Example: sudo ./n3ttrace.sh

Running without sudo will result in incomplete attribution and reduced accuracy.

Files and Output

- n3ttrace.sh
  Main executable script.

- ./n3ttrace.log.txt
  Human-readable rolling table output (ANSI stripped).

- ./.n3ttrace_state/birth_records.tsv
  Append-only connection birth certificates.

- ./.n3ttrace_state/snapshots.tsv
  Reconstructable network state timeline.

Intended Use

N3ttrace is designed for:
- Defensive security research.
- Incident response.
- Blue-team monitoring.
- Threat hunting.
- Forensic readiness.

It is not a firewall, IPS, or prevention tool.
It provides visibility and attribution, not enforcement.

Legal Disclaimer

N3ttrace is provided “as is”, without warranty of any kind, express or implied.

This software is intended solely for defensive, lawful, and authorized use on
systems you own or are explicitly permitted to monitor.

The authors and contributors assume no responsibility or liability for:
- Misuse of this software.
- Unauthorized monitoring.
- Violations of privacy, policy, or law.
- Operational or legal consequences arising from its use.

By using N3ttrace, you acknowledge that:
- You are responsible for complying with all applicable laws and regulations.
- You understand the risks of using security monitoring tools.
- You accept full responsibility for its use and results.

Use responsibly.