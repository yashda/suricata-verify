# fw-prior-state-dump-expanded

POC Suricata-verify fixture for task 8.3 (spec:
`.kiro/specs/firewall-rule-templates/tasks.md`).

Runs Suricata with `--dump-expanded-rules` against a rule file that
contains the two POC Prior_State_Rules (the same rules exercised
against real packets by the fixtures in tasks 8.1 and 8.2), captures
stdout, normalizes install-specific fields, and diffs the result
against a checked-in `dump.expected` golden file.

## What this validates

Per design §Worked Example:

- The TLS SNI `.amazon.com` rule expands into the 12-rule set: 4 TCP
  handshake rules (syn / syn-ack / ack / post-handshake-passthrough) +
  7 TLS prerequisite rules (`client_in_progress` + six server-side
  states up to completion) + 1 Decision_Hook rule.
- The DNS query `.amazon.com` rule expands into the 10-rule
  multi-transport set: 4 TCP handshake rules + 2 UDP transport rules
  (`udp-to-server` / `udp-to-client`) + 3 DNS prerequisite rules
  (`request_started`, `response_started`, `response_complete`) +
  1 Decision_Hook rule. DNS is registered on both TCP and UDP
  (`rust/src/dns/dns.rs:1282` for UDP, `:1329` for TCP), and the
  expander emits the handshake for every supported transport so a
  single Prior_State_Rule permits the flow regardless of which
  transport the traffic actually arrives on (Req 1.3). Transports are
  emitted in the stable `{TCP, UDP}` order documented in design
  §Expansion Algorithm Step 2.
- Every auto-accepted rule contains `noalert;` in its options block,
  enforcing the customer-facing SID abstraction (design Decision 2) at
  the Signature level. The Decision_Hook rules do not carry `noalert;`.
- Every auto-accepted rule carries the design §Components.8 attribution
  comment in the form
  `# sid N (sub PARENT.K: <label>), auto-accepted, from file:lineno`.
- Every Decision_Hook rule carries
  `# sid N (parent), from <proto:state at file:lineno`.

## Why normalisation is necessary

Per design §Expansion Algorithm Step 5, the runtime SIDs of auto-accepted
rules are derived deterministically from the rule file's path via
FNV-1a:

```
sub_runtime_sid = 0x80000000 | (fnv1a32(file) ^ parent_sid ^ sub_index) & 0x7fffffff
```

Because the path depends on where the workspace is checked out, the
concrete integer values shift across installs. The golden file
therefore stores `<SUB>` in place of each runtime SID and `<FILE>` in
place of the absolute path; `check_dump.sh` runs the same substitutions
on the captured stdout before diffing.

## Files

- `test.rules` — two Prior_State_Rules (TLS SNI + DNS query), identical
  to the ones exercised against packets by tasks 8.1 and 8.2. Lines
  11 and 12 are the two rules (the file's leading comment block holds
  lines 1–10 stable).
- `suricata.yaml` — minimal config enabling firewall mode; no output
  modules are required because `--dump-expanded-rules` writes only
  stdout and exits before packet capture.
- `dump.expected` — the checked-in golden dump (two worked-example
  expansions, 12 + 10 = 22 rule lines plus their attribution comments)
  with `<SUB>` / `<FILE>` placeholders. Every auto-accepted rule line
  carries `noalert;` in its options block; the two Decision_Hook lines
  do not.
- `check_dump.sh` — normalizes the captured stdout and diffs it
  against `dump.expected`; invoked from the shell check in
  `test.yaml`. Emits the unified diff on mismatch.
- `test.yaml` — runs Suricata with `--dump-expanded-rules`, then
  six shell checks: the golden-file diff + parent-SID attribution
  grep + sub-rule counts (11 TLS, 9 DNS) + `noalert;` presence/absence
  counts.

## Relation to the in-tree implementation

The golden file matches the design rather than any particular snapshot
of the implementation. Task 8 updates fixtures; task 9 is the POC exit
gate that actually runs `suricata` against these fixtures. If the
in-tree `prior-state-expand.c` at the time of the exit gate emits a
different rule set (for example, if it does not yet iterate every
transport in the protocol's registered set, or if it does not yet append
`noalert;` to every auto-accepted rule), the mismatch surfaces at the
task 9 exit gate for the user to act on — either by updating the
implementation to match the design or by updating the design / golden.
