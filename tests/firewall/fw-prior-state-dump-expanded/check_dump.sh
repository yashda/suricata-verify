#!/bin/sh
# Helper invoked from the suricata-verify shell check.
#
# Runs inside the fixture's output/ directory (where `stdout` is the
# Suricata dump run's captured stdout). Normalizes the two
# install-specific fields — the sub-SIDs (deterministic but computed
# from the absolute path of test.rules via FNV-1a, so they shift
# whenever the workspace root moves) and the absolute path itself — and
# diffs the normalized output against the checked-in dump.expected
# golden.
#
# Prints nothing on success so the `expect: ""` assertion in test.yaml
# is satisfied; on mismatch writes the unified diff to stderr and exits
# non-zero so the shell check fails with a readable error.

set -e

# stdout is the captured dump; the checked-in golden lives one dir up.
STDOUT_FILE="stdout"
GOLDEN="../dump.expected"

if [ ! -f "$STDOUT_FILE" ]; then
  echo "check_dump.sh: $STDOUT_FILE not found" >&2
  exit 1
fi
if [ ! -f "$GOLDEN" ]; then
  echo "check_dump.sh: $GOLDEN not found" >&2
  exit 1
fi

# Three substitutions plus a filter:
#   - every 8+ digit sid (runtime SIDs from PriorStateExpandSubRuntimeSid
#     live in [0x80000000, 0xffffffff], so they print as 10-digit
#     decimal values) becomes "<SUB>".
#   - every absolute path ending in "firewall.rules" becomes "<FILE>".
#   - Warning:/Notice:/Info: lines produced by the Suricata runtime
#     (firewall-mode experimental notice, missing threshold.config,
#     etc.) are install-specific noise and not part of the rule dump
#     we're comparing against the golden.
grep -v -E '^(Warning|Notice|Info|Error):' "$STDOUT_FILE" | \
sed -e 's|sid:[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*|sid:<SUB>|g' \
    -e 's|# sid [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]* (sub|# sid <SUB> (sub|g' \
    -e 's|/[^ ]*/firewall\.rules|<FILE>|g' \
    > stdout.normalized

# Compare. diff emits to stdout on mismatch, so capture and redirect.
if diff -u "$GOLDEN" stdout.normalized > diff.out 2>&1; then
  # success path — emit nothing so the shell check's `expect: ""` passes.
  exit 0
else
  cat diff.out >&2
  exit 1
fi
