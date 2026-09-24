# Strict Phase Gates

## Required evidence packet per phase

Each phase must produce:

- `environment.json`: OS, CPU architecture, tool versions, backend commit hashes;
- `commands.txt`: exact commands executed;
- `stdout.log` and `stderr.log`;
- `exit_codes.json`;
- `hashes.sha256`: relevant binaries and inputs;
- `results.json`: machine-readable assertions;
- `review.md`: Socratic answers, defects, limitations, and disposition.

## Status vocabulary

Only these states are allowed:

- PASS
- FAIL
- BLOCKED
- NOT_TESTED
- PARTIAL_PASS, only when individual subcriteria are separately enumerated

Forbidden substitutes: "looks good", "should work", "code complete", "probably fixed", "logic verified" without runtime evidence.

## Reconciliation rules

For transformations, compare hashes where byte equality is expected. Where output is nondeterministic by design, document the permitted nondeterminism and compare normalized semantic fields.

For VM behavior, define observable milestones before running the test. Logs collected after the fact cannot move the goalposts.
