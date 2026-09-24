# AGENTS.windows-port.md

## Mission

Create a native Windows execution path for vphone-cli without falsifying progress. Preserve upstream behavior where practical, isolate platform-specific code, and require executable evidence for every PASS.

## Non-negotiable review method

Every phase must answer these Socratic questions before implementation is accepted:

1. What exact assumption are we testing?
2. What evidence would prove the assumption false?
3. What is the smallest executable experiment that can answer it?
4. What are the inputs, expected outputs, and invariants?
5. What must reconcile byte-for-byte, field-for-field, or behavior-for-behavior with upstream?
6. Which failure modes can silently look like success?
7. What instrumentation captures those failures?
8. What is the rollback boundary?
9. Which claims are measured, which are inferred, and which remain unknown?
10. Does the change weaken a security boundary or depend on an undocumented bypass? If yes, stop and document instead of silently adding it.

## Phase gate policy

- Never mark PASS from code inspection alone when runtime evidence is possible.
- A test that did not execute is NOT TESTED, not PASS.
- A skipped test is SKIPPED, not PASS.
- An unsupported host is BLOCKED, not PASS.
- Do not advance a phase when its blocking acceptance criteria fail.
- Keep upstream behavior as the reconciliation baseline.
- Preserve a machine-readable evidence folder under `artifacts/evidence/<phase>/`.
- Record commands, exit codes, hashes, logs, and environment versions.
- Never bundle Apple firmware or proprietary blobs in the repository.

## Branch discipline

- `main`: upstream sync only.
- `windows-port`: integration branch.
- `phase/<nn>-<slug>`: one gate at a time.
- Every phase PR must update `PORTING_STATUS.md` and attach evidence.
