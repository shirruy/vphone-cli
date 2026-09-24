# Master Prompt: Native Windows Port of vphone-cli

You are working on a fork of `Lakr233/vphone-cli`. The mission is to create a native Windows path while preserving upstream semantics and proving every compatibility claim with executable evidence.

Read first:
1. `AGENTS.md`
2. `AGENTS.windows-port.md`
3. `docs/PORTABILITY_AUDIT.md`
4. `docs/WINDOWS_PORT_MASTER_PLAN.md`
5. `docs/PHASE_GATES.md`
6. `PORTING_STATUS.md`

Rules:

- Follow phases in order. Do not skip a failing gate.
- Use the Socratic questions in `AGENTS.windows-port.md` before each implementation decision.
- Never mark PASS without executable evidence.
- Preserve the existing `vphone-cli` -> `vphone-vm` process boundary as the default architecture unless evidence proves it unsuitable.
- First objective is **not** a GUI. First objective is a deterministic Windows boot milestone with serial evidence.
- Treat Windows x64 and Windows ARM64 as distinct execution tiers. On x64, use TCG for ARM64 correctness research. Evaluate WHPX acceleration on Windows ARM64 only after the device model is correct.
- Investigate QEMU upstream `vmapple` and current Apple-Silicon QEMU research such as `qemu-sptm/darwin-vm` before writing new device models. Reuse only license-compatible code and preserve attribution.
- Do not redistribute Apple firmware or proprietary blobs.
- Do not add or automate host security bypasses. Document blockers instead.
- Any firmware/signing/archive/restore transformation that is ported must reconcile against upstream fixtures with hashes or normalized semantic comparisons.
- Keep evidence in `artifacts/evidence/<phase>/` with commands, logs, exit codes, tool versions, hashes, and machine-readable results.
- Update `PORTING_STATUS.md` after every completed experiment.

Start with Phase 0/1 only. Produce:
- exact upstream SHA;
- complete target/file dependency census;
- platform classification for every compile unit;
- Windows compile proof for the smallest portable module;
- defects/blockers discovered;
- evidence packet;
- go/no-go decision for Phase 2.

Continue automatically to the next phase only when the current phase is PASS. If a gate fails, stop implementation at that gate, diagnose root cause, and propose the smallest next experiment. Do not paper over a failure with a stub and call it done.
