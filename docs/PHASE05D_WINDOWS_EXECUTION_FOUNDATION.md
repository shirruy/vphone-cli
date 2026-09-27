# Phase 5D Windows ARM64 Execution Foundation

## Purpose

Phase 5D establishes the physical Windows process-execution
foundation required before attempting an Apple guest boot milestone.

This phase deliberately tests one narrow assumption:

> Can the Windows host instantiate the selected QEMU AArch64
> execution provider, initialize the generic `virt` machine with
> TCG, keep the process alive under a controlled headless state,
> observe that state, and terminate it deterministically?

## Certified parent

Phase 5C:

`684df0c3124434dd22fcbde9230df20407c6e21f`

## Executable acceptance criteria

Phase 5D passes only when all of the following execute successfully:

1. Phase 5D descends from the certified Phase 5C commit.
2. Windows physical preflight passes.
3. `qemu-system-aarch64.exe` is physically present and executable.
4. The QEMU binary is fingerprinted with SHA256.
5. QEMU reports the generic ARM64 `virt` machine.
6. QEMU reports the TCG accelerator.
7. A clean Release build succeeds.
8. The complete Release CTest suite passes.
9. The Phase 5C `vresearch101` descriptor contract still passes.
10. A real QEMU AArch64 process is started on Windows.
11. The process remains alive through the controlled health window.
12. The validation harness terminates the process deterministically.
13. The existing Apple guest launch path still fails closed with exit 78.
14. Machine-readable evidence is emitted.

## Safety boundary

The QEMU lifecycle experiment intentionally supplies no Apple firmware
and no Apple guest payload.

The command uses QEMU's generic `virt` board only to prove the
Windows execution-process substrate.

Phase 5D therefore does NOT certify:

- Apple guest boot
- `vresearch101` implementation inside QEMU
- Apple PV=3 device behavior
- SEP behavior
- SpringBoard
- display
- input
- guest API
- full virtual iPhone execution

These remain later executable gates.

## Failure rule

Any early QEMU process exit, missing `virt` machine, missing TCG
accelerator, build failure, test failure, lineage mismatch, or loss
of the fail-closed Apple launch boundary is a Phase 5D failure.

No unsupported result may be relabeled PASS.

## Next gate after Phase 5D

The next experiment must move from host-process execution to a
deterministic guest-visible boot or serial milestone.

That later gate must provide actual runtime evidence rather than
source inspection or a theoretical compatibility claim.