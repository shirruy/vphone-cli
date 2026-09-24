# ADR 0002: QEMU-Derived Runtime Spike Before Full Rewrite

Status: PROPOSED, REQUIRES PHASE-5 EVIDENCE

## Decision

Use a QEMU-derived backend as the first Windows boot experiment rather than implementing WHPX device models from zero.

## Rationale

QEMU already provides ARM system emulation, Windows builds, TCG for cross-ISA execution, WHPX on supported same-ISA Windows hosts, an upstream `vmapple` machine model, and external research forks that model newer Apple Silicon/SPTM/TXM behavior.

## Host split

- Windows x64: correctness/research path uses AArch64 TCG. Expect poor performance.
- Windows ARM64: evaluate WHPX acceleration after the device model boots correctly.

## No-go condition

If a minimal Apple boot milestone cannot be reproduced on Windows with a maintainable backend, stop before investing in UI and automation layers.
