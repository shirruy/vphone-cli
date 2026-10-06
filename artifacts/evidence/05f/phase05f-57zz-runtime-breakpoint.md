# 57ZZ Runtime Boundary — Decisive Breakpoint Evidence

## Verdict

```
APPLEA7IOP_CANDIDATE_RUNTIME_ENTRY: NOT_OBSERVED
APPLEA7IOPNUB_WITHREGISTRYENTRY_RUNTIME: NOT_OBSERVED
APPLEA7IOP_INSTANTIATION: UNKNOWN
APPLEA7IOP_START_VTABLE_SLOT: BLOCKED
BREAKPOINT_ARMED_BEFORE_TARGET_MATCHING: UNKNOWN
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

These are interval-limited observations: the breakpoints were armed after
a 12-second warmup, so the NO_HIT result is proven only from breakpoint
arm time forward. It is not yet a whole-boot absence proof.

Classification follows the P3 contract exactly: NO_HIT means none of the
three instrumented functions (candidate A, candidate B, or
AppleA7IOPNub::withRegistryEntry) was entered during a complete boot of
either DeviceTree fixture within the capture window.

## What this run proves

1. The runtime capture protocol works end to end:
   - KASLR slide derived programmatically from a PC-anchored unique byte
     match against bootkc `__TEXT_EXEC` (slide `0x20000000` in both runs).
   - Byte verification passed for the AppleA7IOPNub prologue and both
     start candidates at the slid addresses.
   - Hardware breakpoints (`hbreak`) installed on all three targets.
   - The kernel booted completely (37,170 / 37,256 serial bytes) and
     reached the idle loop while the breakpoints remained armed.
2. Both DeviceTree fixtures produced NO_HIT:
   - control (`dtree_control.bin`, SHA `9e84c9ad...`): NO_HIT
   - ANS-enabled (`dtree_experiment.bin`, SHA `9f87087f...`, Iteration 58A): NO_HIT
3. No runtime entry into either instrumented AppleA7IOP start candidate or
   into AppleA7IOPNub::withRegistryEntry was observed under either tested
   DeviceTree fixture during the instrumented interval. Iteration 58A
   therefore does not yet provide evidence that the AppleASCWrapV6 ->
   AppleA7IOP -> AppleA7IOPNub runtime chain is exercised; whether
   AppleA7IOP was instantiated through an uninstrumented path remains
   UNKNOWN.

## Control vs ANS-enabled differential

The only ANS-relevant behavioral difference in the serial logs is the
`AppleOLYHAL::start` provider print (provider pointer differs per boot);
`AppleOLYHAL` is a WLAN-family driver and its start method intentionally
bails via the `wlan-olyhal-abort` boot-arg in both fixtures. It is not
part of the ANS chain and is not evidence of ANS activity.

## Why the gate stays closed

Per the P6 gate contract, production 58B entry requires BOTH:

1. A proven AppleA7IOP runtime entry/provider chain.
2. A concretely identified first QEMU-visible primitive.

Both are absent. The AppleASCWrapV6 → AppleA7IOP → AppleA7IOPNub path was
proven statically in Part 15B-V and re-verified programmatically in this
iteration, but the kernel never calls it under the current boot fixtures.

## Remaining exact blocker

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
```

The ANS-enabled DeviceTree preserves the `iop-ans-nub` compatible string,
but no AppleASCWrapV6/AppleA7IOP/A7IOPNub instantiation is triggered. The
next diagnostic slice must find what runtime condition (additional
DeviceTree properties, an AppleARMIODevice/ANS2 service publication, or an
upstream provider) is required before the ANS wrapper chain starts. No
QEMU-side primitive can be implemented from naming alone.

## Raw evidence

| Artifact | Contents |
|---|---|
| `phase05f-57zz-runtime-breakpoint-ans.json` | Raw GDB capture (ANS DT): slide derivation, hbreak install, per-stop registers/memory, classification |
| `phase05f-57zz-runtime-breakpoint-control.json` | Raw GDB capture (control DT): same protocol |
| `phase05f-57zz-runtime-breakpoint-ans-run.json` | Run metadata: SHAs, serial bytes, timing, exit codes |
| `phase05f-57zz-runtime-breakpoint-control-run.json` | Control run metadata |

Commands (reproducible):

```powershell
# ANS-enabled
powershell -ExecutionPolicy Bypass -File scripts\phase05f-57zz-runtime-breakpoint-run.ps1 `
  -RunName p2-decisive-v18 -Dtree "$env:TEMP\dtree_experiment.bin" -GdbPort 1255 -WarmupSeconds 12 -WindowSeconds 150

# Control
powershell -ExecutionPolicy Bypass -File scripts\phase05f-57zz-runtime-breakpoint-run.ps1 `
  -RunName p2-control-v1 -Dtree "$env:TEMP\dtree_control.bin" -GdbPort 1256 -WarmupSeconds 12 -WindowSeconds 150
```

## Harness files

- `scripts/phase05f-57zz-runtime-gdb-capture.py` — GDB client executed by
  gdb-multiarch; PC-anchored slide derivation, adaptive-window bootkc
  matching, hbreak installation, per-stop capture.
- `scripts/phase05f-57zz-runtime-breakpoint-run.ps1` — orchestrator: boots
  the fixture with gdbstub, warmup, GDB attach, evidence collection.
