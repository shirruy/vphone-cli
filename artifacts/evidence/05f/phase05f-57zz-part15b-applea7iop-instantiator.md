# 57ZZ Part 15B-T — AppleA7IOP Instantiator / Start Provider Provenance

## Verdict

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

No production 58B implementation. This pass hardened prelink parsing and
recovered the AppleA7IOP::start function boundary with provider-argument
dataflow. Terminology corrected per reviewer.

## T0: Terminology correction

- "AppleA7IOP is an explicit client" is RETRACTED.
- Correct: AppleA7IOP's recovered prelink block shows NO IOKit personality.
  Instantiation mechanism remains UNKNOWN.
- OSBundleLibraries (AppleARMPlatform + IOSlaveProcessor) are link/load
  dependencies only; they do not prove creation direction.
- The graph is a candidate provider topology, not a proven publication
  chain.

## T1/T2: Prelink metadata parse (hardened)

Exact block extraction (balanced <dict> scan), not substring search:

| Bundle | Block size | IOKitPersonalities |
|---|---|---|
| com.apple.driver.AppleA7IOP | 2679 | ABSENT |
| com.apple.driver.AppleA7IOP-ASCWrap-v6 | 4382 | PRESENT |
| com.apple.driver.AppleARMPlatform | 10895 | PRESENT |
| com.apple.driver.IOSlaveProcessor | 2610 | ABSENT |

```
APPLEA7IOP_IOKIT_PERSONALITY: ABSENT_PROVEN
```

This proves only that ordinary personality matching is not the direct
creation mechanism. It does NOT identify the actual instantiator.

## T6: AppleA7IOP::start function

```
APPLEA7IOP_START = 0xfffffff0082f4df0
```

Prologue:
```
0xfffffff0082f4df0  pacibsp
0xfffffff0082f4df4  sub sp, sp, #0x50
0xfffffff0082f4e0c  mov x19, x1    ; provider argument
0xfffffff0082f4e10  mov x20, x0    ; this
```

```
START_ABI: PROVEN (x0 = this, x1 = provider)
```

## T7/T8: Provider argument and field 0xf8

The start function immediately calls a factory via vtable+0x2c0
(0xfffffff0082f4e2c) and stores the result at `[x20, #0xf8]`
(0xfffffff0082f4e4c). Subsequent calls load `[x20, #0xf8]` and invoke
vtable slots 0x118, 0x3d0, 0x568, 0x570 on it.

`FIELD_0xF8: provider-related object (factory result)` — the exact dynamic
class of that object is not yet resolved, so it is not yet labeled the
IOService provider.

## Remaining unproven (unchanged unless listed above)

- AppleA7IOP instantiator: UNKNOWN
- Provider class / creation mechanism / DT path: UNKNOWN
- VTABLE 0x568 / 0x570 methods: UNKNOWN
- ASCWrap relation: UNKNOWN
- IOSlaveProcessor / AppleARMPlatform roles: dependency only
- AKF register-map source / MMIO base+size: UNKNOWN
- _akfMappedRegs production: BLOCKED
- First AKF hardware access: UNKNOWN
- First QEMU-visible primitive: BLOCKED

## Canonical status

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

Next bounded step: resolve the factory at vtable+0x2c0 and the dynamic
class of the object stored at this+0xf8, then trace that class's creation
back to its DeviceTree/ARMIO provenance.
