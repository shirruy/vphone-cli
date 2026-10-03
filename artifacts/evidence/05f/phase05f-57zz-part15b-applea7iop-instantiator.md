# 57ZZ Part 15B-T — AppleA7IOP Instantiator / Start Provider Provenance

## Verdict

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

No production 58B implementation. This pass replaced the hardcoded
evidence generator with reproducible derivations. Terminology corrected
per reviewer.

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

## 15B-U: Reproducibility correction (supersedes 15B-T details)

The prior pass hardcoded start_vm and canned dataflow strings. This pass
rewrote the generator so every verdict is derived:

- U1/U2: real plistlib.loads over the enclosing prelink plist (276 kext
  dicts). AppleA7IOP IOKitPersonalities ABSENT_PROVEN from the parsed
  object.
- U3: fileset mapping via prelink _PrelinkExecutableLoadAddr
  (0xfffffff00713c1f0 unsigned) matched to fileset entry __TEXT vm, and
  _PrelinkKmodInfo matched to __DATA. PASS.
- U7: start ABI derived from Capstone, not canned strings:
  0xfffffff0082f4df0 pacibsp ... mov x19, x1 (x1->x19). START_ABI PROVEN.
- U8/U9: the vtable+0x2c0 call result stored at [this+0xf8] is
  UNKNOWN_OBJECT_FROM_VTABLE_0x2C0. The incoming start provider (x1) and
  the field-0xf8 object are distinct provenance problems.

Canonical gates (unchanged):

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```
