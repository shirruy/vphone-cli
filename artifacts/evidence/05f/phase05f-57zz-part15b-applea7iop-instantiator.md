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

The start function immediately calls via vtable+0x2c0
(0xfffffff0082f4e2c) and stores the result at `[x20, #0xf8]`
(0xfffffff0082f4e4c). Subsequent calls load `[x20, #0xf8]` and invoke
vtable slots 0x118, 0x3d0, 0x568, 0x570 on it.

`FIELD_0xF8: class-chain walk result (SUPER_START_CHAIN, corrected in
15B-V)` — the exact dynamic class of that object is not yet resolved.

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

Next bounded step: runtime-verify the ANS wrapper path (AppleASCWrapV6 ->
AppleA7IOPNub::withRegistryEntry -> RTBuddy) and capture the first
hardware access. Static vtable-slot archaeology is no longer the gate.

## Runtime boundary statics (programmatically re-derived)

All three facts below are derived by the generator from bootkc Mach-O
structure and instruction evidence — not hardcoded:

```
APPLEASCWRAPV6_SUPERCLASS = AppleA7IOP           (PROVEN_STATIC)
APPLEA7IOP_CLASS_OBJECT   = 0xfffffff00afed5c0   (PROVEN_STATIC)
APPLEA7IOPNUB_WITHREGISTRYENTRY = 0xfffffff0082f7b40 (PROVEN_STATIC)
```

Derivation chain:

- The ASCWrap-v6 fileset entry (outer entry whose `__TEXT_EXEC` is
  `0xfffffff0082f2bf0`) has 3 mod_init functions; mod_init[1] registers
  the class `AppleASCWrapV6` (`0xfffffff00afed498`) with a superclass
  argument loaded from the GOT slot `0xfffffff007d13bc0`.
- Chasing that chained pointer (`raw 0x10000003fe95c0`, low-32 file
  offset `0x3fe95c0`) resolves to `0xfffffff00afed5c0`.
- AppleA7IOP fileset entry mod_init[0] registers the class `AppleA7IOP`
  with the exact class object `0xfffffff00afed5c0` — proving
  `AppleASCWrapV6 -> AppleA7IOP`.
- AppleA7IOP mod_init[1] registers `AppleA7IOPNub` with class object
  `0xfffffff00afed5e8`; `0xfffffff0082f7b40` allocates `0x98` bytes via
  vtable `+0x8b0` and constructs with that class object, proving the
  `withRegistryEntry` factory entry.

## Runtime breakpoint result (NO_HIT)

The decisive runtime run is recorded in
`phase05f-57zz-runtime-breakpoint.md`. Both the control and the
ANS-enabled (Iteration 58A) DeviceTree fixtures completed a full boot with
hardware breakpoints armed on both AppleA7IOP start candidates and
AppleA7IOPNub::withRegistryEntry; none was hit. The gate remains
`BLOCKED_PROOF_INCOMPLETE`.

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

## 15B-V: FINAL boundary findings

V3 correction: the vtable+0x2c0 call inside the candidate start is a
SUPER-START chain (resolved to kernel entry 236 fn 0xfffffff009dad920,
an IOService-style start that calls its own +0x2c0 and creates an object
on success), NOT a factory. The object stored at this+0xf8 is returned by
a class-chain walk helper (entry 13, 0xfffffff00aa4ebc0) that compares the
provider's class against a target class vtable (0xfffffff007d33100).

V1 status: the candidate 0xfffffff0082f4df0 has a twin function at
0xfffffff0082f804c with an identical prologue (x19=x1, x20=x0, same
0x2c0 super-chain). Neither is yet proven to be the vtable start slot:
no vtable entry in the AppleA7IOP vtable (0xfffffff007d14370) points to
either function's file offset. START_VTABLE_SLOT remains BLOCKED.

Given the FINAL-slice constraint, the honest single blocker is:

```
APPLEA7IOP_START_VTABLE_SLOT: BLOCKED
```

The runtime path (V2 fallback) is available: a diagnostic breakpoint at
either candidate with x0/x1 capture would settle the question without
more static guessing. VTABLE_0x2C0 classification stands corrected:
SUPER_START_CHAIN (not factory).
