# 57ZZ Part 15B-R — AKF String Xref / AppleA7IOP CFG Analysis

## Verdict

```
DIFFERENTIAL_ANS_BOOT: PASS
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

The differential experiment is accepted, but the causal conclusion is now
corrected: the AKFProvider hypothesis is a strong candidate, not yet proven
enough to name a production 58B implementation.

## R1: MMIO range scanner (fixed)

The scanner now extracts every hexadecimal address from each diagnostic
line and range-tests numerically (`base <= addr < base+size`) across all
seven ANS ranges. The debug log still contains no access inside any ANS
range, so `FIRST_ANS_MMIO_ACCESS: NOT_OBSERVED` is now a trustworthy scan
result.

## R3: DT consumption (proven)

xnuboot_sptm.c loads `-dtree` via `check_and_open`, copies it into guest
memory at `dtree_base_phys`, and passes `args.deviceTreeP =
dtree_base_phys - physBase + virtBase` and `deviceTreeLength = len` to the
boot path. The file SHA change therefore provably changes the guest-visible
DeviceTree buffer.

```
ANS_ENABLED_DT_QEMU_CONSUMPTION: PASS
```

## R4: AKF string xrefs

| String | VM | Xref (exec) |
|---|---|---|
| ASC firmware must be loaded by iBoot | 0xfffffff00713c04e | ASCWrap entry 24 @ 0xfffffff0082f4a6c (REQUIRE-style call, w9=0x97) |
| AKF_RUNNING: False | 0xfffffff00713c0f7 | ASCWrap entry 24 @ 0xfffffff0082f4034 (log after bit0-clear branch) |
| _akfProvider / _akfRegisterMap / _akfMappedRegs | 0xfffffff00713c8e5/9/4 | AppleA7IOP entry 25: two sites each |

## R5/R6: AppleA7IOP::start CFG and provider class

PARTIAL / BLOCKED. The `_akf*` xrefs are inside entry 25
(com.apple.driver.AppleA7IOP, __TEXT_EXEC vm 0xfffffff0082f4cb0). The
second xref site reads provider member `[x0,#0xf8]` and calls authenticated
vtable slots `0x568`/`0x570`. The exact expected provider class (AKFProvider
vs AKFIOPNub vs subclass) and the full start-boundary CFG remain unproven.

## R9/R10/R11: Register map source / mapped regs / mailbox offsets

All UNKNOWN. The AKF mailbox register names exist only as kernel log format
strings (fo 0x99cf09..0x99cf85). Numeric offsets, widths, access directions,
and the register-map source (DT reg vs provider property vs memory-map) are
not proven. `_akfMappedRegs` is referenced from AppleA7IOP code but its
producing operation (IOMemoryMap::map or equivalent) is not yet traced.

## R12/R13: ASC firmware + role property

ASC firmware predicate is inside ASCWrap (entry 24). Whether it blocks
before or after the AKF requirements, and whether it is an Iteration 58B
blocker, is UNKNOWN. The `role` getProperty call exists in AppleA7IOP code
but the expected type/value/origin are UNKNOWN.

## R14/R15: Observability + first missing behavior

M1/M2/M3 remain NOT_OBSERVED (not PROVEN_NOT_REACHED). The precise
first missing behavior cannot yet be named beyond:

```
CANDIDATE_AKF_PROVIDER_CHAIN
```

The specific guest-visible primitive (exact DT node, MMIO range, or
firmware state) that would cause the guest to publish the AKF provider is
not yet proven.

## Canonical gate state

```
DIFFERENTIAL_ANS_BOOT: PASS
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

No production 58B implementation is started. The next steps are
per-function disassembly of AppleA7IOP::start and recovery of the
provider publication/matching chain above it.
