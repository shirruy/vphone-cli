# 57ZZ Part 15B-S — AppleA7IOP Provider Publication Chain

## Verdict

```
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

No production 58B implementation. This pass recovered the personality
chain facts and fixed the two committed script residues.

## S0: Script residues fixed

1. Reachability overclaim removed: `first_mmio_consumer` now says "No
   ANS-range MMIO access was observed... AppleA7IOP execution reachability
   is not established by this observation alone."
2. Scanner verdict bug fixed: `ANS_MMIO_RANGE_SCANNER` now always reports
   scanner execution PASS, separate from `FIRST_ANS_MMIO_ACCESS`.
3. Deterministic self-test added with 6 synthetic lines covering range
   boundaries and an unrelated PC. All 6 pass.

## S4/S5: Personality recovery (BootKC __PRELINK_INFO)

`com.apple.driver.AppleA7IOP-ASCWrap-v6` has three IOKit personalities:

| IOClass | IOProviderClass | IONameMatch |
|---|---|---|
| AppleASCWrapV6 | AppleARMIODevice | iop,ascwrap-v6 / iop,ascwrap-v7 |
| AppleASCWrapV6SEP | AppleARMIODevice | iop-sep,ascwrap-v6 / iop-sep,ascwrap-v7 |
| AppleASCWrapV6SISP | AppleARMIODevice | iop-isp,ascwrap-v6 |

`com.apple.driver.AppleA7IOP` has **no IOKit personality** in its
Info.plist (no IOClass/IOProviderClass). Its OSBundleLibraries declare:

```
com.apple.driver.AppleARMPlatform
com.apple.driver.IOSlaveProcessor
com.apple.kpi.bsd / iokit / libkern / mach
```

So AppleA7IOP is an **explicit client**, not a personality-matched driver.
Its provider is expected to be an AppleARMIODevice-derived object carrying
AKF register data, created by the arm-io subtree enumeration
(the "arm-io, this should not happen" error string at BootKC 0x15de6e is
the matching-path log).

## S6/S7: Publication chain

```
authoritative DT arm-io subtree
  -> AppleARMIODevice instances (arm-io enumeration)
  -> AppleASCWrapV6 (IONameMatch iop,ascwrap-v6, IOProviderClass AppleARMIODevice)
  -> <unproven AKF-capable provider creation step>
  -> AppleA7IOP (explicit client)
  -> AppleA7IOPNub children
  -> RTBuddy -> RTBuddyService -> AppleANS3NVMeController
```

The `<unproven AKF-capable provider creation step>` is the exact boundary
that must be resolved before 58B can be named.

## Remaining unproven (unchanged)

- AppleA7IOP::start exact function boundary: BLOCKED (partial only)
- Start provider dataflow: BLOCKED
- Exact expected provider class: UNKNOWN
- AKF register-map source / MMIO base / MMIO size: UNKNOWN
- _akfMappedRegs production: BLOCKED
- First mapped-register access: UNKNOWN
- Mailbox register offsets: BLOCKED
- Role property requirement/value: UNKNOWN
- ASC firmware requirement ordering: UNKNOWN
- First QEMU-visible primitive: BLOCKED

## Canonical status

```
DIFFERENTIAL_ANS_BOOT: PASS
ANS_ENABLED_DT_QEMU_CONSUMPTION: PASS
ANS_MMIO_RANGE_SCANNER: PASS (self-test PASS)
FIRST_ANS_MMIO_ACCESS: NOT_OBSERVED
M1/M2/M3: NOT_OBSERVED
FIRST_ANS_RUNTIME_REQUIREMENT: CANDIDATE_AKF_PROVIDER_CHAIN
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B
```

Next bounded step: identify the exact kext/function that instantiates
AppleA7IOP (trace the IOSlaveProcessor / AppleARMPlatform client edge),
then trace its provider argument back to the AppleARMIODevice creation
that carries the AKF register map.
