# 57ZZ Part 15B — First Runtime Requirement of the ANS Chain

## Verdict

```
FIRST_ANS_RUNTIME_REQUIREMENT: PROVEN
ITERATION_58B_ENTRY_GATE: PASS
ANS_STORAGE_IMPLEMENTATION_READINESS: READY_FOR_58B_ONLY
```

Part 15B ran a control-vs-experiment differential boot and identified the
first missing behavior that blocks the proven ANS chain. No ANS emulation
was implemented in this phase.

## Control / experiment boots

| Item | Control | Experiment |
|---|---|---|
| dtree SHA256 | 9E84C9AD... | 9F87087F... |
| iop-ans-nub compatible | ABSENT | iop-nub,rtbuddy-v2 |
| serial bytes | 32,788 | 32,798 |
| bootkc/ramdisk/qemu | identical | identical |

Both runs reach launchd/restore-environment userspace. The only
differences are ASLR/timing noise (provider pointers, timestamps).

## Milestone states

```
M1 AppleA7IOPNub publication: NOT_REACHED
M2 RTBuddy match:             NOT_REACHED
M2 RTBuddyService attach:     NOT_REACHED
M3 ANS3 probe:                NOT_REACHED
M3 ANS3 start:                NOT_REACHED
```

No AppleA7IOPNub/RTBuddy/ANS/NVMe marker appears in either serial log.
`-d guest_errors,unimp` debug run produced only a sysreg access warning
and a TLBI granule message — no ANS MMIO access.

## First ANS MMIO access

NOT_OBSERVED. The chain never reaches the point where the guest touches
an ANS MMIO range.

## Static root-cause trace (BootKC)

The earlier blocker is inside AppleA7IOP itself:

```
AppleA7IOP::start(IOService *) requires:
  _akfProvider    != nullptr   (0x1388e5)
  _akfRegisterMap != nullptr   (0x138999)
  _akfMappedRegs  != 0         (0x1389b4)

AppleASCWrapV6::initialize requires:
  "ASC firmware must be loaded by iBoot" (0x13804e)

AppleA7IOPNub::withRegistryEntry logs:
  "provider is not AKFProvider" (0x1393d0-ish)
```

The AKF transport exposes mailbox registers logged as:

```
AKF_KIC_INBOX_CTRL    (0x99cf09)
AKF_KIC_MAILBOX_SET   (0x99cf26)
AKF_AP_OUTBOX_CTRL    (0x99cf4c)
AKF_AP_MAILBOX_SET    (0x99cf85)
```

The emulator publishes no AKFProvider and no AKF register map. Therefore
AppleA7IOP iterates no children, no iop-ans-nub is published, and the
RTBuddy -> RTBuddyService -> AppleANS3NVMeController chain never starts.

## First missing behavior

```
FIRST_MISSING_BEHAVIOR:
Publish an AKFProvider IOKit service with an AKF register map so that
AppleA7IOP::start can pass its akfProvider/akfRegisterMap/akfMappedRegs
predicates.
```

## Iteration 58B scope

Publish a minimal AKFProvider (or AKFIOPNub) carrying an AKF register-map
MemoryRegion with the proven mailbox registers, plus the role property.
Observation first: do not fabricate mailbox responses beyond what
observation proves. No ANS/NVMe/queue/DMA/interrupt emulation in 58B.

## Requirements for 58B

```
INTERRUPT: NOT_YET_REACHED
DMA:       NOT_YET_REACHED
QUEUE:     NOT_YET_REACHED
```

## Runtime-deferred (unchanged)

- exact root NSID
- exact Data NSID
- mount identity
- external role=3 orchestrator caller
- per-NSID publication

## Canonical status

```
ITERATION_58B_ENTRY_GATE: PASS
ANS_STORAGE_IMPLEMENTATION_READINESS: READY_FOR_58B_ONLY
```

58B is bounded to AKFProvider publication with proven mailbox register
names. 58C+ (ANS MMIO, NVMe, queues, namespace backing) remains blocked
pending observation from 58B.
