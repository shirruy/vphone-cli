# 57ZZ Part 15A — ANS/Storage Implementation Readiness

## Verdict

```
ITERATION_58A_ENTRY_GATE: PASS
ITERATION_58B_PLUS_ENTRY_GATE: BLOCKED
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B_PLUS
ANS_CONTRACT_REVALIDATION: PASS
STORAGE_LBA_CONTRACT_REVALIDATION: PASS
```

Part 15A freezes the implementation contract for Iteration 58. It does not
begin implementation. The existing static contracts are revalidated only;
no closed reverse-engineering work is reopened.

## 15A-A: Contract revalidation

All four closed contracts agree at current HEAD:

| Contract | Status |
|---|---|
| phase05f-ans-dt-contract.json | PASS_CLOSED (authoritative ans/iop-ans-nub extraction) |
| phase05f-ans-kernel-driver-match.json | PASS_CLOSED (AppleANS3NVMeController / RTBuddyService) |
| phase05f-ios-storage-lba-contract.json | PASS_CLOSED (LBA 4096, LBADS 12) |
| phase05f-preboom-storage-contract.json | PASS_CLOSED (7 namespace records, 14 reg pairs, interrupts) |

Controller: AppleANS3NVMeController
Provider: RTBuddyService
Guest LBA: 4096 bytes (shift 12)

## 15A-B: qemu-sptm ANS device-model audit

| Component | Exists | Reusable | Evidence |
|---|---|---|---|
| ANS device object | no | — | no AppleANS symbol in hw/arm |
| NVMe controller emulation | no | — | none |
| AppleANS-related device | no | — | none |
| RTBuddy endpoint | no | — | no rtbuddy/rtkit symbols |
| AppleASC transport | no | — | hw/audio/asc.c is classic Mac ASC (344S0063) |
| DMA/IOMMU | partial | unproven | generic smmuv3 only; no t8120 DART |
| NVMe SQ/CQ | no | — | none |
| namespace abstraction | no | — | none |
| block-backend attachment | yes | partial | generic QEMU block layer, no ANS wiring |
| ANS MMIO handlers | no | — | none |
| ANS interrupt wiring | no | — | none |

Reusable template: apple_amcc.c — a minimal SysBus MMIO device
(read/write ops, sysbus_mmio_map) realized from DeviceTree nodes in
darwin_machine_init.

## 15A-C: Device-tree compatible fix (OPEN ACTION ITEM)

The authoritative `iop-ans-nub` child carries
`compatible = iop-nub,rtbuddy-v2`. The booted dtree.bin produced by
dt_fixup.py does not, because `del_compat()` recursively deletes every
compatible property not matching:

```python
SUPPORTED_DRIVERS=[b'AppleARM', b'aic', b'arm-io', b'uart-1,samsung']
```

Minimal fix: add `b'iop-nub'` (or the exact `b'iop-nub,rtbuddy-v2'`) to
SUPPORTED_DRIVERS, or a targeted exception preserving the compatible
property on the iop-ans-nub child only.

```
PREBOOT_ANS_DEVICE_TREE_COMPAT_RESTORE: OPEN_ACTION_ITEM
```

Acceptance: regenerated dtree.bin contains `iop-nub,rtbuddy-v2` on the
iop-ans-nub child, without globally disabling the pruning behavior.

## 15A-D: ANS MMIO

Seven nonzero (base,size) pairs from the authoritative reg property:

| Base | Size | Proven consumer |
|---|---|---|
| 0x77400000 | 0x6c000 | UNKNOWN_MMIO_REGION |
| 0x77050000 | 0x4000 | UNKNOWN_MMIO_REGION |
| 0x7bcc0000 | 0x60000 | UNKNOWN_MMIO_REGION |
| 0x79000000 | 0x1000000 | UNKNOWN_MMIO_REGION |
| 0x7bb90000 | 0xc000 | UNKNOWN_MMIO_REGION |
| 0x7bd47c00 | 0x4000 | UNKNOWN_MMIO_REGION |
| 0x7b100000 | 0x44000 | UNKNOWN_MMIO_REGION |

No range has a statically proven consumer. No range is given a semantic
name. The first Iteration 58 milestone only requires behavior that is
observably touched during provider startup / controller probe.

## 15A-E: Interrupts

Authoritative ANS interrupts: 622, 621, 624, 623, 629
interrupt-parent: 32
nvme-interrupt-idx: 4

The NVMe completion IRQ is UNKNOWN — nvme-interrupt-idx=4 is a candidate
index, not a statically proven completion vector. Polarity/type UNKNOWN.

## 15A-F: RTBuddy / IOP transport

State: MISSING in qemu-sptm. No RTBuddy/RTKit endpoint exists. The minimal
handshake required for AppleANS3NVMeController probe/start is NOT yet
proven. Do not assume a full storage-firmware emulation is required until
driver-side probe expectations are traced.

## 15A-G: Minimum Identify Namespace response

Only these bytes are proven consumed before publication:

| Field | Offset | Requirement |
|---|---|---|
| NCAP | 0x08 | u32 read; for NSID2-7 must equal DT NSSize word2 |
| NLBAF | 0x19 | must be >= FLBAS+1 |
| FLBAS | 0x1a | selects active LBAF |
| LBAF entry | 0x80 + 4*FLBAS | u16 metadata=0, u8 LBADS=12 |

Active format: metadata size 0, LBADS 12, LBA size 4096. Other spec fields
are not proven consumed; populate only the above.

## 15A-H/I: Capacity and backing mapping

NSID 2-7: use authoritative DT NSSize/NCAP values (2560, 32, 2, 2, 256,
32768 LBAs).

NSID 1: alternate capacity path (inByteCapacity / burn-in block override).
Capacity must NOT be invented. NSID1 backing identity: CANDIDATE only.

All three host images (system 9615441920, cryptex 6014631936, ramdisk
243269632 bytes) are 4096-aligned — IMAGE_CAPACITY_COMPATIBLE only.
IMAGE_TO_NAMESPACE_IDENTITY_PROVEN = false for all.

## 15A-J: LBA translation

Guest contract: 1 LBA = 4096 bytes.
byte_offset = slba * 4096
byte_length = nlb_count * 4096

Host backend granularity is UNPROVEN_IMPLEMENTATION_DETAIL. No hidden
*8 or /8 translation is introduced.

## 15A-K: Command surface for first milestone

| Class | Commands |
|---|---|
| REQUIRED_BEFORE_NAMESPACE_PUBLICATION | Identify (Apple internal selector 0x11 path) |
| REQUIRED_FOR_READ_ONLY_APFS | read |
| REQUIRED_FOR_WRITABLE_RESTORE | write, flush |
| NOT_YET_REQUIRED | full admin feature set, vendor command surface |

Apple selector 0x11 is an internal operation enum, NOT the NVMe wire
opcode. The wire opcode remains UNKNOWN.

## 15A-L: DMA / IOMMU

State: MISSING/PARTIAL. No DART model for the t8120 ANS DMA path. Identity
DMA is not an acceptable shortcut until guest mapping behavior proves it.

## 15A-M: Queue contract

nvme-queue-entries = 64
nvme-linear-sq = present, zero-length

SQ/CQ layout consumed by AppleANS3 is UNKNOWN. Do not infer standard NVMe
MMIO layout.

## 15A-N: Milestone sequence

| ID | Milestone | PASS criterion |
|---|---|---|
| M0 | booted DT preserves ANS compatible | dtree.bin contains iop-nub,rtbuddy-v2 |
| M1 | RTBuddy chain publishes; AppleANS3NVMeController probe runs | AppleA7IOPNub allocated-nub log |
| M2 | controller start requests namespaces | "Creating %d namespaces on NAND" |
| M3 | Identify Namespace completes | LBADS==12 accepted, no Invalid LogicalBlockSize |
| M4 | one AppleEmbeddedBlockDevice publishes | block-device media object appears |
| M5 | read-only read reaches host backing | correct bytes returned |
| M6 | APFS NXSB readable via guest storage | NXSB magic at block 0 |

## 15A-O: Runtime-deferred (kept separate)

- exact runtime root namespace identity
- exact runtime Data-volume selection
- external restore orchestrator role=3 caller
- runtime mount identity
- per-NSID publication until actually observed

## 15A-P: Iteration 58 scope

| Slice | Title | Target |
|---|---|---|
| 58A | DT compatible preservation | dt_fixup.py |
| 58B | ANS device skeleton / MMIO map | hw/arm/apple_ans.c (new), darwin.c |
| 58C | RTBuddy/ANS probe handshake | apple_ans.c |
| 58D | namespace Identify contract | apple_ans.c |
| 58E | queue + completion path | apple_ans.c |
| 58F | read-only namespace backing | apple_ans.c + block backend |
| 58G | first block-device publication | apple_ans.c |
| 58H | APFS block-0/NXSB guest read | apple_ans.c |

## Fail-closed statements

- NSID1 = System: NOT PROVEN (candidate only)
- NSTYPE numeric labels: NOT PROVEN
- Full NVMe opcode support: NOT CLAIMED
- Full ANS firmware emulation requirement: NOT PROVEN
- Root namespace identity: RUNTIME_DEFERRED
- Host 512-byte sectors: NOT PROVEN
- Data namespace assignment: NOT PROVEN
- RTBuddy runtime success: NOT PROVEN

## 57ZZ PART 15A CANONICAL STATUS

```
Existing ANS match contract:    PASS_CLOSED
Existing storage LBA contract:  PASS_CLOSED
Boot-tree ANS compatible gap:   OPEN (58A)
Current ANS device implementation: ABSENT
RTBuddy transport requirement:  MISSING (handshake unproven)
ANS MMIO requirement:           UNKNOWN_MMIO_REGION (all ranges)
Interrupt contract:             BLOCKED (completion IRQ unproven)
DMA/IOMMU contract:             BLOCKED (no DART model)
Namespace Identify contract:    PASS (4 proven fields)
Guest LBA:                      4096 bytes
NSID1 capacity source:          alternate path only (no invention)
NSID1 backing identity:         CANDIDATE
Per-NSID publication:           RUNTIME_DEFERRED
Iteration 58 scope:             FROZEN (58A-58H)

ITERATION_58A_ENTRY_GATE: PASS
ITERATION_58B_PLUS_ENTRY_GATE: BLOCKED
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B_PLUS
```

Runtime-deferred: root NSID, Data NSID, mount identity, external role=3
orchestrator caller, per-NSID publication.

Static blockers: none for starting 58A (DT fix). 58B+ depend on 58A output
and on runtime probing of the minimal MMIO surface.
