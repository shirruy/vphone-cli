# Phase 5F Minimum Guest Payload and Serial Milestone

## Certified parent

Phase 5E:

0520f14ea99d9619929c01ce47df9832bc9625a0

## Purpose

Phase 5F moves beyond payload-free Darwin initialization.

The first goal is not a graphical iOS guest.

The first goal is to provide the smallest authorized guest payload set
accepted by the Darwin machine and observe the first repeatable guest
serial activity.

## Payload isolation

Apple guest payloads are not stored in this Git repository.

Local payload storage is intentionally external to the source tree.

The runtime probe does not download, decrypt, or extract Apple firmware.

## Base non-SPTM contract

The pinned Darwin machine requires:

- bootkc
- device tree
- trust cache
- ramdisk

## SPTM contract

When SPTM mode is selected, the runtime contract additionally requires:

- SPTM
- TXM

## Current claims

Native Windows Darwin-QEMU foundation:

CERTIFIED IN PHASE 5E

Apple payload admission:

PASS (iPhone15,4 / t8120 / iOS 27.0 / 24A437)

Apple kernel execution:

PASS

Serial activity:

PASS (first UART bytes observed; iBoot, AppleImage4, AMFI, and IOKit
backlight output reaches the serial log)

Deterministic serial:

PASS (deterministic meaningful serial milestone)

Two 15-second runs of the identical payload set produced an
identical 2436-byte prefix through the iBoot, AppleImage4, AMFI,
and backlight milestones, and both runs reached the same terminal
ACMTRM SEP-timeout state. Full-log hashes differ only because
boot-time IOKit log lines race position; the meaningful milestone
sequence and terminal state are repeatable. Whole-log byte equality
is NOT_REQUIRED / NONDETERMINISTIC_BY_DESIGN_FOR_CURRENT_GATE
because the acceptance contract requires repeatable meaningful
guest milestones, not identical whole logs.

## AppleImage4 fileset parser defect (found and fixed in this phase)

`macho_find_fileset_entry` assumed the LC_FILESET_ENTRY entry name
always begins exactly at `(char *)(f + 1)`. The Mach-O definition
is an `lc_str` offset (`entry_id.offset`) relative to the command
start. The parser now validates that `entry_id.offset < cmdsize`,
requires a NUL terminator inside `cmdsize`, and fails closed on
malformed entries. Bounds checks use the on-disk ABI constant
`MACHO_FSE_DISK_HEADER_SIZE` (32) rather than host `sizeof(fse_t)`,
because Windows LLP64 keeps the `char *ptr` member in `union lc_str`,
making host `sizeof(fse_t)` 40 while the on-disk header is 32; the
real BootKC places every entry name at offset 32. After the fix, the
misleading
`warning: couldn't find img4 kext` disappeared from stderr with the
known-good BootKC, and serial output of 12,806 bytes with additional
AppleLockdownMode and ACMTRM PersistentStore milestones was observed
after the fix (compared with 11,343 bytes in the earlier run). This
phase already demonstrates boot-time ordering nondeterminism, so the
byte growth is an observation after the fix, not by itself proof
that the parser fix caused the deeper progression.

## LLP64 page-rounding defect (found and fixed in this phase)

The original `include/xnu/boot/xnuboot.h` defined `ONE_KB`,
`ONE_MB`, and `ONE_GB` with `BIT()`, which is `1UL << n` and
therefore 32-bit on Windows LLP64. Every `ROUND_NEXT_PAGE` applied
to a guest physical address at or above 4 GB truncated that address
to its low 32 bits. This corrupted `boot_args.topOfKernelData`
(0x10015ea0000 became 0x15ea0000), the RAMDisk ADT memory-map entry
(0x100076a0000 became 0x076a0000), and the BootArgs entry size.
The SPTM page-index producer at runtime 0xfffffff0070d5700 then
subtracted a DRAM offset from the absolute DRAM base, underflowed,
wrapped the stored page index to 0xfc0057a8, and faulted at runtime
0xfffffff0070a4f74. The fix changes the three macros to `BIT_ULL`;
it is the same defect family as the Phase 5F `BIT(36)`/`BIT(63)`
repairs and is held in the local qemu-sptm working tree diff.

Apple guest boot:

NOT CLAIMED

Graphical guest:

NOT TESTED

## Runtime progression

1. Validate local payload files and hashes.
2. Start the Darwin machine with the minimum payload contract.
3. Capture UART output to a deterministic serial log.
4. Classify the first guest execution boundary.
5. After first serial activity is observed, run the same payload set twice.
6. Compare the two runs before making a deterministic serial milestone claim.

## Post-closure blocker research: root shell requires a patched ramdisk

The repeated terminal lines
`ACMTRM: waitForSEPEndpoint: timed out waiting for AppleSEPManager`
look like a device-model blocker, but an A/B experiment disproved that
hypothesis: cherry-picking the upstream Apple AIC interrupt controller
(bad6336) onto the pinned base changed nothing (33,052 vs 33,060
serial bytes, identical terminal state). The upstream AIC source
itself documents that a working AIC is not required to reach a root
shell.

The actual mechanism, per upstream darwin-vm get_files.sh, is that
the root shell comes from a ramdisk patched on macOS: the stock
LaunchDaemons directory is replaced with a com.jprx.bash plist, an
iOS sysroot is extracted, every binary is ad-hoc codesigned, and a
custom trustcache is rebuilt from the cdhashes. The Windows fixture
uses the raw unpatched ramdisk, so iOS correctly runs the restore
daemon (121 launchd messages, restore checkpoints, userspace sysctl)
instead of the custom shell. Reaching a guest root shell on Windows
therefore requires porting that ramdisk patch pipeline (APFS
LaunchDaemons replacement, ad-hoc signing, trustcache rebuild) or
supplying a pre-patched ramdisk. The AIC cherry-pick is retained
because real interrupt semantics are required for the non-primary
qemuport UARTs.
