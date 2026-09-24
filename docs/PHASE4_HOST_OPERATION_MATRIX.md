# Phase 4 Host Operation Matrix

| Operation | macOS implementation | Windows Phase 4A | Evidence / replacement need |
|---|---|---|---|
| FTAB parse/write | MobileRestoreCore C | SUPPORTED | MSVC compile + explicit round-trip test |
| MBN stitch | MobileRestoreCore C | SUPPORTED | MSVC compile + explicit byte-parity stitch test |
| AEA decrypt/encrypt | /usr/bin/aea | UNSUPPORTED | Needs a Windows-native AEA implementation or validated portable library |
| Disk image attach/convert/resize | hdiutil + diskutil | UNSUPPORTED | Needs Windows image/APFS backend |
| APFS sealing/root hash | staged apfs_sealvolume | UNSUPPORTED | Needs equivalent APFS seal implementation |
| Canonical metadata archive | /usr/bin/aa | UNSUPPORTED | Needs portable Apple Archive-compatible writer |
| ArchiveKit bundle archive | Swift + libarchive | NOT_YET_PROVEN | Phase 4B |
| Full restore transport | MobileRestoreCore + device dependencies | NOT_YET_PROVEN | Later Phase 4 slice |

The matrix is fail-closed: unsupported or unproven operations are not reported as available by the Windows CLI.
