# Phase 4D1 Restore/Image Parity Matrix

| Capability | Windows Phase 4D1 | Evidence |
|---|---|---|
| Offline APFS snapshot scan | SUPPORTED | Valid checksum-gated snapshot record scan on synthetic image fixture |
| Offline APFS snapshot rename | SUPPORTED | Same-length prefix rewrite, touched-block Fletcher64 recomputation, invalid block left unchanged |
| Dry-run APFS snapshot inspection | SUPPORTED | Scan/report without file mutation |
| AEA decrypt/encrypt | UNSUPPORTED | macOS /usr/bin/aea replacement still required |
| Disk image attach/convert/resize | UNSUPPORTED | hdiutil/diskutil replacement still required |
| APFS sealing/root hash | UNSUPPORTED | apfs_sealvolume replacement still required |
| Canonical Apple metadata archive | UNSUPPORTED | Apple aa-compatible metadata writer still required |

Phase 4D1 is fail-closed. Only the APFS snapshot primitive is promoted to supported.
