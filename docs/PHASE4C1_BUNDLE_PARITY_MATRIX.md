# Phase 4C1 Bundle Parity Matrix

| Capability | Windows Phase 4C1 | Evidence |
|---|---|---|
| Safe relative bundle paths | SUPPORTED | Rejects absolute, traversal, backslash, drive-prefix, and NTFS ADS-style paths |
| Exactly one top-level config.plist | SUPPORTED | Bundle validator requires one non-empty regular config.plist |
| Hardlink target path safety | SUPPORTED | Hardlink archive targets use the same path-safety rules |
| Windows hardlink file identity | SUPPORTED | CreateHardLink + volume serial + file index + link count proof |
| Symlink import | UNSUPPORTED | Explicitly rejected until Windows symlink policy is defined |
| gzip | UNSUPPORTED | Phase 4C2 |
| xz | UNSUPPORTED | Phase 4C2 |
| zstd | UNSUPPORTED | Phase 4C2 |
| Darwin xattrs/ACLs | UNSUPPORTED | Requires explicit metadata mapping |

Phase 4C1 is fail-closed. Compression is not claimed until separate dependency and byte-parity tests pass.
