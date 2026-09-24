# Phase 4B Archive Parity Matrix

| Capability | Upstream behavior | Windows Phase 4B | Evidence |
|---|---|---|---|
| GNU tar write | VPhoneArchiveWriter + libarchive | SUPPORTED | Pinned libarchive 3.8.9, MSVC build, byte-parity roundtrip |
| Archive member read | VPhoneArchiveReader + libarchive | SUPPORTED | Named-member readback matches original payload byte-for-byte |
| zstd | libarchive filter | UNSUPPORTED | Dependency/filter parity not yet enabled |
| xz | libarchive filter | UNSUPPORTED | Dependency/filter parity not yet enabled |
| gzip | libarchive filter | UNSUPPORTED | Dependency/filter parity not yet enabled |
| Darwin xattrs/ACLs | Darwin/libarchive metadata APIs | UNSUPPORTED | Windows metadata mapping not yet specified |
| Hardlink preservation | libarchive link resolver + inode identity | NOT_YET_PROVEN | Requires Windows file identity parity test |
| Bundle export/import | VPhoneBundleTransfer | NOT_YET_PROVEN | Requires tree, top-level, exclusion, and config.plist acceptance parity |

Phase 4B is fail-closed. Only capabilities backed by executable Windows evidence are reported as supported.
