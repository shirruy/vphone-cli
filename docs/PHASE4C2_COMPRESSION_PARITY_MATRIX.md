# Phase 4C2 Compression Parity Matrix

| Capability | Windows Phase 4C2 | Evidence |
|---|---|---|
| gzip transport compression | CANDIDATE_SUPPORTED | Pinned zlib 1.3.2, byte-identical tar roundtrip, restored bundle validation |
| xz transport compression | CANDIDATE_SUPPORTED | Pinned XZ Utils 5.8.4/liblzma, byte-identical tar roundtrip, restored bundle validation |
| zstd transport compression | CANDIDATE_SUPPORTED | Pinned zstd 1.5.7, byte-identical tar roundtrip, restored bundle validation |
| Bundle manifest/path safety | PRESERVED | Phase 4C1 regression test remains in suite |
| Windows hardlink identity | PRESERVED | Phase 4C1 regression test remains in suite |
| Symlink import | UNSUPPORTED | Explicitly blocked |
| Darwin xattrs/ACLs | UNSUPPORTED | Explicitly blocked |

Phase 4C2 is accepted only after the same commit passes the physical Windows validator and GitHub CI.
