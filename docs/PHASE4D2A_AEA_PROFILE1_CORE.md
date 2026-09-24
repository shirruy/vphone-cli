# Phase 4D2A AEA Profile 1 Core

| Capability | Windows Phase 4D2A | Evidence |
|---|---|---|
| AEA1 profile 1 header/root parsing | SUPPORTED | Native C++ parser with fail-closed profile/size validation |
| HKDF-SHA256 / HMAC-SHA256 | SUPPORTED | Windows CNG implementation exercised by roundtrip |
| AES-256 CTR | SUPPORTED | Windows CNG ECB keystream + CTR counter implementation |
| LZFSE segment compression | SUPPORTED | Pinned lzfse commit e634ca58b4821d9f3d560cdc6df5dec02ffc93fd |
| Multi-cluster MAC chain | SUPPORTED | Test forces three clusters and validates chain |
| Segment SHA256/HMAC authentication | SUPPORTED | Wrong key and ciphertext mutation are rejected |
| Raw auth-data preservation | SUPPORTED | Roundtrip asserts byte-identical auth data |
| Full /usr/bin/aea file replacement | UNSUPPORTED | Streaming file I/O and independent interoperability vector still required |
| AEA signed/asymmetric/password profiles | UNSUPPORTED | Outside vphone's current profile-1 filesystem use case |

The full AEA backend remains fail-closed until Phase 4D2B proves Windows file streaming and independent interoperability.
