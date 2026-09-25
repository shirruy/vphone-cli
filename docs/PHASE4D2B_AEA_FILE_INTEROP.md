# Phase 4D2B AEA File Backend + Independent Interoperability

| Capability | Windows Phase 4D2B | Evidence |
|---|---|---|
| AEA profile 1 native crypto core | SUPPORTED | Phase 4D2A regression suite |
| Native Windows file encrypt/decrypt API | SUPPORTED | Atomic file backend roundtrip |
| Native Windows AEA utility | SUPPORTED | vphone-aea-win encrypt/decrypt |
| C++ encoder -> independent decoder | SUPPORTED | Pinned kinnay/AEA reference decodes native archive |
| Independent encoder -> C++ decoder | SUPPORTED | Native decoder restores pinned reference archive |
| Reference implementation | PINNED | kinnay/AEA d22f4fdf620436d12f1a893bbb11b90ac52fa646 |
| Windows LZFSE Python oracle | PINNED | pyliblzfse 0.4.1 Windows wheel from iLEAPP |
| Full /usr/bin/aea replacement | NOT YET | Memory-backed file API still needs bounded-memory streaming proof |

Phase 4D2B does not overclaim the final AEA backend. Phase 4D2C must prove bounded-memory file processing before aea_decrypt_encrypt becomes supported.
