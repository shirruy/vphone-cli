# Phase 4D2C Bounded-Memory AEA Streaming

This phase replaces the previous whole-file Windows AEA wrapper with a bounded-buffer native file path.

Evidence requirements:

- Physical Windows build and test suite pass.
- 80 MB streaming stress roundtrip passes.
- The stress test enforces tracked hot-path buffers below 16 MB.
- Corrupted AEA input must fail closed and preserve the existing target file.
- Independent bidirectional interoperability against pinned kinnay/AEA remains green.
- Compile-unit census remains complete with zero UNKNOWN units.
- Full `aea_decrypt_encrypt` capability remains unsupported until physical Windows and CI both pass the exact same commit.

The supported streaming envelope currently caps AEA auth data at 16 MiB. This keeps memory use bounded while covering the profile-1 restore workflow.
