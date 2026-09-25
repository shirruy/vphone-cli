# Phase 4D2C Bounded-Memory AEA Streaming

This phase replaces the previous whole-file Windows AEA wrapper with a bounded-buffer native file path.

Evidence requirements:

- Physical Windows build and test suite pass.
- 80 MB streaming stress roundtrip passes.
- The stress test enforces tracked hot-path buffers below 16 MB.
- Corrupted AEA input must fail closed and preserve the existing target file.
- Independent bidirectional interoperability against pinned kinnay/AEA remains green.
- Compile-unit census remains complete with zero UNKNOWN units.
- Parent evidence commit `5ddd569cf47636f58574da7a936dfedf4149c33b` passed both physical Windows and GitHub CI on the exact same commit.
- Full `aea_decrypt_encrypt` capability is now promoted to `supported`.
- The promotion commit itself must also pass physical Windows and CI before Phase 4D2C is marked closed.

The supported streaming envelope currently caps AEA auth data at 16 MiB. This keeps memory use bounded while covering the profile-1 restore workflow.

## Promotion gate

The capability promotion is intentionally a separate exact-commit gate. A PASS requires the promotion commit to complete the full Phase 4D2C validator on physical Windows and the matching GitHub Actions workflow successfully.
