# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | PASS | Revalidated on physical Windows host and CI with explicit Release-mode checks. Windows 11 Pro / AMD64 preflight PASS, MSVC/CMake build PASS, backend contract PASS, CLI capability contract PASS. |
| 1 | Portability census | PASS | Revalidated after removal of Release-disabled `assert` tests. 377 current compile units classified with 0 UNKNOWN: 23 APPLE_ONLY, 63 REWRITE, 283 SHIMMABLE, 8 PORTABLE. Upstream-derived `MobileRestoreCore/Firmware/Containers/ftab.c` compiled under MSVC and `upstream_ftab_roundtrip` passed with explicit runtime checks. |
| 2 | Host abstraction boundary | PASS | Protocol v1 implemented and verified on physical Windows plus GitHub Windows and macOS CI at code commit `4e6e9d2b0d44a2316b9cf0a88bc206a86609f6eb`. Physical Windows cumulative gate: preflight PASS, census 377/0 UNKNOWN, 7/7 Release-mode CTest PASS, shared v1 fixture accepted. GitHub `windows-protocol`, `macos-protocol`, and `windows-port-smoke` all SUCCESS. |
| 3 | Portable CLI/core build on Windows | IN_PROGRESS | Build a native Windows orchestration surface against the v1 backend protocol without linking Apple-only host frameworks. |
| 4 | Firmware/restore/archive parity | NOT_STARTED | |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. Phases 0-2 prove the Windows-native scaffold/toolchain, full compile-unit census, upstream-derived Windows execution proof, and a versioned cross-platform backend protocol with matching Windows/macOS semantics.
