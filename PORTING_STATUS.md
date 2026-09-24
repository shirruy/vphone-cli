# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | PASS | Verified on Windows 11 Pro / AMD64: clean `windows-port` branch, MSVC/CMake build PASS, 3/3 CTest PASS, CLI capability contract PASS. |
| 1 | Portability census | PASS | Verified on physical Windows host and GitHub Actions. 373 compile units classified with 0 UNKNOWN: 23 APPLE_ONLY, 63 REWRITE, 281 SHIMMABLE, 6 PORTABLE. MSVC built upstream-derived `MobileRestoreCore/Firmware/Containers/ftab.c`; `upstream_ftab_roundtrip` passed. Physical host: 4/4 CTest PASS. GitHub Actions run for commit `36ca7009f2c564cbf172e29aed63d112ad77f47e`: SUCCESS. |
| 2 | Host abstraction boundary | IN_PROGRESS | Stabilize the existing `vphone-cli -> vphone-vm` process seam into a versioned, platform-neutral backend protocol. |
| 3 | Portable CLI/core build on Windows | NOT_STARTED | |
| 4 | Firmware/restore/archive parity | NOT_STARTED | |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here, not Phase 0 |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. Phase 0 and Phase 1 prove the Windows-native scaffold/toolchain, evidence harness, full compile-unit census, and at least one upstream-derived production module compiling and executing correctly on Windows.
