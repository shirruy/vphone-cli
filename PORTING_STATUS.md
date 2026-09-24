# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | PASS | Revalidated on physical Windows host and CI with explicit Release-mode checks. Windows 11 Pro / AMD64 preflight PASS, MSVC/CMake build PASS, backend contract PASS, CLI capability contract PASS. |
| 1 | Portability census | PASS | Revalidated after removal of Release-disabled `assert` tests. 380 current compile units classified with 0 UNKNOWN. Upstream-derived `MobileRestoreCore/Firmware/Containers/ftab.c` compiled under MSVC and `upstream_ftab_roundtrip` passed with explicit runtime checks. |
| 2 | Host abstraction boundary | PASS | Protocol v1 verified on physical Windows plus GitHub Windows and macOS CI. Shared v1 fixture semantics match on both hosts. |
| 3 | Portable CLI/core build on Windows | PASS | Verified on physical Windows and GitHub CI at commit `2bff88d0519634462fa3bbcff496505171441480`. Physical host: 380 compile units, 0 UNKNOWN, 11/11 Release-mode CTest PASS, native `vphone-cli-win.exe` generated the correct Protocol v1 request and rejected invalid paths fail-closed. GitHub `Windows Port Phase 3` and `windows-port-smoke` both SUCCESS. |
| 4 | Firmware/restore/archive parity | IN_PROGRESS | Phase 4A PASS. Phase 4B PASS. Phase 4C PASS on physical Windows and GitHub CI at closure head `a8d32012feafbd3c53b542c041480c0ed33e62dc`: 388 compile units, 0 UNKNOWN, 34/34 tests PASS, gzip/xz/zstd supported, bundle parity preserved, Phase 4C1 regression gate PASS, smoke PASS. Phase 4D now targets restore/image backend parity including AEA, disk image, APFS seal, metadata archive, and remaining restore primitives. |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. Phases 0-3 prove the Windows-native toolchain, full compile-unit census, upstream-derived Windows execution proof, a versioned cross-platform backend protocol, and a native Windows CLI/core orchestration layer.
