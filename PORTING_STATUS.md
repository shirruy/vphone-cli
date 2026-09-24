# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | PASS | Verified on Windows 11 Pro build 26200 / AMD64 on 2026-09-24: clean `windows-port` branch, MSVC 19.44, CMake configure/build PASS, 3/3 CTest PASS, `vphone-vm-win --capabilities` JSON contract PASS, persistent storage = supported and all unproven runtime capabilities remain unknown. |
| 1 | Portability census | PASS | 373 tracked compile units classified with 0 UNKNOWN: 6 PORTABLE, 281 SHIMMABLE, 63 REWRITE, 23 APPLE_ONLY. Physical Windows validation PASS with 4/4 tests including upstream-derived `upstream_ftab_roundtrip`. GitHub Actions run 36041715082 also PASS for Configure, Build, Census, Test, FTAB proof, and evidence upload. |
| 2 | Host abstraction boundary | IN_PROGRESS | Phase branch to be created from merged Phase 1. |
| 3 | Portable CLI/core build on Windows | NOT_STARTED | |
| 4 | Firmware/restore/archive parity | NOT_STARTED | |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here, not Phase 0 |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. Phase 1 proves complete compile-unit triage and one upstream-derived Windows-native compile/test path; it does not prove the full CLI/core, firmware pipeline, or VM boot.
