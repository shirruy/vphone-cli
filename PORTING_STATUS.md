# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | PASS | Verified on Windows 11 Pro build 26200 / AMD64 on 2026-09-24: clean `windows-port` branch, MSVC 19.44, CMake configure/build PASS, 3/3 CTest PASS, `vphone-vm-win --capabilities` JSON contract PASS, persistent storage = supported and all unproven runtime capabilities remain unknown. |
| 1 | Portability census | IN_PROGRESS | Initial dependency census exists; expanding to a complete compile-unit and host-dependency matrix. |
| 2 | Host abstraction boundary | NOT_STARTED | |
| 3 | Portable CLI/core build on Windows | NOT_STARTED | |
| 4 | Firmware/restore/archive parity | NOT_STARTED | |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here, not Phase 0 |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. Phase 0 proves only repository provenance, the Windows-native scaffold/toolchain, its CLI contract, and its fail-closed test harness.
