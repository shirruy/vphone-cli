# Windows Port Status

Upstream baseline: `d308fb9956afcbf5ad063b1680969d2692a4d9de`

| Phase | Name | Status | Evidence |
|---:|---|---|---|
| 0 | Baseline + provenance | REVALIDATION_REQUIRED | Repository/toolchain/CLI evidence remains valid, but one native C++ contract test used `assert` under Release and therefore did not provide executable assertion evidence. Revalidation pending with explicit checks. |
| 1 | Portability census | REVALIDATION_REQUIRED | Census completeness remains valid: 373 compile units, 0 UNKNOWN. The upstream FTAB proof used `assert` under Release, so its behavioral proof is invalidated pending rerun with explicit checks. |
| 2 | Host abstraction boundary | IN_PROGRESS | Protocol v1 implemented on Swift/macOS and C++/Windows. macOS CI passed at commit `4cddd49927f7085c871004dd9cbb06d5b983f230`. Windows exposed a real parser defect: the string value `"boot"` was mistaken for the `"boot"` key. Parser and Release-test harness remediation in progress. |
| 3 | Portable CLI/core build on Windows | NOT_STARTED | |
| 4 | Firmware/restore/archive parity | NOT_STARTED | |
| 5 | Windows ARM boot feasibility spike | NOT_STARTED | WHPX readiness belongs here, not Phase 0 |
| 6 | Apple device-model parity | NOT_STARTED | |
| 7 | Persistent VM + restore flow | NOT_STARTED | |
| 8 | Display/input/audio/network | NOT_STARTED | |
| 9 | Guest API + automation | NOT_STARTED | |
| 10 | Packaging + CI + release | NOT_STARTED | |
| 11 | Full E2E acceptance | NOT_STARTED | |

A full virtual iPhone on Windows is **not yet proven**. No phase relying on Release-mode `assert` tests will be treated as closed until the replacement explicit-check tests pass on the physical Windows host and CI.
