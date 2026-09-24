# Phase 1 Portability Census

## Socratic gate

**Assumption being tested:** a meaningful portion of the upstream codebase can be separated from Apple-only host runtime dependencies and compiled on Windows without pretending the full product is portable.

**What would falsify it:** unclassified compile units, category drift with no explicit review, or failure to compile and execute even one upstream-derived production module on Windows.

**Smallest executable proof:** compile and round-trip test upstream `MobileRestoreCore/Firmware/Containers/ftab.c` under MSVC using only a narrow logger compatibility header. The test exercises add -> serialize -> parse -> lookup -> compare.

**Invariant:** the FTAB payload must survive the round trip byte-for-byte.

**Silent-success risk:** compiling only Windows-authored scaffolding would falsely look like upstream portability. Therefore the Phase 1 CTest suite must register and execute `upstream_ftab_roundtrip`.

## Baseline census

The tracked branch census covers every `.swift`, `.c`, `.cc`, `.cpp`, `.cxx`, `.m`, and `.mm` compile unit. The executable census fails closed if a file has no rule.

Current baseline:
- 373 compile units
- 23 APPLE_ONLY
- 281 SHIMMABLE
- 63 REWRITE
- 6 PORTABLE
- 0 UNKNOWN

The categories are architectural triage, not claims that every SHIMMABLE unit already compiles on Windows.
