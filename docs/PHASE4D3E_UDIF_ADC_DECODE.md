# Phase 4D3E: Native Windows ADC UDIF Decode

Phase 4D3E extends the native Windows UDIF decoder with Apple Disk Copy (ADC) block type `0x80000004`.

The Windows implementation is intentionally bounded and fail closed:

- ADC literals are decoded directly from the declared compressed run.
- 2-byte back-references support lengths 3 through 18 and offsets up to 1023.
- 3-byte back-references support lengths 4 through 67 and offsets up to 65535.
- A 64 KiB history window is retained, matching the format's maximum back-reference distance.
- Back-references before the start of output are rejected.
- Truncated commands are rejected.
- Output beyond the declared sector span is rejected.
- Output shorter than the declared sector span is rejected.
- Existing destination files are preserved on decode failure through the existing temporary-file/atomic-replace path.

Validation includes the Phase 4D3A RAW/UDRW, Phase 4D3B zlib, Phase 4D3C LZFSE, and Phase 4D3D BZIP2 regressions plus an independent Python ADC oracle covering literal, 2-byte, 3-byte, corrupt, truncated, and trailing-input cases.

This phase does not claim APFS/HFS mounting, filesystem-aware resizing, APFS sealing, or canonical Apple metadata archive output.
