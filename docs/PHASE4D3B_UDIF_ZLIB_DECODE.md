# Phase 4D3B: Native Windows zlib UDIF Decode

## Scope

Phase 4D3A proved RAW <-> uncompressed UDIF/UDRW container parity. Phase 4D3B adds a fail-closed native Windows decoder for the whole-disk blkx/mish map when the mapped runs are:

- zero-fill (0x00000000);
- raw/uncompressed (0x00000001);
- zlib (0x80000005);
- comment/terminator metadata.

The decoder validates the koly footer before touching the destination, requires exactly one whole-disk mish descriptor, rejects overlapping or uncovered output ranges, rejects payload ranges outside the data fork, streams zlib with bounded buffers, requires exact input/output lengths, and atomically replaces the destination only after full success.

## Deliberately unsupported

- ADC (0x80000004);
- bzip2 (0x80000006);
- arbitrary/unknown UDIF block types;
- APFS/HFS host mounting;
- filesystem-aware image grow/shrink;
- APFS sealing/root hash;
- canonical Apple metadata archive output.

Because mounting and resize are still absent, the aggregate capability disk_image_attach_convert remains unsupported.

## Evidence

A PASS requires the complete Windows build, all regressions green, the Phase 4D3A oracle green, an independently generated compressed zlib UDIF decoded byte-for-byte, corrupt zlib fail-closed behavior, unsupported ADC fail-closed behavior, zero UNKNOWN compile units, and the exact capability boundary.
