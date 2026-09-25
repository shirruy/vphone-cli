# Phase 4D3D: Native Windows BZIP2 UDIF Decode

Phase 4D3D extends the whole-disk UDIF decoder with block type 0x80000006 (BZIP2).

Validation preserves the Phase 4D3A RAW/UDRW, Phase 4D3B zlib, and Phase 4D3C LZFSE oracles as regressions, then adds an independent Python bz2-generated BZIP2 fixture.

Safety boundary:
- streaming BZIP2 decompression with bounded input/output buffers;
- exact compressed-input consumption;
- exact declared sector-span output length;
- corrupt BZIP2 fails without replacing an existing destination;
- ADC remains fail-closed and unsupported;
- aggregate disk-image attach/convert remains unsupported.

Still unsupported: ADC and other unimplemented UDIF codecs, APFS/HFS host mounting, filesystem-aware resize, APFS sealing, and canonical Apple metadata archive output.
