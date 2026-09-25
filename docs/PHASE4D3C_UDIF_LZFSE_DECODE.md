# Phase 4D3C: Native Windows LZFSE UDIF Decode

Phase 4D3C extends the Phase 4D3B whole-disk UDIF decoder with block type 0x80000007 (LZFSE / ULFO).

Validation keeps the previous RAW/UDRW and zlib oracles as regressions and adds an independently generated pyliblzfse fixture.

Safety boundary:
- maximum compressed LZFSE run: 64 MiB;
- maximum decoded LZFSE run: 64 MiB;
- temporary output plus atomic replace;
- corrupt LZFSE fails without changing an existing destination;
- bzip2 remains fail-closed and unsupported;
- aggregate disk-image attach/convert remains unsupported.

Still unsupported: ADC, bzip2, xz/LZMA UDIF, APFS/HFS host mounting, filesystem-aware resize, APFS sealing, and canonical Apple metadata archive output.
