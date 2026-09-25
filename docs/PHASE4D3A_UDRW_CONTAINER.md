# Phase 4D3A: Native Windows UDIF/UDRW Container Parity

## Scope

This slice replaces only the host-side RAW <-> uncompressed UDIF/UDRW container conversion primitive used by the restore-image workflow.

Supported in this slice:

- deterministic RAW disk image wrapping into an uncompressed UDIF/UDRW-style container;
- koly footer generation and validation;
- blkx/mish raw-run metadata generation;
- extraction of a contiguous raw UDIF data fork;
- bounded-memory streaming copies;
- atomic/fail-closed output replacement;
- independent Python plist/footer/block-map verification.

Not supported yet:

- compressed DMG/UDIF decoding;
- Windows attachment/mounting of APFS or HFS volumes;
- filesystem-aware grow/shrink-to-min operations;
- APFS sealing/root-hash generation;
- Apple canonical metadata archive generation.

The aggregate capability \`disk_image_attach_convert\` therefore remains \`unsupported\`.

## Evidence gate

A PASS requires:

1. complete Windows build;
2. all regression tests green;
3. synthetic 32 MiB UDRW roundtrip test green;
4. independent Python parser/oracle green;
5. fail-closed corrupted-footer test preserving the existing destination;
6. compile-unit census with zero UNKNOWN;
7. capability JSON reporting \`disk_image_udrw_raw_convert=supported\` while the aggregate attach/convert capability remains unsupported.
