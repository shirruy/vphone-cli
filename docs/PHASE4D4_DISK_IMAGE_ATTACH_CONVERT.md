# Phase 4D4: Native Windows Disk Image Attach / Convert Baseline

## Goal

Promote the current restore-image backend from codec-level UDIF decode parity to a usable Windows-native disk-image preparation boundary.

## Inherited verified capabilities

- UDRW/raw conversion
- UDIF zlib decode
- UDIF LZFSE decode
- UDIF BZIP2 decode
- UDIF ADC decode
- fail-closed output semantics
- bounded decode paths

## Current unsupported boundary

- disk image attach / convert orchestration
- filesystem-aware resize
- APFS sealing / root hash
- canonical Apple metadata archive output

## Phase 4D4 acceptance direction

The implementation must remain fail closed. It must not report disk_image_attach_convert as supported until the exact Windows-native path has executable evidence on physical Windows and CI.

No macOS runtime fallback is allowed.
