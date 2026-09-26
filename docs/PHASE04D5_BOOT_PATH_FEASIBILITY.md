# PHASE 4D5 - WINDOWS BOOT PATH FEASIBILITY

## Objective

Establish the exact boundary between the Windows host capabilities already
implemented in Phase 4D4C and the remaining runtime work required before a
virtual iPhone guest boot attempt is technically legitimate.

## Certified inheritance

Phase 4D4C already proves:

- fixed VHD conversion
- fixed VHD read-only attach
- aggregate attach/convert capability
- physical Windows attach probe
- automatic detach
- exact-commit Windows CI
- windows-port-smoke CI

## Phase 4D5 does NOT claim

Phase 4D5 does not claim:

- iOS boot
- iBoot execution
- Apple machine-model parity
- SEP emulation
- APFS mounting
- display/input parity
- guest networking
- guest transport
- hardware acceleration

## Boot-critical upstream requirements

The upstream/macOS runtime currently depends on equivalents for:

- Apple hardware model
- machine identifier / ECID
- NVRAM auxiliary storage
- ROM bootloader
- PL011 serial
- block device
- graphics
- network
- virtio socket
- touch input
- synthetic battery
- SEP
- GDB debug stub
- DFU start semantics

Phase 5 may begin only after Phase 4D5 produces deterministic feasibility
evidence while the Windows runtime remains fail-closed.

## Correct engineering invariant

A feasibility PASS is not a boot PASS.

The Windows backend must continue refusing launch until a real runtime backend
has been implemented and tested.