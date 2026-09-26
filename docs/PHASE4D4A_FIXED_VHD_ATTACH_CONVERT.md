# Phase 4D4A: Native Windows Fixed VHD Convert + Read-Only Attach Probe

## Goal

Replace the first useful part of the macOS `hdiutil` / `diskutil` boundary with a Windows-native path that can:

1. preserve a decoded raw disk byte-for-byte inside a fixed VHD;
2. produce a standards-shaped fixed VHD footer;
3. ask the Windows Virtual Disk API to attach the VHD read-only with no drive letter;
4. obtain the physical-disk path;
5. detach immediately after the probe.

## Safety boundary

The attach probe is deliberately read-only and requests no drive letter.

This phase does **not** mount APFS, modify partitions, resize a filesystem, seal APFS, or write Apple metadata archives.

The aggregate `disk_image_attach_convert` capability remains fail-closed until physical Windows attach evidence and CI conversion evidence are both green on the exact promotion commit.

## Granular capability state on the implementation commit

- `disk_image_fixed_vhd_convert`: supported by native round-trip tests
- `disk_image_fixed_vhd_attach_readonly`: implemented_not_promoted
- `disk_image_attach_convert`: unsupported until promotion gate

## Physical Windows gate

Run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\phase4d4a-validation.ps1 -PhysicalAttachProbe
```

A physical PASS must show a non-empty Windows physical disk path and successful detach.
