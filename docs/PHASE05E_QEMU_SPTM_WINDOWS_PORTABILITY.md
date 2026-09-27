# Phase 5E qemu-sptm Native Windows Portability

## Certified parent

Phase 5D:

a35190c76e1371b098cfcb403e536a98658becb9

## External source compatibility

darwin-vm:

ffdf01874f5cc9cdfbfc7a3d117d4aef1e49b4d9

qemu-sptm:

2867d847d3471560e773120ee50c42dbcbb6d60b

The darwin-vm revision above pins the qemu-sptm revision above.

## Purpose

Phase 5E proves that the qemu-sptm Darwin machine can be ported to a
native Windows x64/MSYS2 MINGW64 build far enough to produce and execute
qemu-system-aarch64.exe on Windows.

## Windows portability patch

The durable patch is:

windows/patches/qemu-sptm/phase05e-windows-portability.patch

SHA256:

3b869ccaef78395677ec02c4afc807562ec52a52c35a4d840e71ddc90a862d6e

The patch changes exactly four upstream files:

1. hw/arm/apple_dtree.c
2. hw/arm/apple_regs.c
3. hw/arm/darwin.c
4. hw/arm/xnuboot_sptm.c

## Portability changes

The Phase 5E patch performs four bounded changes.

First, it removes an unused sys/mman.h include from xnuboot_sptm.c.

Second, it replaces the POSIX mmap/munmap file-buffer path in darwin.c
with GLib g_file_get_contents and g_free.

Third, it replaces BSD strsep path tokenization in apple_dtree.c with
GLib g_strsplit.

Fourth, it replaces BIT(36) and BIT(63) with BIT_ULL equivalents where
Windows LLP64 would otherwise use a 32-bit unsigned long.

## Build configuration

Target:

aarch64-softmmu

Host:

Windows x64 using MSYS2 MINGW64

QEMU plugins:

Disabled for this gate because the Windows delay-library plugin build
is unrelated to Darwin machine execution and failed before Apple code
was reached.

Rust:

Disabled

Documentation:

Disabled

## Executed proof

The resulting native Windows qemu-system-aarch64.exe executes directly
on Windows.

The Darwin machine appears in -machine help.

A payload-free launch using -machine darwin enters Darwin machine
initialization and fails closed at the first Apple payload boundary
with:

error opening XNU kernel

This proves machine selection and initialization execution on Windows.

## Explicit non-claims

Phase 5E does not prove:

- Apple firmware preparation
- Apple kernel execution
- Apple guest boot
- deterministic serial output
- SpringBoard
- graphical display
- input
- networking
- audio
- full virtual iPhone execution

## Next milestone

After Phase 5E is committed and independently reproduced in GitHub
Windows CI, the next runtime experiment may introduce the minimum
authorized guest payload necessary to pursue a deterministic serial
boot milestone.