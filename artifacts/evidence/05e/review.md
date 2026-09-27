# Phase 5E Review

## Question

Did Phase 5E prove that the pinned qemu-sptm Darwin machine can be
built and entered on native Windows?

## Answer

Yes, within the bounded Phase 5E scope.

The pinned qemu-sptm source was compiled under Windows x64 using
MSYS2 MINGW64 after applying the sealed four-file portability patch.

The resulting qemu-system-aarch64.exe executed directly on Windows.

The Darwin machine was present in the runtime machine registry.

A payload-free Darwin launch entered the Darwin initialization path
and failed closed at the expected first payload boundary:

error opening XNU kernel

## Why is the non-zero probe exit a PASS?

The probe intentionally supplies no bootkc, device tree, trust cache,
ramdisk, SPTM, or TXM payload.

The declared milestone is therefore not successful guest execution.

The declared milestone is successful Darwin machine selection followed
by deterministic rejection at the first missing Apple payload boundary.

## What did Phase 5E not prove?

Phase 5E did not prove Apple firmware preparation, Apple kernel
execution, guest boot, serial output, SpringBoard, graphics, input,
audio, networking, guest APIs, or a complete virtual iPhone.

## Remaining risk

The Darwin machine still requires real Apple-specific guest inputs for
the next runtime milestone.

Those inputs must not be introduced until Phase 5E has been committed
and independently reproduced in CI.

## Disposition

PASS for Phase 5E bounded Windows Darwin-machine feasibility.

Phase 5 remains IN_PROGRESS.