# Phase 5E Darwin Machine Payload-Free Startup Probe

## VPhone

Branch:

phase/05e-qemu-sptm-windows-feasibility

HEAD:

a35190c76e1371b098cfcb403e536a98658becb9

## Native Windows qemu-sptm

Source base:

2867d847d3471560e773120ee50c42dbcbb6d60b

Executable:

C:\Users\rbjos\source\vphone-cli-windows\build\phase05e-qemu-sptm-source-build\darwin-vm\qemu-sptm\build-win\qemu-system-aarch64.exe

Version:

QEMU emulator version 11.1.0

SHA256:

d4d74db8c2ac45fb1b6ecabe32171823711e99a8a758f2ca4567f90753fbe875

## Probe

Machine:

darwin

Accelerator:

tcg

Apple payloads supplied:

NONE

bootkc:

NOT PROVIDED

Device tree:

NOT PROVIDED

Trust cache:

NOT PROVIDED

Ramdisk:

NOT PROVIDED

SPTM:

NOT PROVIDED

TXM:

NOT PROVIDED

## Runtime result

Process started:

PASS

Process exited:

PASS

Exit code:

1

Expected fail-closed marker:

error opening XNU kernel

Expected marker observed:

PASS

## Interpretation

The native Windows qemu-sptm executable accepted the Darwin
machine selection and entered the Darwin machine initialization
path.

Initialization stopped at the first Apple payload boundary because
no XNU kernel was supplied.

This is the expected payload-free result.

## Explicit non-claims

Apple firmware preparation:

NOT TESTED

Apple kernel execution:

NOT TESTED

Apple guest boot:

NOT TESTED

Serial boot milestone:

NOT TESTED

Graphical guest:

NOT TESTED