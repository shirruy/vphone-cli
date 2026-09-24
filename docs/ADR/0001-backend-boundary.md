# ADR 0001: Preserve the CLI/VM Process Boundary

Status: ACCEPTED FOR SPIKE

## Decision

Treat the existing `vphone-cli` -> `vphone-vm` process split as the cross-platform seam. Keep orchestration/file-format semantics stable and replace the VM implementation per host.

## Why

A process boundary is easier to keep stable than sprinkling `#if os(Windows)` through private Apple VM APIs. It also permits the Windows VM backend to be implemented in C/C++ around QEMU without forcing the entire runtime into Swift.

## Consequences

- define a versioned boot/control protocol;
- macOS keeps its Virtualization.framework backend;
- Windows obtains its own backend executable;
- parity is measured at the boundary and at guest-visible behavior.
