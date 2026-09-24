# Initial Portability Audit

## Baseline

Upstream: `Lakr233/vphone-cli`
Pinned audit commit: `d308fb9956afcbf5ad063b1680969d2692a4d9de`
License: MIT
Source-tree size observed during audit: 736 entries.

## Existing architectural advantage

Upstream already separates the normal CLI from the privileged/private-entitlement VM process:

- `vphone-cli`: argument parsing/orchestration
- `vphone-vm`: Virtualization.framework-backed runtime
- `vphone-archive`: archive helper

That process boundary should become the primary Windows seam. Do not start by rewriting the whole product.

## Apple-bound surface observed

The audit found direct use of `Virtualization.framework` in the runtime/UI and selected core support code, including:

- `VPhoneVirtualMachine.swift`
- `VPhoneVirtualMachineHardwareModel.swift`
- `VPhoneVirtualMachineView.swift`
- guest control/VSOCK proxy code
- camera/screen/input host-device code
- networking helpers

The hardware model explicitly creates private PV=3 configuration with private Apple APIs. The runtime also configures Apple/macOS-specific objects for auxiliary storage, boot loader, graphics, audio, PL011 serial, accelerators, touch, entropy, keyboard, VSOCK, synthetic battery, debug stubs, and SEP.

## More portable surfaces

The repository contains substantial logic that is not conceptually tied to Virtualization.framework:

- ARM64 patching primitives
- Mach-O parsing
- IM4P handling
- firmware manifest selection
- dyld shared cache patching
- restore-core C code derived around mobile restore/recovery flows
- signing implementation
- archive implementation
- VM manifest/library/orchestration logic
- guest HTTP/WebSocket API model

These are candidates for extraction or Windows-compatible builds, but each must be proven by compile and parity tests. Do not equate `Foundation` with portability automatically: Apple-only APIs are mixed into some modules.

## Additional macOS-only preparation dependencies observed

The current firmware/custom-firmware path also references macOS host tooling such as `hdiutil`, `diskutil`, `cryptexctl`, `/usr/bin/aea`, and SecurityResearch/APFS sealing helpers. These are separate from the VM runtime problem. A Windows port must either replace each operation with a portable implementation or explicitly fail the corresponding capability gate.

This means a successful Windows VM backend alone is not end-to-end parity. Firmware preparation and APFS/cryptex mutation are independent blockers and need their own golden-output tests.

## Windows-specific constraints

1. A Windows x64 host cannot hardware-virtualize an ARM64 guest through WHPX. Cross-ISA execution requires software translation such as QEMU TCG.
2. QEMU WHPX supports ARM64 guests with hardware acceleration on Windows-on-ARM hosts that meet its minimum OS requirements.
3. Upstream QEMU has a `vmapple` machine model for Apple's macOS Virtualization.framework-style device model, but its documented setup is not a drop-in PV=3 iPhone runtime.
4. `qemu-sptm`/`darwin-vm` demonstrates modern Apple Silicon/iOS kernel boot support in QEMU, but currently describes itself as a barebones Darwin environment, not a full graphical iPhone/SpringBoard implementation.

## Initial conclusion

The rational first target is not "full iPhone UI on Windows." The rational target sequence is:

1. make the portable host tooling build and test on Windows;
2. define a stable `vphone-vm` backend contract;
3. prove an Apple ARM boot on Windows using a QEMU-derived research backend;
4. only then invest in the missing PV/device/display stack needed for a full iPhone experience.

Anything else creates a beautiful pile of code with no boot proof.
