# Research References Used for the Initial Architecture

These are starting points, not proof that the Windows port works.

- Upstream vphone-cli: https://github.com/Lakr233/vphone-cli
- QEMU Windows Hypervisor Platform docs: https://www.qemu.org/docs/master/system/whpx.html
- QEMU ARM system emulation: https://www.qemu.org/docs/master/system/target-arm.html
- QEMU VMApple machine model: https://www.qemu.org/docs/master/system/arm/vmapple.html
- darwin-vm: https://github.com/jprx/darwin-vm
- qemu-sptm: https://github.com/jprx/qemu-sptm
- Historical qemu-t8030: https://github.com/TrungNguyen1909/qemu-t8030

Important distinctions:

- QEMU's `vmapple` models the device model exposed to Apple Silicon macOS guests by Virtualization.framework; it is not automatically equivalent to the private PV=3 iPhone configuration used by current vphone-cli.
- darwin-vm/qemu-sptm demonstrates modern Darwin/iOS kernel execution, but its own documentation says it is not a full graphical iPhone emulator.
- WHPX can accelerate ARM64 QEMU guests on compatible Windows ARM64 hosts. Windows x64 requires cross-ISA software translation for an ARM64 guest.
