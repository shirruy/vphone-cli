# Acceptance Matrix

| Capability | macOS upstream baseline | Windows target | Current status |
|---|---|---|---|
| CLI help | yes | native `.exe` | NOT_TESTED |
| VM library create/list/info | yes | parity | NOT_TESTED |
| Firmware manifest handling | yes | parity | NOT_TESTED |
| Patching core | yes | parity | NOT_TESTED |
| Archive import/export | yes | parity | NOT_TESTED |
| Restore flow | yes | parity | NOT_TESTED |
| VM boot | PV=3 Virtualization.framework | QEMU-derived Windows backend | NOT_TESTED |
| Serial boot evidence | yes | yes | NOT_TESTED |
| Persistent storage | yes | yes | NOT_TESTED |
| Guest API | HTTP/WebSocket over host bridge/VSOCK | same API semantics | NOT_TESTED |
| Display | Virtualization.framework | native Windows host window/framebuffer | NOT_TESTED |
| Touch/input | Apple virtual device APIs | injected backend events | NOT_TESTED |
| Audio | Virtio sound via Apple framework | backend equivalent | NOT_TESTED |
| Network | Virtualization.framework | user/NAT first | NOT_TESTED |
| SEP behavior | private VZ config | model or compatible substitute | NOT_TESTED |
| SpringBoard | upstream supported guest flow | required for graphical parity | NOT_TESTED |
| Screenshot automation | yes | yes | NOT_TESTED |
| End-to-end relaunch | yes | yes | NOT_TESTED |
