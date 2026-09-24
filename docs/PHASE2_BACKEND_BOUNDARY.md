# Phase 2: Backend Boundary

## Existing seam

The upstream design already separates:

`vphone-cli -> vphone-vm`

The CLI owns orchestration while the companion VM process owns the entitled
Virtualization.framework runtime. Phase 2 preserves that split.

## Protocol v1

The new platform-neutral envelope is JSON and currently defines one operation:
`boot`.

Fields:
- `protocol_version`
- `operation`
- `boot.config`
- `boot.dfu`
- `boot.headless`
- `boot.api_listen`
- `boot.kernel_debug_port`
- `boot.vphoned_bin`
- `boot.install_ipa`

The canonical fixture lives at:

`protocol/fixtures/backend_request_v1_boot.json`

## Compatibility invariant

On macOS:

`VPhoneBootCommand -> VPhoneBackendRequest -> VPhoneBootCommand`

must preserve the existing `bootArguments` exactly.

On Windows:

the same fixture must parse, validate, canonicalize, and reject unsupported
protocol versions or structurally invalid requests.

## Socratic gate

**Assumption:** the current process split is sufficient as the cross-platform
compatibility seam.

**Falsifier:** a boot option cannot be represented without embedding
Virtualization.framework types, or the same request has different semantics on
the two host implementations.

**Smallest executable experiment:** decode the same v1 request semantics in
Swift/macOS and C++/Windows, round-trip the existing macOS boot arguments, and
reject incompatible protocol versions.

**Silent-success risk:** independently written request types may drift while
each side's unit tests remain green. A shared fixture plus version rejection is
therefore required.

Phase 2 does not prove VM boot. It proves the boundary that later VM backends
must implement.
