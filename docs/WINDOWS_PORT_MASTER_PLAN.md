# vphone-cli Native Windows Port: End-to-End Master Plan

## Goal

Deliver a native Windows workflow with the same user-facing intent as vphone-cli: create/manage a virtual iPhone environment, boot it, interact with it, and automate it. The implementation may use a different host virtualization backend. Compatibility claims must be evidence-backed.

## Definition of "native Windows"

- primary orchestration and runtime processes execute on Windows;
- no macOS VM is required at runtime;
- no remote Mac is required at runtime;
- Apple firmware is user-supplied and is not redistributed;
- any preparation step that still requires macOS is tracked as a blocking gap, not hidden.

## Phase 0: Freeze the baseline

Questions:
- Which upstream commit is the reference?
- Which commands and observable behaviors define parity?
- Which firmware/device pairs are the minimum acceptance fixtures?

Work:
- pin upstream SHA;
- inventory commands, schemas, VM files, APIs and tests;
- capture license/provenance;
- create a baseline behavior matrix.

PASS evidence:
- immutable SHA;
- command inventory;
- source-to-test map;
- no ambiguous baseline.

## Phase 1: Portability census

Questions:
- Which compile units are pure Swift/C/C++?
- Which rely on AppKit, Security, Virtualization.framework, Darwin-only syscalls, Xcode build phases, or Apple private APIs?
- Which dependencies have Windows equivalents?

Work:
- generate import/API dependency graph;
- classify every target: PORTABLE, SHIMMABLE, REWRITE, APPLE_ONLY, UNKNOWN;
- attempt Windows compile of smallest pure modules.

PASS evidence:
- 100% compile-unit classification;
- automated report;
- at least one portable upstream-derived module compiled and unit-tested on Windows.

## Phase 2: Stabilize the process boundary

Decision:
Use the existing `vphone-cli` -> `vphone-vm` split as the compatibility seam.

Questions:
- What exact boot manifest must cross the boundary?
- Which commands require direct VM process access?
- Can guest-control semantics remain stable while transport changes?

Work:
- define versioned backend protocol;
- serialize VM configuration in a platform-neutral form;
- isolate Apple implementation behind a macOS backend adapter;
- add a Windows stub backend that fails loudly with structured capability results.

PASS evidence:
- macOS backend still passes upstream tests;
- Windows backend executable compiles and returns deterministic capability JSON;
- protocol compatibility tests pass.

## Phase 3: Native Windows CLI/core

Questions:
- Can Swift code build under SwiftPM on Windows without Xcode-only targets?
- Where must Security/CryptoKit behavior be replaced or conditionally compiled?
- Can archive/sign/manifest code retain byte parity?

Work:
- create Windows SwiftPM layout or a thin Windows orchestration layer;
- replace platform calls with narrow interfaces;
- keep file formats unchanged.

PASS evidence:
- `vphone-cli.exe --help` on Windows;
- VM library create/list/info operations pass without booting;
- config/manifest round trips match macOS fixtures.

## Phase 4: Firmware, archive, restore and signing parity

Questions:
- Are outputs byte-identical or semantically identical?
- Which steps depend on APFS mounting or Apple host tools?
- Can those steps use portable libraries or an isolated helper?

Work:
- port pure patching/signing/archive logic first;
- build golden-fixture tests from legally user-supplied local fixtures;
- never commit Apple firmware.

PASS evidence:
- hash/parity report per operation;
- no silent fallback to macOS-only tools;
- failures identify the exact unsupported operation.

## Phase 5: Windows ARM boot feasibility spike

This is the project-killer gate. Do it before GUI work.

Backend candidates:
1. QEMU-derived Apple Silicon machine/device work, including research from `qemu-sptm`/`darwin-vm`;
2. upstream QEMU `vmapple` components where applicable;
3. TCG on Windows x64 for correctness research;
4. WHPX on Windows ARM64 for acceleration after correctness is established.

Questions:
- Can the required boot chain reach deterministic serial output on Windows?
- Which Apple PV=3 behaviors are already modeled and which are missing?
- Does the guest require SEP/device behavior not present in the candidate backend?

Minimum experiment:
- headless only;
- one CPU if needed;
- serial log enabled;
- no graphical SpringBoard requirement;
- explicit boot milestone markers.

PASS evidence:
- reproducible Windows command line;
- serial log proving the agreed boot milestone;
- process exit behavior documented;
- hash of backend build and firmware inputs recorded.

If this fails, STOP. Do not build a UI around a non-booting backend.

## Phase 6: Device-model parity

Map upstream runtime devices one by one:

- boot ROM / auxiliary storage / NVRAM
- block storage
- interrupt controller / timers / Apple-specific CPU/system registers
- serial
- entropy
- network
- host/guest communication transport
- input/touch/keyboard
- display/framebuffer/graphics
- audio
- battery/power
- SEP/security coprocessor behavior
- debug interfaces

For every device ask:
- required for boot, required for SpringBoard, or optional?
- what observable guest behavior proves correctness?
- can a generic VirtIO device substitute without guest patches?

PASS evidence:
- device matrix with executable tests;
- no device marked supported from source inspection alone.

## Phase 7: Persistent VM and restore lifecycle

Questions:
- Can create -> restore -> stop -> relaunch preserve identity and disk state?
- Are interrupted restores transactional?
- Can corruption be detected before boot?

PASS evidence:
- clean create/restore/launch cycle;
- forced interruption tests;
- state hash and identity stability checks.

## Phase 8: Full interaction surface

Order:
1. framebuffer/display output;
2. touch/input;
3. keyboard/clipboard;
4. audio;
5. network;
6. camera/location/other optional host devices.

SpringBoard is the gate for calling the product a graphical virtual iPhone.

PASS evidence:
- guest-generated frame captured on Windows;
- deterministic tap coordinates produce expected guest response;
- automated screenshot assertions with tolerances;
- restart/reconnect tests.

## Phase 9: Guest API and automation

Preserve the useful semantics of vphoned where possible.

Questions:
- Can the existing HTTP/WebSocket API survive a transport change?
- Is VSOCK available and reliable in the chosen backend on Windows?
- If transport changes, can the client API remain stable?

PASS evidence:
- ping;
- screenshot;
- tap/swipe;
- text/input;
- clipboard;
- app/file operations selected for parity;
- disconnect/reconnect and malformed-request tests.

## Phase 10: Packaging and CI

Deliverables:
- signed/hashed Windows release artifacts;
- deterministic dependency manifest;
- no hidden Homebrew/macOS runtime dependency;
- Windows x64 research build and Windows ARM64 accelerated build clearly separated if both exist;
- update/sync procedure from upstream.

CI gates:
- format/lint;
- unit tests;
- contract tests;
- Windows build;
- dependency/provenance scan;
- fixture-free smoke test;
- optional hardware E2E runner for boot evidence.

## Phase 11: Final E2E acceptance

The port is not DONE until one documented flow performs:

`preflight -> create -> firmware prepare -> restore -> launch -> reach graphical guest -> input -> guest API -> stop -> relaunch -> state retained`

Every step must emit evidence. Final reconciliation must separate:

- PASS: executed and verified;
- FAIL: executed and incorrect;
- BLOCKED: environment/hardware prevents execution;
- NOT_TESTED: no execution evidence.
