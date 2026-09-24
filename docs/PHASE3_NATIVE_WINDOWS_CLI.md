# Phase 3: Native Windows CLI/Core

## Goal

Build a Windows-native orchestration surface that converts user-facing VM launch options into the already verified Backend Protocol v1 without linking Apple-only host frameworks.

## Native executable

vphone-cli-win.exe

Supported Phase 3 proof surface:

- vphone-cli-win --help
- vphone-cli-win --version
- vphone-cli-win protocol-version
- vphone-cli-win vm launch --config PATH [boot options] --dry-run

The --dry-run option emits the canonical Protocol v1 JSON request.

Live VM execution is deliberately rejected during Phase 3 because the Windows VM runtime is not yet proven. ARM/iOS execution belongs to Phase 5.

## Socratic gate

Assumption: command orchestration can be made Windows-native without depending on AppKit, Security.framework, or Virtualization.framework.

Falsifier: representing or validating a boot request requires Apple host types, or Windows option parsing changes the verified Protocol v1 semantics.

Executable proof: build vphone-cli-win.exe under MSVC Release, generate the canonical boot request from user-facing flags, validate all fields, and fail closed for invalid DFU/API combinations and unsupported live execution.

Silent-success risk: an executable that only prints help is not a portable CLI/core proof. The gate therefore requires semantic request generation and negative-path tests.
