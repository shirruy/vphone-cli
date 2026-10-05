# 57ZZ — ASCWrap Runtime Matching (Valid Instrumentation)

## Legacy P9 run (instrumentation later invalidated)

- Canonical ascwrap DT fixture; breakpoints were at vtable +0x348 entries and the nub factory.
- The +0x348 slot is NOT start (start is +0x360 per callsite proof); the P9 NO_HIT says nothing about AppleASCWrapV6::start.

## Valid provider runs (v2/v3)

- ARMIO allocator hits and callsite-proven +0x360 start dispatches observed live; no ASCWrap-family vtable in any observed client start.

## Timing

```
GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING: PROVEN
BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING: UNKNOWN
```


## Result

```
GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING: PROVEN
BREAKPOINT_ARMED_BEFORE_ARMIO_ALLOCATION_PHASE: PROVEN (earliest allocation t=0.057 post-attach, derived from provider runs)
BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING: UNKNOWN (ANS-specific alloc not yet identified among ARMIO allocations)
ARMIO_ALLOCATIONS_OBSERVED: >= 55
IOKIT_START_DISPATCHES_OBSERVED: >= 40
ASCWRAP_FAMILY_START_OBSERVED: False
LEGACY_P9_START_INSTRUMENTATION: INVALID_TARGET
APPLEASCWRAPV6_START_FROM_P9: UNKNOWN (instrumented +0x348, not start)
APPLEA7IOPNUB_START_FROM_P9: UNKNOWN (instrumented +0x348, not start)
MATCHING_STAGE_CLASSIFICATION: UNKNOWN_REQUIRES_ANS_NAME_CORRELATION
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
58B_IMPLEMENTATION: NONE
```

The legacy P9 instrumentation did not target start. The valid v2/v3
provider runs observed the ARMIO allocation phase and client starts
live; no ASCWrap-family vtable appeared. The earliest failed stage
remains UNKNOWN pending ANS DT-name correlation.

