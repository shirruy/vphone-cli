# 57ZZ — ASCWrap Runtime Matching (Valid Instrumentation)

## Setup

- Canonical ascwrap DT fixture (parent `iop,ascwrap-v6` + child `iop-nub,rtbuddy-v2`)
- Hardware breakpoints on the chain-decoder-derived vtable +0x348 entries
  (`0xfffffff0082f4dec`, `0xfffffff0082f8048`) and the nub factory (`0xfffffff0082f7b40`)
- 8s warmup; slide 0x20000000; full boot in window

## Timing gate

```
BREAKPOINT_ARMED_BEFORE_TARGET_MATCHING: PROVEN_FOR_OBSERVED_MATCHING_PHASE
```

Breakpoints were armed at ~8.03s wall-clock. The kernel IOKit matching phase (CoreAnalyticsHub/OLYHAL/Backlight starts, kernel timestamps [00:00:20+] = ~17-22s wall) occurred entirely within the instrumented window. The boot reached idle within the window (first watchdog stop at 30s GDB-time showed the idle-loop PC). T2 < T3 is proven for the observed matching phase.

## Result

```
GENERIC_IOKIT_ACTIVITY_AFTER_BREAKPOINT_ARMING: PROVEN
BREAKPOINT_ARMED_BEFORE_ARMIO_ALLOCATION_PHASE: PROVEN (3s warmup; allocations observed from t=0.057)
BREAKPOINT_ARMED_BEFORE_ANS_PROVIDER_MATCHING: UNKNOWN (ANS-specific alloc not yet identified among ARMIO allocations)
ARMIO_ALLOCATIONS_OBSERVED: >= 55
IOKIT_START_DISPATCHES_OBSERVED: >= 40
ASCWRAP_FAMILY_START_OBSERVED: False
APPLEASCWRAPV6_START_HIT: NO
APPLEA7IOPNUB_START_HIT: NO
MATCHING_STAGE_CLASSIFICATION: UNKNOWN_REQUIRES_PROVIDER_PUBLICATION_INSTRUMENTATION
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
58B_IMPLEMENTATION: NONE
```

All three instrumented entries remained unhit across the full boot,
while other drivers' start calls were observed in serial — proving the
matching pipeline was active in the window. The earliest failed stage
cannot be classified without provider-publication instrumentation
(AppleARMIODevice nub creation/registerService for /arm-io/ans).

