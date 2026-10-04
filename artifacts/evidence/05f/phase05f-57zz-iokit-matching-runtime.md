# 57ZZ — IOKit Matching Runtime Evidence

## Key correction: prior instrumentation targets invalidated

A whole-binary scan proves that no qword in bootkc.bin references
either start candidate (`0xfffffff0082f4df0` / `0xfffffff0082f804c`)
as a chained-fixup target:

```
candA references: 0
candB references: 0
```

Neither candidate is vtable-dispatched. The prior NO_HIT results on
these addresses therefore do not disprove AppleASCWrapV6 or
AppleA7IOP instantiation.

## Corrected-DT runtime run

The corrected DeviceTree preserves BOTH hierarchy levels:
- `/arm-io/ans` compatible = `iop,ascwrap-v6` (provider identity, required by IONameMatch)
- `/arm-io/ans/iop-ans-nub` compatible = `iop-nub,rtbuddy-v2` (child nub)

The boot completed (37,155 serial bytes) with no new ANS-related
serial output versus the 58A run — but the instrumentation targets
were the invalidated candidates, so no instantiation conclusion can
be drawn from the breakpoint result.

## Verdicts

```
VTABLE_REFERENCE_SCAN_CANDA_CANDB: ZERO_REFERENCES_PROVEN
PRIOR_NO_HIT_DISPROVES_INSTANTIATION: INVALIDATED
APPLEASCWRAPV6_RUNTIME_ENTRY: NOT_OBSERVED
APPLEA7IOP_INSTANTIATION: UNKNOWN
BREAKPOINT_ARMED_BEFORE_TARGET_MATCHING: UNKNOWN
ASCWRAP_CORRECTED_DT_BOOT: COMPLETED_NO_NEW_ANS_SERIAL
MATCHING_STAGE_CLASSIFICATION: UNKNOWN_REQUIRES_VALID_INSTRUMENTATION
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

