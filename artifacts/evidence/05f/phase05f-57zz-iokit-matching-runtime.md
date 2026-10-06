# 57ZZ — IOKit Matching Runtime Evidence

## Key correction: prior instrumentation targets invalidated

RETRACTED: the prior scan masked raw qwords to 30 bits and compared
them directly to file offsets. That is not the
DYLD_CHAINED_PTR_64_KERNEL_CACHE resolution semantics; the real
resolution is basePointers[cacheLevel] + target. The scan result is:

```
VTABLE_REFERENCE_SCAN_CANDA_CANDB: INVALID_DECODER_ASSUMPTION
CANDA_VTABLE_DISPATCH_STATUS: UNKNOWN
CANDB_VTABLE_DISPATCH_STATUS: UNKNOWN
```

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
VTABLE_REFERENCE_SCAN_CANDA_CANDB: INVALID_DECODER_ASSUMPTION
CANDA_VTABLE_DISPATCH_STATUS: UNKNOWN
CANDB_VTABLE_DISPATCH_STATUS: UNKNOWN
PRIOR_NO_HIT_DISPROVES_INSTANTIATION: UNKNOWN
APPLEASCWRAPV6_RUNTIME_ENTRY: NOT_OBSERVED
APPLEA7IOP_INSTANTIATION: UNKNOWN
BREAKPOINT_ARMED_BEFORE_TARGET_MATCHING: UNKNOWN
ASCWRAP_CORRECTED_DT_BOOT: COMPLETED_NO_NEW_ANS_SERIAL
MATCHING_STAGE_CLASSIFICATION: UNKNOWN_REQUIRES_VALID_INSTRUMENTATION
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

