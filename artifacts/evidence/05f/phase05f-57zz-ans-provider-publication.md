# 57ZZ — ANS AppleARMIODevice Provider Publication

## Instrumentation

- AppleARMIODevice allocator: `0xfffffff008387eb8` (both args forwarded to init; DT-registry arg role UNKNOWN pending caller trace)
- IOService start dispatch: `0xfffffff00aada0e0` (+0x360 slot, callsite-proven)
- 3s warmup; slide 0x20000000; canonical ascwrap DT

## Findings

```
ANS_DT_ENTRY_CONSUMED: UNKNOWN
APPLEARMIODEVICE_ALLOCATED: PROVEN_FOR_OTHER_NODES (>=55 observed; ANS-specific not identified)
APPLEARMIODEVICE_INITIALIZED: UNKNOWN
PROVIDER_ATTACHED: UNKNOWN
PROVIDER_PUBLICATION_RESULT: PARTIAL: allocation + start phases observed; no ASCWrap-family start; ANS-specific identity unconfirmed
MATCHING_STAGE_CLASSIFICATION: UNKNOWN_REQUIRES_ANS_NAME_CORRELATION
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

The ARMIO allocation phase and the IOKit start dispatch phase were
both observed live from breakpoint arm time. No AppleASCWrapV6/
AppleA7IOP/A7IOPNub vtable appeared in any observed client start.
The ANS-specific allocation cannot yet be identified among the ARMIO
allocations because the DT dictionary name is not exposed in the
current capture; that name correlation is the exact next blocker.

