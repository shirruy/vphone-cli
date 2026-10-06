# 57ZZ — ASCWrap/A7IOP Vtables

Vtable contents are chain-decoder derived; vtable bases are derived
from mod_init instruction sequences and asserted.

```
IOSERVICE_START_VTABLE_SLOT: PROVEN_FROM_CALLSITE (+0x360)
```

| Class | Vtable VM | +0x360 start target | Superclass target | Classification |
|---|---|---|---|---|
| AppleA7IOP | 0xfffffff007d14370 | 0xfffffff00aad7da0 | 0xfffffff008300420 | OVERRIDES_START |
| AppleASCWrapV6 | 0xfffffff007d131e0 | 0xfffffff00aad7da0 | 0xfffffff00aad7da0 | INHERITS_START |
| AppleASCWrapV6SEP | 0xfffffff007d139b8 | 0xfffffff00aac8a4c | 0xfffffff00aad7da0 | OVERRIDES_START |
| AppleASCWrapV6SISP | 0xfffffff007d12a08 | 0xfffffff00aad7da0 | 0xfffffff00aad7da0 | INHERITS_START |
| AppleA7IOPNub | 0xfffffff007d14960 | 0xfffffff00aad7da0 | 0xfffffff00aad7da0 | INHERITS_START |

## Candidate relationship

candA (0xfffffff0082f4dec pad) and candB (0xfffffff0082f8048 pad) are vtable slot +0x348 targets. The proven start slot is +0x360; +0x348 is NOT start and its semantic identity is UNKNOWN. Prior breakpoints at the +4 function bodies were never start instrumentation.

The start slot is +0x360 (callsite-proven). Slot +0x2c0 resolves to a
shared kernel function in every derived vtable; both the prior
+0x2c0 SUPER_START claim and the later +0x348 hypothesis are
invalidated.

