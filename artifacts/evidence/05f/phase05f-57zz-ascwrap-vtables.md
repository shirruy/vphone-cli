# 57ZZ — ASCWrap/A7IOP Vtables (Chain Decoder Derived)

```
ASCWRAP_START_VTABLE_SLOT: PROVEN (+0x348)
```

| Class | Vtable VM | +0x348 target | Owner | Classification |
|---|---|---|---|---|
| AppleA7IOP | 0xfffffff007d14370 | 0xfffffff00aad7da0 | kernel | OVERRIDES_START |
| AppleASCWrapV6 | 0xfffffff007d131e0 | 0xfffffff00aad7da0 | kernel | OVERRIDES_START |
| AppleASCWrapV6SEP | 0xfffffff007d139b8 | 0xfffffff00aac8a4c | kernel | OVERRIDES_START |
| AppleASCWrapV6SISP | 0xfffffff007d12a08 | 0xfffffff00aad7da0 | kernel | OVERRIDES_START |
| AppleA7IOPNub | 0xfffffff007d14960 | 0xfffffff00aad7da0 | kernel | OVERRIDES_START |

## Candidate relationship

candA (%s pad) and candB (%s pad) sit at vtable slot +0x348, which the proven start dispatch proves is NOT start (start is +0x360). The semantic identity of +0x348 is UNKNOWN; prior breakpoints there were never start instrumentation.

The +0x2c0 slot resolves to the same shared kernel function in every
derived vtable — it is not the start slot. The prior SUPER_START_CHAIN
claim at +0x2c0 is invalidated.

