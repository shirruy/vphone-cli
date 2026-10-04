# 57ZZ — ASCWrap/A7IOP Vtables

Vtable contents are chain-decoder derived; vtable base addresses are
known anchors until independently rederived.

```
START_VTABLE_SLOT_SEMANTIC_IDENTITY: UNPROVEN
START_SLOT_0x348: CANDIDATE_SUPPORTED_BY_VTABLE_CORRELATION
```

| Class | Vtable VM | +0x348 target | Owner | Classification |
|---|---|---|---|---|
| AppleA7IOP | 0xfffffff007d14370 | 0xfffffff00aad8190 | kernel | OVERRIDES_START |
| AppleASCWrapV6 | 0xfffffff007d131e0 | 0xfffffff0082f4dec | a7iop | OVERRIDES_START |
| AppleASCWrapV6SEP | 0xfffffff007d139b8 | 0xfffffff00aac8d44 | kernel | OVERRIDES_START |
| AppleASCWrapV6SISP | 0xfffffff007d12a08 | 0xfffffff0082f4dec | a7iop | OVERRIDES_START |
| AppleA7IOPNub | 0xfffffff007d14960 | 0xfffffff0082f8048 | a7iop | OVERRIDES_START |

## Candidate relationship

candA is the function body 4 bytes after the AppleASCWrapV6/A7IOP start landing pad (%s); candB is the body 4 bytes after the AppleA7IOPNub start pad (%s). Neither is the direct vtable target, but both lie on the entry path.

The +0x2c0 slot resolves to the same shared kernel function in every
derived vtable — it is not the start slot. The prior SUPER_START_CHAIN
claim at +0x2c0 is invalidated.

