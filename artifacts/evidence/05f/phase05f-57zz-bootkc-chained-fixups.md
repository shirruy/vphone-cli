# 57ZZ — BootKC Chained-Fixup Decoder

```
BOOTKC_CHAIN_FORMAT: PROVEN (pointer_format 8 where chained)
CHAIN_WALK_SELF_CONSISTENCY: PASS
total chain-walked fixups: 532174
```

## Validation against known pointers

- PASS ASCWrap GOT superclass -> AppleA7IOP class object: 0xfffffff00afed5c0 (expected 0xfffffff00afed5c0)
- PASS ASCWrap mod_init[1] (AppleASCWrapV6 registration): 0xfffffff0082f42b4 (expected 0xfffffff0082f42b4)
- PASS ASCWrap mod_init[2] (AppleASCWrapV6SEP registration): 0xfffffff0082f4800 (expected 0xfffffff0082f4800)
- PASS A7IOP mod_init[0] chain entry: 0xfffffff0082f7798 (expected 0xfffffff0082f7798)

## Candidate references (real chain decode)

- candA `0xfffffff0082f4df0`: 0 reference(s)
- candB `0xfffffff0082f804c`: 0 reference(s)

