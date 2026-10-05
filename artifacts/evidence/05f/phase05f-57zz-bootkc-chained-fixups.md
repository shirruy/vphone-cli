# 57ZZ — BootKC Chained-Fixup Decoder (format-complete)

```
BOOTKC_CHAIN_FORMAT: PROVEN (pointer format 8)
CHAIN_DECODER_CURRENT_FIXTURE: PASS
MULTI_START_PAGES_OBSERVED: 0
MULTI_PATH_RUNTIME_VALIDATED: NO
CHAIN_WALK_SELF_CONSISTENCY: PASS
total fixups: 532174
cache levels: {'0': 532174, '1': 0, '2': 0, '3': 0}
```

| segment | fmt | pages | single | multi | none | heads | fixups |
|---|---|---|---|---|---|---|---|
| __DATA_CONST | 8 | 352 | 334 | 0 | 18 | 334 | 516451 |
| __DATA_SPTM | 8 | 19 | 0 | 0 | 19 | 0 | 0 |
| __DATA | 8 | 152 | 52 | 0 | 100 | 52 | 15723 |

## Validation

- PASS ASCWrap GOT superclass -> AppleA7IOP class object: 0xfffffff00afed5c0
- PASS ASCWrap mod_init[1] (AppleASCWrapV6 registration): 0xfffffff0082f42b4
- PASS ASCWrap mod_init[2] (AppleASCWrapV6SEP registration): 0xfffffff0082f4800
- PASS A7IOP mod_init[0] chain entry: 0xfffffff0082f7798

candA references (valid decoder): 0
candB references (valid decoder): 0

