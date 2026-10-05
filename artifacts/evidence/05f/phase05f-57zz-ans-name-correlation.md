# 57ZZ — ANS DT Name Correlation

## Method

GDB hardware breakpoints on the AppleARMIODevice allocator and the
callsite-proven +0x360 start dispatch. At each allocator hit, searched
±1MB around the x1 dictionary for 'ans\0' and 'iop,ascwrap'.

## Result

```
ARMIO_ALLOCATION_PHASE_ACTIVE: PROVEN
ANS_STRING_SEARCH_NEGATIVE: PROVEN_IN_SEARCHED_WINDOWS
ANS_DT_ENTRY_CONSUMED: UNKNOWN
ANS_SPECIFIC_ARMIO_ALLOCATION: UNKNOWN (not found in observed subset; search method has structural limits)
MATCHING_STAGE_CLASSIFICATION: UNKNOWN (cannot classify without ANS allocation identity)
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

## Interpretation

Neither 'ans\0' nor 'iop,ascwrap' was found in the searched windows near the observed ARMIO allocator arg1 objects. The v6 run searched ±64KB (55/55 successful searches); the v7 run searched ±1MB (27/27 successful searches). Zero search errors. The semantic role of arg1 is UNKNOWN, so this proves absence in searched memory near arg1 objects only - it does not prove anything about DT property dictionaries specifically. These are separate boots, so the observations may overlap the same DT population; do not sum them as unique allocations. Proximity-based search cannot serve as final identity-correlation proof even if a hit were found.

## Next approaches

1. STATIC: derive caller-of-ARMIO-allocator argument semantics (which arg is IORegistryEntry/OSDictionary/DT node)
2. Instrument the DT plane name accessor (IORegistryEntry::getName / compareName) with an ANS filter
3. Search the kernel OSSymbol table for the interned 'ans' symbol and trace its reference to the owning DT entry
4. Instrument the registerService() path with a provider-name check (ARMIODevice store the name early)

