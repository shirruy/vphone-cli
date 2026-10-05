# 57ZZ — ANS DT Name Correlation

## Method

GDB hardware breakpoints on the AppleARMIODevice allocator and the
callsite-proven +0x360 start dispatch. At each allocator hit, searched
±1MB around the x1 dictionary for 'ans\0' and 'iop,ascwrap'.

## Result

```
ARMIO_ALLOCATION_PHASE_ACTIVE: PROVEN
ANS_STRING_SEARCH_NEGATIVE: PROVEN (no hits in ±1MB of observed dicts)
ANS_DT_ENTRY_CONSUMED: UNKNOWN
ANS_SPECIFIC_ARMIO_ALLOCATION: UNKNOWN (not found in observed subset; search method has structural limits)
MATCHING_STAGE_CLASSIFICATION: UNKNOWN (cannot classify without ANS allocation identity)
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

## Interpretation

Neither 'ans\0' nor 'iop,ascwrap' was found within ±1MB of any observed ARMIO allocator dictionary. Three hypotheses remain: (a) the ANS DT node's allocation was outside the truncated capture window; (b) DT entry name strings are stored in a different kernel heap zone than the property dictionaries; (c) the property dictionary passed at allocation time does not contain the DT name property at all (the name is set later or via a different path). This does NOT prove the ANS node was not allocated.

## Next approaches

1. Un-truncated allocator-only run (remove the 60-event cap; capture all ~102 DT allocations, search each)
2. Instrument the DT plane name accessor (IORegistryEntry::getName / compareName) with an ANS filter
3. Search the kernel OSSymbol table for the interned 'ans' symbol and trace its reference to the owning DT entry
4. Instrument the registerService() path with a provider-name check (ARMIODevice store the name early)

