# 57ZZ — ARMIO Thunk x2 Provenance

## Key Finding

All 40 thunk x2 objects share vtable `0xfffffff007cc90f8`.
Its `+0x40` slot resolves to `0xfffffff00aa4e744` (IOService::start base).

The x2 objects are IOService-family objects - likely the DT-derived
service entries that the platform expert passes to the ARMIODevice
allocator. They are NOT ARMIODevice instances (different vtable).

No 'ans' string found inline in the x2 objects. The name property
is likely stored as a separate OSString object, not inline.

## Verdicts

```
X2_OBJECT_FAMILY: IOService-family (vtable +0x40 == IOService::start)
X2_SPECIFIC_CLASS: UNKNOWN (vtable 0xfffffff007cc90f8 not in known map)
X2_IS_ARMIODevice_INSTANCE: NO (ARMIODevice vtable is 0xfffffff007d336e0, different)
X2_IS_DT_DERIVED_SERVICE: SUPPORTED (IOService-family vtable + allocator context)
ANS_SPECIFIC_ALLOCATION: UNKNOWN (no 'ans' string found in x2 objects; name may not be inline)
THUNK_X2_SEMANTIC_ROLE: LIKELY_DT_DERIVED_SERVICE_ENTRY (IOService-family object passed to ARMIODevice allocator as the source/registry object)
NEXT_APPROACH: The x2 objects are IOService-family but their names are not inline strings. Next: instrument IORegistryEntry::getName or compareName at runtime with the specific x2 pointers as 'this' to extract names.
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

