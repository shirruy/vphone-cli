# 57ZZ — Runtime Thunk-Allocator Pairing

```
THUNK_ENTRY_RUNTIME: PROVEN (39 hits observed)
ALLOCATOR_ENTRY_RUNTIME: NOT_OBSERVED (breakpoint conflict suspected; 8-byte gap)
THUNK_X2_DISTINCT_PER_DEVICE: PROVEN (39 distinct values)
X1_EQ_X2_AT_THUNK_ENTRY: PROVEN (39/39)
RUNTIME_ALLOCATOR_ENTRY_VIA_THUNK: SUPPORTED (thunk hit + static mov x1,x2 + branch to allocator; but allocator bp not observed so pairing not directly confirmed)
RUNTIME_ALLOCATOR_ENTRY_VIA_THUNK_STRICT: UNKNOWN (requires allocator bp hit or single-bp thunk-only run)
THUNK_X2_SEMANTIC_ROLE: UNKNOWN (next gate: trace x2 producer)
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

39 thunk entry hits observed (bp at 0x...87eb0), 0 allocator entry hits (bp at 0x...87eb8). The 8-byte gap between the two hardware breakpoints likely caused a conflict in the QEMU gdbstub's limited hardware debug registers, preventing the allocator breakpoint from triggering. However, at every thunk hit x1 already equals x2 (39/39), consistent with the statically proven 'mov x1, x2' thunk instruction being either a no-op (caller already set x1==x2) or the values having been synchronized by a prior mechanism. The x2 values are distinct across hits (distinct per-device objects). The 60-event cap truncated the capture.

