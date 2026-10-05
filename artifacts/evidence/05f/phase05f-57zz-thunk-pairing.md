# 57ZZ — Runtime Thunk-Allocator Pairing

## Prior run retraction

The v7 capture script's CAND_B was the allocator, not the thunk. The .Replace() used to derive v7 from v3 silently failed. All 'thunk_hits' were actually allocator hits.

## Method

Single hardware breakpoint on thunk entry (0x...87eb0) only.
On each hit: capture x0/x1/x2, then `stepi` twice:
  step 1 reaches thunk+4 (the `b allocator` instruction)
  step 2 reaches allocator entry (0x...87eb8)
Capture allocator x0/x1; prove thunk.x2 == allocator.x1.

## Result

```
THUNK_ENTRY_RUNTIME: PROVEN
CONTROL_FLOW_THUNK_TO_ALLOCATOR: PROVEN_RUNTIME
THUNK_X2_TO_ALLOCATOR_X1_RUNTIME: PROVEN_RUNTIME
RUNTIME_ALLOCATOR_ENTRY_VIA_THUNK: PROVEN_RUNTIME
ALLOCATOR_ARG1_SOURCE_GLOBAL: THUNK_X2 (proven for all 40 observed pairs)
THUNK_X2_SEMANTIC_ROLE: UNKNOWN (next gate: ARMIO_THUNK_X2_PROVENANCE)
FIRST_QEMU_VISIBLE_PRIMITIVE: BLOCKED
ITERATION_58B_ENTRY_GATE: BLOCKED_PROOF_INCOMPLETE
```

```
thunk hits: 40
control flow OK: 40
control flow FAIL: 0
register match: 40
register mismatch: 0
```

