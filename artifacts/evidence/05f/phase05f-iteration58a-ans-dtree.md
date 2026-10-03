# Iteration 58A — Opt-in ANS-compatible DeviceTree preservation

## Verdict

```
ITERATION_58A: PASS
DEFAULT_DT_FIXUP_REGRESSION: PASS
BOOTED_ANS_COMPATIBLE_RESTORE: PASS
```

58A proves payload preparation only. No RTBuddy attach, ANS3 probe, MMIO,
namespace publication, or storage functionality is claimed from the
modified DeviceTree alone.

## Source / provenance

| Item | Value |
|---|---|
| Upstream repo | https://github.com/jprx/darwin-vm.git |
| Source commit | ffdf018 |
| Target file | dt_fixup.py |
| Durable patch | windows/patches/darwin-vm/phase05f-iteration58a-ans-dtree.patch |
| Patch SHA256 | C543522A94042FA352C3D892789DC80D98C7CE42CF1CB14429CB2438048A8646 |
| Metadata | windows/patches/darwin-vm/phase05f-iteration58a-ans-dtree.json |

## Change semantics

`del_compat()` now accepts `preserve_ans_compat`. When enabled and the node
is the `iop-ans-nub` child, the exact compatible value
`iop-nub,rtbuddy-v2` is preserved. The new CLI flag
`--preserve-ans-compatible` is strictly opt-in; default behavior is
unchanged.

The preservation is scoped by node name (`iop-ans-nub`) — sibling
`iop-*-nub` children (ane, aop, dcp, dcpext, gfx-asc, mtp, pmp, sio, smc)
continue to have their compatible properties pruned even in ANS-enabled
mode.

## Verification (both modes)

### Default regression

```
default output SHA256: 9E84C9ADD25B99EDDD8B088B249E7CE348394B80A0DEF59949E9BB9C63A24E1B
baseline SHA256:       9E84C9ADD25B99EDDD8B088B249E7CE348394B80A0DEF59949E9BB9C63A24E1B
DEFAULT_DT_FIXUP_REGRESSION: PASS (byte-identical)
```

### ANS-enabled structural proof

```
ans output SHA256:     9F87087F4A147922C2327950E8E77EFBF958765820A86C679549F43F1D7FF8E9
iop-ans-nub compatible: iop-nub,rtbuddy-v2
ans role:               ANS2
semantic diff count:    1
the one diff:           /arm-io/ans/iop-ans-nub/compatible
```

Exactly ONE intended compatible property restored. No broad compatible
restoration. Namespace records, ANS reg, interrupts, AIC compatibility all
unchanged (they participate in no diff).

## Not claimed by 58A

- RTBuddy attach
- RTBuddyService attach
- AppleANS3 probe/start
- ANS MMIO functionality
- namespace publication
- storage functionality

Those belong to later slices (58B+).

## Canonical status

```
ITERATION_58A_ENTRY_GATE:      CLOSED_PASS
ITERATION_58B_PLUS_ENTRY_GATE: BLOCKED
ANS_STORAGE_IMPLEMENTATION_READINESS: BLOCKED_FOR_58B_PLUS

Next: 57ZZ Part 15B / Iteration 58B Entry Analysis
```
