# 57ZZ Part 14L — External Orchestrator / Data Role Proof

## Verdict

```
DATA_ROLE_0x40_STATIC_PROOF_BLOCKED
```

The static dataflow chain from an external orchestrator through
`LPStaticAPFSContainer addVolumeWithName:role:...` to a proven
`role = 0x40` invocation cannot be completed with the currently extracted
binaries. Per the fail-closed rules, the gate is **BLOCKED**, not "probably
Data".

## 1. Binaries searched

Every binary under the 57ZZ workspace was searched for the exact selector:

| Binary | Selector present |
|---|---|
| APFS_framework.bin | no |
| apfs_iosd.bin | no |
| apfs_sealvolume.bin | no |
| apfs_vol_converter.bin | no |
| asr.bin | no |
| fsck_apfs.bin | no |
| mount_apfs.bin | no |
| newfs_apfs.bin | no |
| restored_external.bin | **yes** (0x1cb0e1) |
| slurpAPFSMeta.bin | no |

The selector has exactly one selref in `restored_external.bin`
(`0x1002f5860`) and zero in-binary code users (verified by full `__text`
ADRP+LDR scan, clearing tracking at every BL).

## 2. Exact caller function / address

Known wrapper (from 14I–14K):

```
IMP: 0x1000821bc (LPStaticAPFSContainer addVolumeWithName:role:...)
BL _APFSVolumeCreate: 0x1000829d8
```

The caller of this IMP is **outside** the extracted binaries.

## 3. Register / dataflow reconstruction

### Role parameter (w3 at IMP entry)

```
0x1000821f0  mov x25, x3          ; save role
...
0x1000824ac  cmp w25, #1          ; System branch
...
0x100082680  adrp x8, [RoleKey slot]
0x100082688  mov x2, x23          ; role value
0x10008268c  bl numberWithInt:
0x1000826b0  setObject:forKey:    ; dict[RoleKey] = @(role)
```

### pairedVolume (x5 at IMP entry)

```
0x1000821e8  mov x27, x5          ; save pairedVolume
...
0x1000827c4  adrp x26, [GroupSiblingFSIndex slot]
0x10008282c  bl intValue
0x100082848  bl numberWithInt:
0x100082864  setObject:forKey:    ; dict[GroupSiblingFSIndexKey] = @(intValue)
```

## 4. Role encoding finding

The wrapper compares the role against a **logical enum** (`cmp w25, #1` =
System branch), not APFS numeric role bits. No `0x40` constant appears in
the wrapper's role dataflow. The conversion from this enum (or from the
`--role=%s` string consumed by newfs_apfs) to APFS numeric role bits
happens downstream, outside the currently proven chain.

`newfs_apfs` contains no role-name strings and no direct `0x40` role
constant; its `role=%s` handling stores the raw string for conversion
elsewhere.

## 5. Proof of role=0x40

**Not established.** No executable dataflow chain in restored_external,
APFS_framework, newfs_apfs, or mount_apfs links a Data invocation to
numeric role 0x40.

## 6. pairedVolume source

Proven only at the wrapper boundary: `pairedVolume -> intValue ->
kAPFSVolumeGroupSiblingFSIndexKey`. The actual DATA-invocation value is
supplied by the missing external orchestrator.

## 7. Control-flow condition

`cmp w25, #1` selects the System creation path; non-1 values take the
other path. The DATA-specific condition and the sibling pairing decision
are made upstream in the missing orchestrator.

## 8. Unresolved items

1. External orchestrator binary (restored host-side / LogicalPlatform
   framework / XPC service) that invokes `addVolumeWithName:role:...`.
2. Role-enum-to-APFS-bits conversion site (inside APFS.framework or the
   kernel) downstream of the wrapper.
3. DATA invocation's pairedVolume value at runtime.

## 9. Final verdict

```
DATA_LIFECYCLE_STATIC_GATE: BLOCKED
```

Remaining blockers:

1. External orchestrator binary/interface that supplies the DATA role value.
2. Downstream role-bits conversion proof linking this path to 0x40.
