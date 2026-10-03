# 57ZZ Part 14L / 14L-R — External Orchestrator / Data Role Proof

## Verdict (updated by 14L-R)

```
DATA_ROLE_0x40_STATIC_PROOF: PASS
ROLE_WRAPPER_DATAFLOW: PASS
DATA_LIFECYCLE_STATIC_GATE: BLOCKED (external orchestrator only)
```

14L-R resolves the x25/x23 contradiction from the original 14L report. The
wrapper **does** perform the LP-enum → APFS-role-bits conversion internally,
via `+[LPStaticAPFSVolume roleMetadataForRole:]`. The earlier
"unmodified passthrough" claim is **RETRACTED**, and the "no 0x40 constant"
wording is **CORRECTED**.

The remaining blocker is now narrower: only the external orchestrator that
passes LP role=3 for the actual Data invocation.

## 14L-R: The conversion chain (proven)

```
0x1000821f0  mov x25, x3        ; save LP logical role
0x100082588  mov x2, x25        ; lookup key
0x10008258c  bl roleMetadataForRole:   ; +[LPStaticAPFSVolume roleMetadataForRole:]
0x100082594  cbz x0, fail_path  ; nil -> default w23 = 0
0x100082598  ldrh w23, [x0,#4]  ; APFS role bits from metadata entry +4
...            w23 -> numberWithInt: -> dict[kAPFSVolumeRoleKey]
```

## 14L-R: Complete role metadata table

Enumerated by `+[LPStaticAPFSVolume enumerateRoleMetadataUsingBlock:]`
(IMP 0x100084044), 17 entries at table VM 0x1002cb238:

| LP enum | APFS role bits | Name |
|---:|---:|---|
| 0x00 | 0x00000000 | (zero entry) |
| 0x01 | 0x00000001 | System |
| 0x02 | 0x00000002 | User |
| 0x03 | **0x00000040** | **Data** |
| 0x04 | 0x00000004 | Recovery |
| 0x05 | 0x00000008 | VM |
| 0x06 | 0x00000010 | Preboot |
| 0x07 | 0x00000020 | Installer |
| 0x08 | 0x00000080 | Baseband data |
| 0x09 | 0x00000100 | xART |
| 0x0a | 0x00000200 | Internal |
| 0x0b | 0x00000180 | Backup |
| 0x0c | 0x000000c0 | Update |
| 0x0d | 0x00000140 | Hardware |
| 0x0e | 0x000001c0 | SideCar |
| 0x0f | 0x00000240 | Enterprise data |
| 0x10 | 0x00000280 | iDiags |

`mov w23, #0` is the **failure default** when `roleMetadataForRole:` returns
nil for an unknown role — not a "default role".

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
