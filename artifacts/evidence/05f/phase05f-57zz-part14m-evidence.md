# 57ZZ Part 14M — CreateForMSU Audit

## Verdict

```
CREATEFORMSU_STATIC_AUDIT: PASS
CLASSIFICATION: CREATEFORMSU_SPECIALIZED_MSU_VOLUME_PATH
```

## 14M-A: Symbol/reference discovery

| Binary | Reference | Type |
|---|---|---|
| APFS_framework.bin | `_APFSVolumeCreateForMSU` @ 0x2b824 | exported symbol (stub) |
| asr.bin | `_APFSVolumeCreateForMSU` (linkedit strings) | import only |
| restored_external.bin | `_APFSVolumeCreateForMSU` import ordinal 122, stub 0x1001bc520 | import |

## 14M-B/C: Caller + ABI

Exactly ONE caller in restored_external.bin:

```
0x1000829c0  bl _APFSVolumeCreateForMSU   (inside the addVolume wrapper)
```

Register state:

```
x0 = x21 = container (after fileSystemRepresentation)
x1 = x28 = the SAME CFDictionary used by the normal path
```

ABI: `_APFSVolumeCreateForMSU(x0=container, x1=options CFDictionary)` —
identical shape to `_APFSVolumeCreate`.

## 14M-D: Created volume role

The wrapper takes the MSU branch only when:

```
0x100082928 ldr x8, [auth_ptr 0x1002ef518]  ; _APFSVolumeCreateForMSU fn ptr
0x100082930 cbz x8, skip                     ; API must be available
0x100082934 cmp w25, #1                      ; LP role == 1
0x100082938 b.ne skip                        ; non-System -> normal path
```

**CreateForMSU is exclusively the System-volume (LP role 1 → APFS 0x01)
creation path.** It is not used for Data, Preboot, or any other role.

## 14M-E: Options/dictionary comparison

| Property | Normal `_APFSVolumeCreate` | `_APFSVolumeCreateForMSU` |
|---|---|---|
| Name | same dict | same dict |
| Role | same dict | same dict |
| Case sensitivity | same dict | same dict |
| Reserve | same dict | same dict |
| Quota | same dict | same dict |
| GroupSiblingFSIndex | same dict | same dict |
| Encryption | ABSENT | ABSENT |
| Keybag | ABSENT | ABSENT |
| Seal input | ABSENT | ABSENT |
| Snapshot input | ABSENT | ABSENT |

Both calls receive the **same x28 dictionary** constructed by the wrapper;
the dictionary construction is not role- or path-dependent.

## 14M-F/G: Crypto / seal evidence

### Framework-side stub

```
_APFSVolumeCreateForMSU @ 0x2b824:
    mov w0, #0x2d
    ret
```

In THIS firmware build the exported `_APFSVolumeCreateForMSU` is a
2-instruction stub returning error `0x2d`. The specialized path cannot
succeed through this export.

### Internal OTI helper

The adjacent internal function (`__APFSVolumeOtiRequestHelper` @ 0x2b8c4,
reached from the pre-stub wrapper at 0x2b82c with `w5=2`) builds a
0x4c8-byte request and issues internal calls (0xcac / 0x6da6c); request
types 1 and 4 output a volume handle. This is the OTI (one-time-index)
machinery, but it is **not reachable** through the exported stub in this
build.

### Restore-side

No encryption/keybag property is added by the CreateForMSU path. No seal or
snapshot operation is invoked by the CreateForMSU path in
restored_external.bin. No fallback from MSU failure to normal create exists
at the wrapper level: the MSU result is returned directly.

## 14M-J: Why two paths exist

CreateForMSU is the specialized MSU (sealed System) creation entry, gated
on API availability and restricted to LP role 1. On this firmware build the
export is stubbed to `0x2d`, so the specialized path cannot execute
successfully; the normal `_APFSVolumeCreate` path (taken when the API
pointer is null or the role is not System) is the functional path.

## Negative evidence (scoped)

- No encryption dictionary key found within the wrapper's dictionary
  construction in restored_external.bin.
- No keybag/crypto-user construction edge found within the wrapper or the
  single MSU callsite.
- No seal/snapshot/bless call found within the MSU branch of the wrapper.
- No fallback from CreateForMSU failure to normal create found within the
  wrapper.
- No Data-role usage of CreateForMSU found anywhere in restored_external
  (the `cmp w25,#1` gate excludes it).
