# 57ZZ Part 14M — CreateForMSU Audit

## Verdict

```
CREATEFORMSU_STATIC_AUDIT: PASS
CLASSIFICATION: CREATEFORMSU_SYSTEM_ONLY_STUBBED_PATH
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

## 14M-R: Post-call behavior (correction pass)

The wrapper's post-call region converges both paths at `0x1000829dc`:

```
0x1000829dc  mov x25, x0         ; result (integer status)
0x1000829e0  cbz w0, 0x100082b30 ; 0 = success -> fsindex post-processing
```

Since the implementation in this build always returns `0x2d`, the MSU call
always takes the error path:

```
0x1000829e4  cbz x22, skip-error-object
0x1000829fc  sxtw x3, w25       ; integer status -> NSError
0x100082a14  str x0, [x22]      ; error out-param
0x100082a84  stur w25, [x0,#0xe]; status value in log record
0x100082aa0  mov x24, #0        ; nil result
0x100082aa4  b 0x10008242c      ; release + return
```

**Fallback to `_APFSVolumeCreate`: PROVEN_ABSENT.**
No branch in the post-call region targets the normal-create block
(`0x1000829c8..0x1000829dc`). Directional BFS from `0x1000829c0` shows all
failure edges terminate at the release/error-record paths returning nil.

**Error semantics:** nonzero = error int, zero = success (then fsindex
post-processing). `0x2d` symbolic meaning: UNKNOWN (no error table or
strerror mapping found in the analyzed artifacts).

## 14M-R5: Import binding

Import ordinal 122 (`_APFSVolumeCreateForMSU`) has `weak_import = 1`
(raw import entry bit 8). `_APFSVolumeCreate` (ordinal 121) has
`weak_import = 0`. Therefore the `cbz x8` after the auth_ptr load is a
genuine weak-import availability check.

```
CREATEFORMSU_IMPORT: WEAK
```

## 14M-R7: OTI reachability (correction)

The adjacent function at `0x2b82c` is a named sibling API —
`_APFSVolumeSetOtiLockerData` (exported, N_EXT) — not a CreateForMSU
preamble. The 6 exported OtiLocker APIs tail-branch into the internal
`__APFSVolumeOtiRequestHelper`
(`0x2b8c4`, N_EXT=False). `_APFSVolumeCreateForMSU` (`0x2b824`) is a
separate 2-instruction stub with an immediate ret and **no CFG edge** to
the helper. No caller of `0x2b824` or `0x2b82c` exists within
APFS.framework text.

```
CREATEFORMSU_TO_OTI_EDGE: PROVEN_ABSENT
```

OTI is removed from the CreateForMSU architectural chain.

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

### Adjacent OtiLocker subsystem (separate from CreateForMSU)

The adjacent OtiLocker subsystem is independently present in
APFS.framework: `_APFSVolumeSetOtiLockerData` (@ 0x2b82c) and five sibling
exports tail-branch into the internal `__APFSVolumeOtiRequestHelper`
(@ 0x2b8c4, N_EXT=False), which builds a 0x4c8-byte request and issues
internal calls (0xcac / 0x6da6c). No executable control-flow edge from
`_APFSVolumeCreateForMSU` (@ 0x2b824) to this helper was found. It is
therefore excluded from the CreateForMSU architectural chain.

### Restore-side

No encryption/keybag property is added by the CreateForMSU path. No seal or
snapshot operation is invoked by the CreateForMSU path in
restored_external.bin. No fallback from MSU failure to normal create exists
at the wrapper level: the MSU result is returned directly.

## 14M-J: Observed normal-vs-MSU path distinction

The wrapper contains two creation call paths:

- The normal path invokes `_APFSVolumeCreate`.
- The optional System-only path invokes the weakly imported
  `_APFSVolumeCreateForMSU` when that API is available and LP role == 1.

Both receive the same creation dictionary. In the analyzed APFS.framework
build, the CreateForMSU export is stubbed and cannot succeed. The design
motive for the split is not proven and is not claimed here.

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

## 57ZZ PART 14M CANONICAL STATUS

```
CreateForMSU:
  _APFSVolumeCreateForMSU @ 0x2b824

Analyzed implementation:
  mov w0, #0x2d
  ret

Import:
  WEAK

Role eligibility:
  LP role 1 / System only

Caller-side dictionary:
  Same dictionary as normal _APFSVolumeCreate path

Return contract:
  0 = success path
  nonzero = error path

0x2d symbolic meaning:
  UNKNOWN

Fallback to normal create:
  PROVEN ABSENT

CreateForMSU -> OTI edge:
  PROVEN ABSENT

Additional caller-side encryption/keybag input:
  PROVEN ABSENT

Seal/snapshot behavior through analyzed export:
  PROVEN ABSENT IN THIS BUILD

Classification:
  CREATEFORMSU_SYSTEM_ONLY_STUBBED_PATH

CREATEFORMSU_STATIC_AUDIT:
  PASS

DATA_ROLE_MAPPING:
  PASS

DATA_INVOCATION_ROLE3_PROOF:
  BLOCKED_EXTERNAL_BOUNDARY

DATA_LIFECYCLE_STATIC_GATE:
  BLOCKED_EXTERNAL_BOUNDARY

RUNTIME_MOUNT_IDENTITY:
  DEFERRED
```

PART14M_CANONICAL_EVIDENCE_INTEGRITY: PASS
