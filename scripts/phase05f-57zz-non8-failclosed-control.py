#!/usr/bin/env python3
"""57ZZ closure proof: non-8 pointer-format fail-closed positive control.

Creates a synthetic copy of the BootKC with exactly one chained segment's
pointer_format changed from 8 to 2 (DYLD_CHAINED_PTR_64), runs the
reporting decoder against it, and proves fixture_complete = FAIL with an
UNSUPPORTED_POINTER_FORMAT error. Then proves the untouched canonical
fixture still returns PASS. Production evidence is never modified.
"""

import hashlib
import importlib.util as ilu
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
DECODER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase05f-57zz-bootkc-chain-decoder.py")
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-non8-failclosed-positive-control.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-non8-failclosed-positive-control.md"


def find_format_offset(data, seg_index=2):
    """Locate the pointer_format field for one starts-table segment."""
    fixoff = None
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from("<II", data, off)
        if cmd == 0x80000034:
            fixoff, fixsize = struct.unpack_from("<II", data, off + 8)
        off += csz
    chain = data[fixoff : fixoff + fixsize]
    starts_offset = struct.unpack_from("<I", chain, 4)[0]
    seg_count = struct.unpack_from("<I", chain, starts_offset)[0]
    offs = struct.unpack_from("<%dI" % seg_count, chain, starts_offset + 4)
    # __DATA_CONST is index 2
    base = starts_offset + offs[seg_index]
    # struct: size(u32) page_size(u16) pointer_format(u16)...
    format_field_offset = fixoff + base + 6  # after size(4) + page_size(2)
    return format_field_offset


def run_decoder(bootkc_path, out_json, out_md):
    """Run the reporting decoder against a specific bootkc path."""
    # temporarily point the decoder at the alternate file via env
    env = dict(os.environ)
    # The decoder hardcodes BOOTKC; create a wrapper that patches it
    wrapper = out_json.replace(".json", "-wrapper.py")
    src = open(DECODER, "r", encoding="utf-8-sig").read()
    # The decoder resolves fixup-index.py relative to its own file location;
    # rewrite that path to the real scripts dir since the wrapper runs from temp.
    scripts_dir = os.path.dirname(os.path.abspath(DECODER))
    src = src.replace(
        '_fixup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")',
        '_fixup_path = os.path.join(r"%s", "phase05f-57zz-fixup-index.py")' % scripts_dir,
    )
    src = src.replace(
        'BOOTKC = r"C:\\Users\\rbjos\\vphone-private\\phase05f-known-good\\payloads-v3\\bootkc.bin"',
        'BOOTKC = r"%s"' % bootkc_path,
    )
    src = src.replace(
        'OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.json"',
        'OUT_JSON = r"%s"' % out_json,
    )
    src = src.replace(
        'OUT_MD = "artifacts/evidence/05f/phase05f-57zz-bootkc-chained-fixups.md"',
        'OUT_MD = r"%s"' % out_md,
    )
    with open(wrapper, "w", encoding="utf-8") as f:
        f.write(src)
    result = subprocess.run(
        [sys.executable, wrapper], capture_output=True, text=True, env=env, cwd=os.getcwd()
    )
    os.unlink(wrapper)
    return result


def main():
    canonical = open(BOOTKC, "rb").read()
    canonical_sha = hashlib.sha256(canonical).hexdigest().upper()

    # --- synthetic: flip __DATA_CONST pointer_format 8 -> 2 ---
    tmpdir = tempfile.mkdtemp(prefix="phase05f-non8-")
    synthetic_path = os.path.join(tmpdir, "bootkc-non8.bin")
    data = bytearray(canonical)
    fmt_off = find_format_offset(bytes(data), seg_index=2)
    original_format = struct.unpack_from("<H", data, fmt_off)[0]
    assert original_format == 8, "expected format 8, got %d" % original_format
    struct.pack_into("<H", data, fmt_off, 2)  # DYLD_CHAINED_PTR_64
    synthetic_sha = hashlib.sha256(bytes(data)).hexdigest().upper()
    with open(synthetic_path, "wb") as f:
        f.write(bytes(data))

    # --- direct shared-decoder synthetic test ---
    # Prove the shared build_fixup_index itself receives and rejects the
    # synthetic BootKC (not just the reporting layer's metadata check).
    fixup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase05f-57zz-fixup-index.py")
    spec = ilu.spec_from_file_location("fixidx_test", fixup_path)
    fixidx = ilu.module_from_spec(spec)
    spec.loader.exec_module(fixidx)
    shared_decoder_rejected = False
    shared_decoder_error = None
    try:
        fixidx.build_fixup_index(path=synthetic_path)
    except SystemExit as e:
        shared_decoder_rejected = True
        shared_decoder_error = str(e)

    # --- run decoder on synthetic ---
    syn_out = os.path.join(tmpdir, "syn-result.json")
    syn_md = os.path.join(tmpdir, "syn-result.md")
    syn_result = run_decoder(synthetic_path, syn_out, syn_md)
    syn_artifact = json.load(open(syn_out, encoding="utf-8-sig")) if os.path.exists(syn_out) else None

    has_unsupported = False
    fixture_fail = False
    if syn_artifact:
        for seg in syn_artifact.get("segments", []):
            if "UNSUPPORTED_POINTER_FORMAT" in str(seg.get("error", "")):
                has_unsupported = True
        fixture_fail = syn_artifact.get("CHAIN_DECODER_CURRENT_FIXTURE") == "FAIL"

    # --- run decoder on untouched canonical ---
    can_out = os.path.join(tmpdir, "can-result.json")
    can_md = os.path.join(tmpdir, "can-result.md")
    can_result = run_decoder(BOOTKC, can_out, can_md)
    can_artifact = json.load(open(can_out, encoding="utf-8-sig")) if os.path.exists(can_out) else None
    canonical_pass = can_artifact and can_artifact.get("CHAIN_DECODER_CURRENT_FIXTURE") == "PASS"

    control = {
        "gate": "57ZZ_NON8_FAILCLOSED_POSITIVE_CONTROL",
        "synthetic_bootkc_sha256": synthetic_sha,
        "canonical_bootkc_sha256": canonical_sha,
        "modified_segment": "__DATA_CONST",
        "modified_field": "pointer_format (starts-table entry +6)",
        "original_format": original_format,
        "synthetic_format": 2,
        "synthetic_result": {
            "UNSUPPORTED_POINTER_FORMAT_present": has_unsupported,
            "fixture_complete": syn_artifact.get("CHAIN_DECODER_CURRENT_FIXTURE") if syn_artifact else "SCRIPT_ERROR",
            "self_consistency": syn_artifact.get("CHAIN_WALK_SELF_CONSISTENCY") if syn_artifact else "SCRIPT_ERROR",
        },
        "shared_decoder_direct_test": {
            "synthetic_path_passed_to_build_fixup_index": True,
            "build_fixup_index_rejected_synthetic": shared_decoder_rejected,
            "rejection_message": shared_decoder_error,
        },
        "END_TO_END_SAME_FIXTURE_PROVENANCE": "PASS" if shared_decoder_rejected else "FAIL",
        "canonical_rerun_result": {
            "fixture_complete": can_artifact.get("CHAIN_DECODER_CURRENT_FIXTURE") if can_artifact else "SCRIPT_ERROR",
        },
        "NEGATIVE_CONTROL_PASS": bool(has_unsupported and fixture_fail),
        "CANONICAL_UNAFFECTED_PASS": bool(canonical_pass),
        "OVERALL": "PASS" if (has_unsupported and fixture_fail and canonical_pass and shared_decoder_rejected) else "FAIL",
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(control, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — Non-8 Fail-Closed Positive Control",
        "",
        "```",
        f"NEGATIVE_CONTROL_PASS: {control['NEGATIVE_CONTROL_PASS']}",
        f"CANONICAL_UNAFFECTED_PASS: {control['CANONICAL_UNAFFECTED_PASS']}",
        f"OVERALL: {control['OVERALL']}",
        "```",
        "",
        "Synthetic fixture: __DATA_CONST pointer_format changed 8 -> 2.",
        "The reporting decoder must fail closed (UNSUPPORTED_POINTER_FORMAT +",
        "fixture_complete FAIL), and the untouched canonical must still PASS.",
        "",
        f"Synthetic SHA256: `{synthetic_sha}`",
        f"Canonical SHA256: `{canonical_sha}`",
        "",
    ]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    # cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps(control, indent=2))
    return 0 if control["OVERALL"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
