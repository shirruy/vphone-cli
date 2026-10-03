#!/usr/bin/env python3
"""Iteration 58A verification: opt-in ANS-compatible preservation.

Verifies both dt_fixup.py modes structurally:
  default: iop-ans-nub compatible ABSENT (byte-identical to baseline)
  ANS-enabled: iop-ans-nub compatible == iop-nub,rtbuddy-v2,
               exactly ONE semantic diff vs default, no unrelated restoration
"""

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile

DT_FIXUP = "build/phase05e-qemu-sptm-source-build/darwin-vm/dt_fixup.py"
NVRAM = "build/phase05e-qemu-sptm-source-build/darwin-vm/nvram.bin"
OUT = "artifacts/evidence/05f/phase05f-iteration58a-ans-dtree.json"


def load_dt_module(path):
    spec = importlib.util.spec_from_file_location("dt_fixup_mod", path)
    m = importlib.util.module_from_spec(spec)
    src = open(path, "r", encoding="utf-8").read().split("if __name__==")[0]
    ns = {"__name__": "dt_fixup_mod"}
    exec(compile(src, "dt_fixup_mod", "exec"), ns)
    return ns


def dump_tree(ns, dt_bytes):
    root = ns["ADTNode"]()
    ns["decode_node"](dt_bytes, root)
    return root


def find_by_name(node, name):
    for c in node.children:
        if c.props.get("name") == name:
            return c
    return None


def collect(node, prefix=""):
    out = {}
    for k, v in node.props.items():
        out[prefix + "/" + str(k)] = v
    for c in node.children:
        out.update(collect(c, prefix + "/" + str(c.props.get("name", "?"))))
    return out


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def run_fixup(dtree_in, out_path, extra_args):
    cmd = [sys.executable, DT_FIXUP, dtree_in, out_path, "-nvram", NVRAM] + extra_args
    subprocess.run(cmd, check=True, capture_output=True)


def main():
    dtree_in = os.environ.get("ANS_58A_DTREE_IN")
    baseline_sha = os.environ.get("ANS_58A_BASELINE_SHA")
    if not dtree_in:
        dtree_in = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\dtree.raw.bin"
    if not baseline_sha:
        baseline_sha = "9E84C9ADD25B99EDDD8B088B249E7CE348394B80A0DEF59949E9BB9C63A24E1B"

    ns = load_dt_module(DT_FIXUP)
    tmp = tempfile.mkdtemp()
    default_out = os.path.join(tmp, "default.bin")
    ans_out = os.path.join(tmp, "ans.bin")

    run_fixup(dtree_in, default_out, [])
    run_fixup(dtree_in, ans_out, ["--preserve-ans-compatible"])

    default_sha = sha256_file(default_out)
    ans_sha = sha256_file(ans_out)

    r_def = dump_tree(ns, open(default_out, "rb").read())
    r_ans = dump_tree(ns, open(ans_out, "rb").read())

    d_def = collect(r_def)
    d_ans = collect(r_ans)
    diffs = [
        k
        for k in sorted(set(d_def) | set(d_ans))
        if d_def.get(k, "<MISSING>") != d_ans.get(k, "<MISSING>")
    ]

    ans_node = find_by_name(find_by_name(r_ans, "arm-io"), "ans")
    nub_ans = find_by_name(ans_node, "iop-ans-nub") if ans_node else None
    nub_def = find_by_name(find_by_name(r_def, "arm-io"), "ans")
    nub_def = find_by_name(nub_def, "iop-ans-nub") if nub_def else None

    default_compat = nub_def.props.get("compatible", None) if nub_def else "<NODE_MISSING>"
    ans_compat = nub_ans.props.get("compatible", None) if nub_ans else "<NODE_MISSING>"
    role = ans_node.props.get("role") if ans_node else None

    default_regression = default_sha == baseline_sha
    ans_structural = (
        ans_compat == "iop-nub,rtbuddy-v2"
        and role == "ANS2"
        and len(diffs) == 1
        and diffs[0].endswith("/arm-io/ans/iop-ans-nub/compatible")
    )

    artifact = {
        "gate": "ITERATION_58A",
        "default_output_sha256": default_sha,
        "ans_enabled_output_sha256": ans_sha,
        "baseline_sha256": baseline_sha,
        "default_regression": "PASS" if default_regression else "FAIL",
        "default_iop_ans_nub_compatible": default_compat,
        "ans_enabled_iop_ans_nub_compatible": ans_compat,
        "ans_role": role,
        "semantic_diff_count": len(diffs),
        "semantic_diffs": diffs,
        "ans_structural_proof": "PASS" if ans_structural else "FAIL",
        "verdict": "PASS" if (default_regression and ans_structural) else "FAIL",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        import json

        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact, indent=2))


if __name__ == "__main__":
    main()
