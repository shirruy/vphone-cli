#!/usr/bin/env python3
"""57ZZ P8: canonical ASCWrap DT experiment builder.

Builds three DeviceTree fixtures from the known-good RAW DT:
  control    - canonical dt_fixup default (compatible pruning intact)
  ans58a     - canonical dt_fixup --preserve-ans-compatible (child nub only)
  ascwrap    - 58A behavior + restored parent /arm-io/ans compatible
               iop,ascwrap-v6 (the proven personality matching precondition)

The ascwrap fixture runs the SAME canonical fixup pipeline (decode, nvram and
sptm patches, prune, encode) with one in-memory extension: the ANS parent
node keeps its iop,ascwrap-v6 compatible. No output re-decode/re-encode is
performed, because that round-trip is not byte-stable in this encoder.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

DT_FIXUP = os.path.join("build", "phase05e-qemu-sptm-source-build", "darwin-vm", "dt_fixup.py")
DEFAULT_RAW = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\dtree.raw.bin"
DEFAULT_NVRAM = os.path.join("build", "phase05e-qemu-sptm-source-build", "darwin-vm", "nvram.bin")

PARENT_MARKER = b"iop,ascwrap-v6"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def run_canonical_fixup(raw, out, nvram, extra):
    cmd = [sys.executable, DT_FIXUP, raw, out, "-nvram", nvram] + extra
    subprocess.run(cmd, check=True, capture_output=True)


def run_ascwrap_fixup(raw, out, nvram):
    """Run the canonical fixup pipeline with ANS-parent compatible preservation.

    Applies the same decode -> fixup() -> encode flow as dt_fixup.main(),
    with one in-memory extension: the ANS parent node keeps its
    iop,ascwrap-v6 compatible when --preserve-ans-compatible semantics are
    active. No output re-decode/re-encode round-trip is performed.
    """
    src_bytes = open(DT_FIXUP, "rb").read()
    import hashlib as _hl
    src_sha = _hl.sha256(src_bytes).hexdigest().upper()
    src = src_bytes.decode("utf-8")
    expected_patterns = [
        "def del_compat(d, preserve_ans_compat=False):",
        "if preserve_ans_compat and is_ans_nub and ANS_COMPAT_PRESERVE in compat:",
    ]
    for pat in expected_patterns:
        if src.count(pat) != 1:
            raise SystemExit(
                "dt_fixup source drift (pattern count != 1): %r (sha %s)" % (pat, src_sha)
            )
    old = """def del_compat(d, preserve_ans_compat=False):
  is_ans_nub = (d.props.get('name') == 'iop-ans-nub')
  for c in d.children:
    del_compat(c, preserve_ans_compat=preserve_ans_compat)"""
    new = """def del_compat(d, preserve_ans_compat=False, _parent_is_ans=False):
  is_ans_nub = (d.props.get('name') == 'iop-ans-nub')
  role = d.props.get('role')
  if isinstance(role, bytes):
    role = role.rstrip(b'\\x00').decode('ascii', 'replace')
  _is_ans_parent = _parent_is_ans or (d.props.get('name') == 'ans' and role == 'ANS2')
  for c in d.children:
    del_compat(c, preserve_ans_compat=preserve_ans_compat, _parent_is_ans=_is_ans_parent)"""
    if old not in src:
        raise SystemExit("dt_fixup del_compat signature changed; builder needs update")
    src = src.replace(old, new, 1)

    old2 = """    if preserve_ans_compat and is_ans_nub and ANS_COMPAT_PRESERVE in compat:
      return"""
    new2 = """    if preserve_ans_compat and is_ans_nub and ANS_COMPAT_PRESERVE in compat:
      return
    if preserve_ans_compat and _is_ans_parent and b'iop,ascwrap-v6' in compat:
      return"""
    if old2 not in src:
        raise SystemExit("dt_fixup preserve block changed; builder needs update")
    src = src.replace(old2, new2, 1)

    src = src.split('def main():')[0]
    ns = {"__name__": "dt_fixup_ascwrap"}
    exec(compile(src, "dt_fixup_ascwrap", "exec"), ns)

    root = ns["ADTNode"]()
    ns["decode_node"](open(raw, "rb").read(), root)
    ns["fixup"](root, nvram_file=open(nvram, "rb"), preserve_ans_compat=True)
    with open(out, "wb") as f:
        f.write(ns["encode_node"](root))
    return src_sha

def load_parser():
    src = open(DT_FIXUP, "r", encoding="utf-8").read().split("if __name__==")[0]
    ns = {"__name__": "dt_fixup_parse"}
    exec(compile(src, "dt_fixup_parse", "exec"), ns)
    return ns


def find_child(node, name):
    for c in node.children:
        v = c.props.get("name", "")
        if isinstance(v, bytes):
            v = v.split(b"\x00")[0].decode("ascii", "replace")
        if v == name:
            return c
    return None


def node_count(node):
    return 1 + sum(node_count(c) for c in node.children)


def prop_count(node):
    return len(node.props) + sum(prop_count(c) for c in node.children)


def collect_tree(node, prefix=""):
    out = {}
    for k, v in node.props.items():
        key = prefix + "/" + str(k)
        out[key] = v if isinstance(v, bytes) else str(v).encode()
    for c in node.children:
        nm = c.props.get("name", "?")
        if isinstance(nm, bytes):
            nm = nm.split(b"\x00")[0].decode("ascii", "replace")
        out.update(collect_tree(c, prefix + "/" + nm))
    return out


def parse(ns, path):
    root = ns["ADTNode"]()
    ns["decode_node"](open(path, "rb").read(), root)
    return root


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=DEFAULT_RAW)
    ap.add_argument("--nvram", default=DEFAULT_NVRAM)
    ap.add_argument("--outdir", default=os.path.join("build", "phase05f-runtime", "dt-fixtures"))
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    control = os.path.join(args.outdir, "dtree_control.bin")
    ans58a = os.path.join(args.outdir, "dtree_ans58a.bin")
    ascwrap = os.path.join(args.outdir, "dtree_ascwrap.bin")

    run_canonical_fixup(args.raw, control, args.nvram, [])
    run_canonical_fixup(args.raw, ans58a, args.nvram, ["--preserve-ans-compatible"])
    src_sha = run_ascwrap_fixup(args.raw, ascwrap, args.nvram)

    ns = load_parser()
    r_ctrl = parse(ns, control)
    r_58a = parse(ns, ans58a)
    r_asc = parse(ns, ascwrap)
    d_ctrl = collect_tree(r_ctrl)
    d_58a = collect_tree(r_58a)
    d_asc = collect_tree(r_asc)

    diff_58a_ctrl = sorted(k for k in set(d_ctrl) | set(d_58a) if d_ctrl.get(k) != d_58a.get(k))
    diff_asc_58a = sorted(k for k in set(d_58a) | set(d_asc) if d_58a.get(k) != d_asc.get(k))

    expected_58a = ["/arm-io/ans/iop-ans-nub/compatible"]
    expected_asc = ["/arm-io/ans/compatible"]
    unexpected = [k for k in diff_asc_58a if k not in expected_asc]

    report = {
        "gate": "57ZZ_ASCWRAP_DT_FIXTURE_BUILDER",
        "DT_FIXUP_SOURCE_SHA256": src_sha,
        "raw_dt_sha256": sha256(args.raw),
        "control_dt_sha256": sha256(control),
        "ans58a_dt_sha256": sha256(ans58a),
        "ascwrap_dt_sha256": sha256(ascwrap),
        "control_path": control,
        "ans58a_path": ans58a,
        "ascwrap_path": ascwrap,
        "node_counts": {"control": node_count(r_ctrl), "ans58a": node_count(r_58a), "ascwrap": node_count(r_asc)},
        "property_counts": {"control": prop_count(r_ctrl), "ans58a": prop_count(r_58a), "ascwrap": prop_count(r_asc)},
        "diff_58a_vs_control": diff_58a_ctrl,
        "diff_ascwrap_vs_58a": diff_asc_58a,
        "expected_changed_properties": expected_asc,
        "UNEXPECTED_CHANGED_PROPERTIES": len(unexpected),
        "verdict": "PASS" if (len(unexpected) == 0 and diff_58a_ctrl == expected_58a) else "FAIL",
    }
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

