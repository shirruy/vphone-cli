#!/usr/bin/env python3
"""57ZZ: AppleASCWrapV6 personality contract vs DeviceTree provider matching.

Phases implemented (evidence-gated, no runtime):
  P1: Parse the exact AppleASCWrapV6/SEP/SISP personality dictionaries from
      the known-good BootKC prelink plist (real plistlib parse).
  P2: Walk the complete DeviceTree topology around arm-io/ans for BOTH the
      control and the Iteration-58A ANS-enabled fixtures.
  P3: Build the personality-to-DT match matrix programmatically: compare the
      personalities' IONameMatch values against every ANS-related node's
      name/compatible/device_type.

All values are generated from the fixtures; none are hand-typed verdicts.
"""

import hashlib
import json
import plistlib
import struct
import sys

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
CONTROL_DT = {"label": "control", "path": None}  # resolved by caller env/args
ANS_DT = {"label": "ans58a", "path": None}

OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-ascwrap-personality-contract.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-ascwrap-personality-contract.md"
OUT_TOPO_JSON = "artifacts/evidence/05f/phase05f-57zz-ans-dtree-provider-topology.json"
OUT_TOPO_MD = "artifacts/evidence/05f/phase05f-57zz-ans-dtree-provider-topology.md"

TARGET_BUNDLES = [
    "com.apple.driver.AppleA7IOP-ASCWrap-v6",
]

MATCH_KEYS = [
    "IOClass",
    "IOProviderClass",
    "IONameMatch",
    "IONameMatched",
    "IOPropertyMatch",
    "IOParentMatch",
    "IOPathMatch",
    "IOResourceMatch",
    "IOMatchCategory",
    "IOProbeScore",
    "IOMatchDefer",
    "Cfname",
]

ALIGN = 4


# ---------------------------------------------------------------------------
# BootKC prelink personality extraction
# ---------------------------------------------------------------------------

def find_prelink_plist(data):
    anchor = (
        b"<key>CFBundleIdentifier</key>\n\t\t\t<string>"
        b"com.apple.driver.AppleA7IOP-ASCWrap-v6</string>"
    )
    i = data.find(anchor)
    if i < 0:
        return None
    plist_open = data.rfind(b"<plist", max(0, i - 100000), i)
    xml_decl = data.rfind(b"<?xml", max(0, plist_open - 1000), plist_open)
    plist_close = data.find(b"</plist>", plist_open)
    if plist_close < 0:
        return None
    return data[xml_decl : plist_close + len(b"</plist>")]


def parse_personalities():
    data = open(BOOTKC, "rb").read()
    xml = find_prelink_plist(data)
    if xml is None:
        raise SystemExit("ASCWrap prelink plist not found")
    pl = plistlib.loads(xml)
    entries = pl["_PrelinkInfoDictionary"]
    out = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        bid = e.get("CFBundleIdentifier")
        if bid == "com.apple.driver.AppleA7IOP-ASCWrap-v6":
            personalities = e.get("IOKitPersonalities")
            out["bundle"] = {
                "CFBundleIdentifier": bid,
                "CFBundleExecutable": e.get("CFBundleExecutable"),
                "OSBundleLibraries": e.get("OSBundleLibraries"),
            }
            out["personalities"] = {}
            if isinstance(personalities, dict):
                for pname, pdict in personalities.items():
                    if not isinstance(pdict, dict):
                        continue
                    rec = {}
                    for key in MATCH_KEYS:
                        if key in pdict:
                            rec[key] = pdict[key]
                    other = {
                        k: v for k, v in pdict.items()
                        if k not in MATCH_KEYS and "match" not in k.lower()
                    }
                    rec["_other_keys"] = sorted(other.keys())
                    rec["_all_keys"] = sorted(pdict.keys())
                    out["personalities"][pname] = rec
    return out


# ---------------------------------------------------------------------------
# DeviceTree parsing (ADT format, mirrors phase05f-ans-dt-contract.py)
# ---------------------------------------------------------------------------

def parse_dt_node(buf, off):
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    cursor = off + 8
    node = {"offset": off, "props": {}, "children": []}
    for _ in range(nprops):
        name = buf[cursor : cursor + 32].split(b"\x00")[0].decode("ascii", "replace")
        (length,) = struct.unpack_from("<I", buf, cursor + 32)
        cursor += 36
        vlen = length & ~(1 << 31)
        value = buf[cursor : cursor + vlen]
        node["props"][name] = value
        cursor += (vlen + ALIGN - 1) & ~(ALIGN - 1)
    for _ in range(nchildren):
        child, cursor = parse_dt_node(buf, cursor)
        node["children"].append(child)
    return node, cursor


def node_name(node):
    raw = node["props"].get("name", b"")
    if isinstance(raw, bytes):
        return raw.split(b"\x00")[0].decode("ascii", "replace")
    return str(raw).split("\x00")[0]


def dt_string_list(value):
    """ADT compatible/name/device_type are NUL-separated string lists."""
    if isinstance(value, bytes):
        return [p.decode("ascii", "replace") for p in value.rstrip(b"\x00").split(b"\x00") if p]
    return [str(value)]


def find_path(root, parts):
    node = root
    for part in parts:
        nxt = None
        for child in node["children"]:
            if node_name(child) == part:
                nxt = child
                break
        if nxt is None:
            return None
        node = nxt
    return node


def summarize_node(node, path):
    props = node["props"]
    rec = {
        "path": path,
        "name": node_name(node),
        "compatible": dt_string_list(props.get("compatible", b"")),
        "device_type": dt_string_list(props.get("device_type", b"")),
        "reg": None,
        "role": None,
        "iop_version": None,
        "interrupt_parent": None,
        "iommu_parent": None,
        "phandle": None,
        "children": [node_name(c) for c in node["children"]],
        "prop_names": sorted(props.keys()),
    }
    if "role" in props:
        rec["role"] = dt_string_list(props["role"])
    if "iop-version" in props:
        v = props["iop-version"]
        if len(v) >= 4:
            rec["iop_version"] = struct.unpack("<I", v[:4])[0]
    if "interrupt-parent" in props:
        v = props["interrupt-parent"]
        if len(v) >= 4:
            rec["interrupt_parent"] = struct.unpack("<I", v[:4])[0]
    if "iommu-parent" in props:
        v = props["iommu-parent"]
        if len(v) >= 4:
            rec["iommu_parent"] = struct.unpack("<I", v[:4])[0]
    if "AAPL,phandle" in props:
        v = props["AAPL,phandle"]
        if len(v) >= 4:
            rec["phandle"] = struct.unpack("<I", v[:4])[0]
    if "reg" in props:
        raw = props["reg"]
        pairs = []
        for i in range(0, len(raw) - 15, 16):
            b, s = struct.unpack("<QQ", raw[i : i + 16])
            pairs.append({"base": b, "size": s})
        rec["reg"] = pairs
    return rec


def extract_topology(path):
    buf = open(path, "rb").read()
    root, _ = parse_dt_node(buf, 0)
    out = {"root_children": [node_name(c) for c in root["children"]], "nodes": []}

    def walk_arm_io():
        arm_io = find_path(root, ["arm-io"])
        if arm_io is None:
            return
        # ANS node and its subtree
        ans = None
        for child in arm_io["children"]:
            if node_name(child) == "ans":
                ans = child
                break
        targets = []
        if ans is not None:
            targets.append(("/arm-io/ans", ans))
            for c in ans["children"]:
                targets.append(("/arm-io/ans/" + node_name(c), c))
                for cc in c["children"]:
                    targets.append(
                        "/arm-io/ans/" + node_name(c) + "/" + node_name(cc), cc
                    )
        # Any other node in arm-io whose compatible mentions ascwrap/ans/iop
        for child in arm_io["children"]:
            nm = node_name(child)
            comp = dt_string_list(child["props"].get("compatible", b""))
            joined = " ".join(comp).lower()
            if ("ascwrap" in joined or nm == "ans" or "ans" in joined) and (
                "/arm-io/" + nm
            ) not in [t[0] for t in targets]:
                targets.append(("/arm-io/" + nm, child))
        for pathstr, n in targets:
            out["nodes"].append(summarize_node(n, pathstr))
        out["arm_io_child_names"] = [node_name(c) for c in arm_io["children"]]

    walk_arm_io()
    return out


# ---------------------------------------------------------------------------
# P3: personality-to-DT match matrix
# ---------------------------------------------------------------------------

def build_matrix(personalities, topology):
    rows = []
    for pname, p in personalities.get("personalities", {}).items():
        provider = p.get("IOProviderClass")
        names = p.get("IONameMatch")
        if names is None:
            names = []
        elif isinstance(names, str):
            names = [names]
        for node in topology["nodes"]:
            values = set(node["compatible"]) | set(node["device_type"]) | {node["name"]}
            for nm in names:
                matches = nm in values
                rows.append({
                    "personality": pname,
                    "expected_provider_class": provider,
                    "dt_path": node["path"],
                    "actual_node_name": node["name"],
                    "compatible": node["compatible"],
                    "device_type": node["device_type"],
                    "name_match_value": nm,
                    "matches_personality": matches,
                    "node_has_iop_nub_rtbuddy": "iop-nub,rtbuddy-v2" in node["compatible"],
                    "node_has_ascwrap_compatible": any("ascwrap" in c.lower() for c in node["compatible"]),
                })
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    import os

    control = os.environ.get("PHASE05F_CONTROL_DT", "")
    ansdt = os.environ.get("PHASE05F_ANS_DT", "")
    if not control or not ansdt:
        # default temp fixtures used by the prior decisive runs
        control = os.path.join(os.environ.get("TEMP", "/tmp"), "dtree_control.bin")
        ansdt = os.path.join(os.environ.get("TEMP", "/tmp"), "dtree_experiment.bin")

    personalities = parse_personalities()
    if not personalities.get("personalities"):
        raise SystemExit("no ASCWrap personalities parsed")

    ctrl_topo = extract_topology(control)
    ans_topo = extract_topology(ansdt)

    matrix_ctrl = build_matrix(personalities, ctrl_topo)
    matrix_ans = build_matrix(personalities, ans_topo)

    # H1 classification: does ANY node in either DT satisfy each personality's
    # (IOProviderClass=AppleARMIODevice, IONameMatch) contract?
    def h1_for(matrix):
        out = {}
        for row in matrix:
            p = row["personality"]
            out.setdefault(p, {"any_name_match": False, "ascwrap_compatible_node": False})
            if row["matches_personality"]:
                out[p]["any_name_match"] = True
            if row["node_has_ascwrap_compatible"]:
                out[p]["ascwrap_compatible_node"] = True
        return out

    h1 = {"control": h1_for(matrix_ctrl), "ans58a": h1_for(matrix_ans)}

    p1_pass = all(
        p.get("IOProviderClass") for p in personalities["personalities"].values()
    )

    artifact = {
        "gate": "57ZZ_ASCWRAP_MATCHING",
        "bootkc_sha256": sha256(BOOTKC),
        "control_dt_path": control,
        "control_dt_sha256": sha256(control),
        "ans_dt_path": ansdt,
        "ans_dt_sha256": sha256(ansdt),
        "P1_personality_contract": personalities,
        "P1_PERSONALITY_PARSE": "PASS" if p1_pass else "BLOCKED",
        "P2_topology": {"control": ctrl_topo, "ans58a": ans_topo},
        "P3_matrix": {"control": matrix_ctrl, "ans58a": matrix_ans},
        "P4_H1_MISSING_ASCWRAP_PROVIDER_IDENTITY": h1,
        "verdicts": {
            "P1_PERSONALITY_PARSE": "PASS" if p1_pass else "BLOCKED",
            "H1_MISSING_ASCWRAP_PROVIDER_IDENTITY": "UNKNOWN",  # set below
        },
    }

    # H1: SUPPORTED if no personality name-matches any node with an ASCWrap
    # compatible in EITHER fixture (i.e. provider identity absent).
    def classify_h1(h1):
        for fixture in ("control", "ans58a"):
            for p, v in h1[fixture].items():
                if v["ascwrap_compatible_node"] and v["any_name_match"]:
                    return "REFUTED"
        # if no ascwrap-compatible node exists at all in either fixture
        any_ascwrap = any(
            v["ascwrap_compatible_node"]
            for fixture in h1.values()
            for v in fixture.values()
        )
        return "SUPPORTED" if not any_ascwrap else "UNKNOWN"

    artifact["verdicts"]["H1_MISSING_ASCWRAP_PROVIDER_IDENTITY"] = classify_h1(h1)

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    # Separate topology artifacts (P2) including the ASCWrap experiment DT
    # when present.
    topo_artifact = {
        "gate": "57ZZ_ANS_DTREE_PROVIDER_TOPOLOGY",
        "control_dt_sha256": artifact["control_dt_sha256"],
        "ans58a_dt_sha256": artifact["ans_dt_sha256"],
        "control": ctrl_topo,
        "ans58a": ans_topo,
    }
    ascwrap_dt = os.environ.get("PHASE05F_ASCWRAP_DT", "")
    if ascwrap_dt and os.path.exists(ascwrap_dt):
        topo_artifact["ascwrap_experiment_dt_path"] = ascwrap_dt
        topo_artifact["ascwrap_experiment_dt_sha256"] = sha256(ascwrap_dt)
        topo_artifact["ascwrap_experiment"] = extract_topology(ascwrap_dt)
    with open(OUT_TOPO_JSON, "w", encoding="utf-8") as f:
        json.dump(topo_artifact, f, indent=2)
        f.write("\n")
    tlines = ["# 57ZZ — ANS DeviceTree Provider Topology", ""]
    for label in ("control", "ans58a", "ascwrap_experiment"):
        key = label
        topo = topo_artifact.get(key)
        if topo is None:
            continue
        tlines.append("## " + label)
        tlines.append("")
        for n in topo["nodes"]:
            tlines.append(f"- `{n['path']}` compatible={n['compatible']} device_type={n['device_type']}" + (f" role={n['role']}" if n.get('role') else ""))
        tlines.append("")
    with open(OUT_TOPO_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(tlines) + "\n")

    # Markdown summary
    lines = []
    lines.append("# 57ZZ — AppleASCWrapV6 Personality Contract & Provider Matching")
    lines.append("")
    lines.append("## P1: Personality contract (parsed from BootKC prelink plist)")
    lines.append("")
    lines.append("```")
    lines.append("P1_PERSONALITY_PARSE: " + artifact["P1_PERSONALITY_PARSE"])
    lines.append("```")
    lines.append("")
    for pname, p in personalities["personalities"].items():
        lines.append("### " + pname)
        lines.append("")
        for k in MATCH_KEYS:
            if k in p:
                lines.append(f"- `{k}`: `{p[k]}`")
        if p.get("_other_keys"):
            lines.append(f"- other keys: {', '.join(p['_other_keys'])}")
        lines.append("")
    lines.append("## P2: DeviceTree topology around arm-io/ans")
    lines.append("")
    for label, topo in (("control", ctrl_topo), ("ans58a", ans_topo)):
        lines.append(f"### {label}")
        lines.append("")
        for n in topo["nodes"]:
            lines.append(f"#### `{n['path']}`")
            lines.append(f"- compatible: `{n['compatible']}`")
            lines.append(f"- device_type: `{n['device_type']}`")
            if n.get("role"):
                lines.append(f"- role: `{n['role']}`")
            if n.get("iop_version") is not None:
                lines.append(f"- iop-version: `0x{n['iop_version']:x}`")
            if n.get("reg"):
                regs = ", ".join(f"0x{r['base']:x}+0x{r['size']:x}" for r in n["reg"])
                lines.append(f"- reg: {regs}")
            lines.append(f"- children: {n['children']}")
            lines.append("")
    lines.append("## P3: Personality-to-DT match matrix")
    lines.append("")
    lines.append("Matched rows only (name-match satisfied):")
    lines.append("")
    matched = [r for r in matrix_ctrl + matrix_ans if r["matches_personality"]]
    if not matched:
        lines.append("_No personality name-match against any ANS-related node in either fixture._")
    for r in matched:
        lines.append(
            f"- {r['personality']} ↔ {r['dt_path']} "
            f"(name_match={r['name_match_value']}, compatible={r['compatible']})"
        )
    lines.append("")
    lines.append("## P4: H1 classification")
    lines.append("")
    lines.append("```")
    lines.append(
        "H1_MISSING_ASCWRAP_PROVIDER_IDENTITY: "
        + artifact["verdicts"]["H1_MISSING_ASCWRAP_PROVIDER_IDENTITY"]
    )
    lines.append("```")
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(json.dumps({
        "P1_PERSONALITY_PARSE": artifact["P1_PERSONALITY_PARSE"],
        "personalities": sorted(personalities["personalities"].keys()),
        "H1": artifact["verdicts"]["H1_MISSING_ASCWRAP_PROVIDER_IDENTITY"],
        "matrix_rows_control": len(matrix_ctrl),
        "matrix_rows_ans": len(matrix_ans),
        "matched_rows": len(matched),
    }, indent=2))


if __name__ == "__main__":
    main()

