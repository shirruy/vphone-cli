#!/usr/bin/env python3
"""Machine-readable ANS device-tree contract extractor.

Parses the d37ap device tree binary ADT format (dtree_prop + dtree_node)
to dump the ans node with exact decoded property values and byte-range
provenance. Mirrors qemu-sptm hw/arm/apple_dtree.c layout:
  dtree_prop { char name[32]; u32 length; }  (length may have BIT(31) set)
  value = prop+1, rounded up to 4-byte alignment
  node   = { u32 nProperties; u32 nChildren; }
"""

import json
import struct
import sys

ALIGN = 4


def strip_len(l):
    return l & ~(1 << 31)


def parse_node(buf, off):
    """Parse a node at buf[off]. Returns (node_dict, next_off)."""
    nprops, nchildren = struct.unpack_from("<II", buf, off)
    cursor = off + 8
    node = {"_byte_offset": off, "properties": {}, "children": []}
    for _ in range(nprops):
        name = buf[cursor:cursor + 32].split(b"\x00")[0].decode(
            "ascii", errors="replace")
        (length,) = struct.unpack_from("<I", buf, cursor + 32)
        cursor += 36
        vlen = strip_len(length)
        value = buf[cursor:cursor + vlen]
        node["properties"][name] = {
            "length": vlen,
            "byte_offset": cursor,
            "hex": value.hex(),
        }
        cursor += (vlen + ALIGN - 1) & ~(ALIGN - 1)
    for _ in range(nchildren):
        child, cursor = parse_node(buf, cursor)
        node["children"].append(child)
    return node, cursor


def find_node(root, path_parts):
    node = root
    for part in path_parts:
        match = None
        for child in node.get("children", []):
            name_prop = child["properties"].get("name", {})
            name = bytes.fromhex(name_prop.get("hex", "")).decode(
                "ascii", errors="replace").rstrip("\x00")
            if name == part:
                match = child
                break
        if match is None:
            return None
        node = match
    return node


def decode_values(node):
    out = {}
    for name, prop in node["properties"].items():
        raw = bytes.fromhex(prop["hex"])
        decoded = None
        # little-endian u32s (Apple ADT stores values LE on-disk,
        # matching qemu-sptm's direct-cast reads on LE hosts)
        if len(raw) % 4 == 0 and len(raw) > 0:
            u32s = [
                struct.unpack("<I", raw[i:i + 4])[0]
                for i in range(0, len(raw), 4)
            ]
            decoded = u32s
        # (base,size) u64 pairs for reg: little-endian u64s
        if name == "reg" and len(raw) % 16 == 0:
            decoded = [
                {
                    "base": struct.unpack("<Q", raw[i:i + 8])[0],
                    "size": struct.unpack("<Q", raw[i + 8:i + 16])[0],
                }
                for i in range(0, len(raw), 16)
            ]
        out[name] = {
            "length": prop["length"],
            "byte_offset": prop["byte_offset"],
            "decoded": decoded,
            "decoded_hex_strings": None,
            "hex_prefix": raw[:64].hex(),
        }
        # Correct small-integer fields that ADT encodes as u32
        if name in ("interrupts", "interrupt-parent", "clock-ids",
                    "clock-gates", "power-gates", "iop-version",
                    "nvme-interrupt-idx", "nvme-queue-entries",
                    "iommu-parent", "AAPL,phandle"):
            out[name]["decoded_ints"] = [
                struct.unpack("<I", raw[i:i + 4])[0]
                for i in range(0, len(raw), 4)
            ]
        if name in ("name", "device_type", "role", "tunable-table-bundle"):
            out[name]["decoded_string"] = raw.rstrip(b"\x00").decode(
                "ascii", errors="replace")
    return out


def main():
    path = sys.argv[1]
    buf = open(path, "rb").read()
    root, _ = parse_node(buf, 0)
    ans = find_node(root, ["arm-io", "ans"])
    apcie = find_node(root, ["arm-io", "apcie"])
    if ans is None:
        print(json.dumps({"error": "ans node not found"}))
        return 1
    report = {
        "ans_node": {
            "byte_offset": ans["_byte_offset"],
            "properties": decode_values(ans),
            "child_names": [
                bytes.fromhex(
                    c["properties"].get("name", {}).get("hex", "")
                ).decode("ascii", errors="replace").rstrip("\x00")
                for c in ans.get("children", [])
            ],
        },
        "apcie_node": {
            "byte_offset": apcie["_byte_offset"] if apcie else None,
            "properties": decode_values(apcie) if apcie else {},
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
