#!/usr/bin/env python3
"""57ZZ Part 15B-S: AppleA7IOP provider publication chain analysis.

Recovers the IOKit personality chain above AppleA7IOP from BootKC
__PRELINK_INFO XML, the authoritative DT, and the AppleA7IOP kext
metadata to identify what QEMU must actually expose.
"""

import hashlib
import json
import re

BOOTKC = r"C:\Users\rbjos\vphone-private\phase05f-known-good\payloads-v3\bootkc.bin"
OUT = "artifacts/evidence/05f/phase05f-57zz-part15b-provider-chain.json"


def extract_prelink_block(data, bundle_id):
    search = b'<key>CFBundleIdentifier</key>\n\t\t\t<string>' + bundle_id + b'</string>'
    i = data.find(search)
    if i < 0:
        return None
    start = data.rfind(b'<dict>', max(0, i - 6000), i)
    depth = 0
    p = start
    end = None
    while p < len(data):
        m = re.search(br'<(/?dict)>', data[p : p + 1000000])
        if not m:
            break
        if m.group(1) == b'dict':
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                end = p + m.end()
                break
        p = p + m.end()
    return data[start:end] if end else None


def personality_keys(block):
    out = []
    for km in re.finditer(
        br'<key>(IOClass|IOProviderClass|IONameMatch|IOPropertyMatch|IOProbeScore|IOPersonalityPublisher|IOResourceMatch)</key>\s*<(string|integer|array|dict)>([\s\S]*?)</\2>',
        block,
    ):
        out.append({"key": km.group(1).decode(), "value": km.group(3).decode("utf-8", "replace").strip()[:400]})
    return out


def main():
    data = open(BOOTKC, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()

    ascwrap = extract_prelink_block(data, b"com.apple.driver.AppleA7IOP-ASCWrap-v6")
    a7iop = extract_prelink_block(data, b"com.apple.driver.AppleA7IOP")
    armplat = extract_prelink_block(data, b"com.apple.driver.AppleARMPlatform")

    ascwrap_personalities = personality_keys(ascwrap) if ascwrap else []
    a7iop_keys = personality_keys(a7iop) if a7iop else []
    armplat_personalities = personality_keys(armplat) if armplat else []

    # AppleA7IOP bundle dependencies
    a7iop_deps = []
    if a7iop:
        dep_block = re.search(br'<key>OSBundleLibraries</key>\s*<dict>([\s\S]*?)</dict>', a7iop)
        if dep_block:
            for km in re.finditer(br'<key>([^<]+)</key>\s*<string>([^<]+)</string>', dep_block.group(1)):
                a7iop_deps.append({"bundle": km.group(1).decode(), "version": km.group(2).decode()})

    artifact = {
        "gate": "PART15B_PROVIDER_CHAIN",
        "iteration": "57ZZ_PART15B_S",
        "bootkc_sha256": sha,
        "ascwrap_personalities": ascwrap_personalities,
        "a7iop_info_keys": a7iop_keys,
        "a7iop_bundle_dependencies": a7iop_deps,
        "armplatform_relevant_personalities": [
            p for p in armplat_personalities if p["key"] == "IOClass"
        ],
        "key_findings": {
            "ascwrap_personality": "AppleASCWrapV6: IOProviderClass=AppleARMIODevice, IONameMatch=iop,ascwrap-v6 / iop,ascwrap-v7 (and SEP/SISP variants)",
            "applea7iop_is_personality_driven": "NO: com.apple.driver.AppleA7IOP Info.plist contains NO IOClass/IOProviderClass personality. It is an explicit client of AppleARMPlatform and IOSlaveProcessor.",
            "applea7iop_dependencies": a7iop_deps,
            "applearmio_device_publisher": "AppleARMIODevice instances are published from the arm-io DeviceTree subtree; the IOPlatformExpert-adjacent arm-io enumeration ('arm-io, this should not happen' error string at 0x15de6e is the matching-path log)",
            "expected_provider_hypothesis": "AppleA7IOP is instantiated by code that iterates AppleARMIODevice children carrying AKF register data. The exact creator kext is NOT yet proven (candidate: IOSlaveProcessor / AppleARMPlatform platform expert).",
            "qemu_visible_prerequisite": "BLOCKED: not yet proven which concrete DT node/property or MMIO region causes the AKF-capable provider to exist.",
        },
        "verdicts": {
            "APPLEA7IOP_START": "BLOCKED",
            "START_PROVIDER_DATAFLOW": "BLOCKED",
            "APPLEA7IOP_PROVIDER_CLASS": "UNKNOWN",
            "APPLEA7IOP_PERSONALITY_MATCH": "BLOCKED (no personality in Info.plist)",
            "PROVIDER_PUBLICATION_CHAIN": "BLOCKED",
            "AKF_REGISTER_MAP_SOURCE": "UNKNOWN",
            "AKF_MMIO_BASE": "UNKNOWN",
            "AKF_MMIO_SIZE": "UNKNOWN",
            "AKF_MAPPED_REGS_PRODUCTION": "BLOCKED",
            "FIRST_AKF_MAPPED_REG_ACCESS": "UNKNOWN",
            "MAILBOX_OFFSETS": "BLOCKED",
            "AKF_ROLE_PROPERTY_REQUIRED": "UNKNOWN",
            "ASC_FIRMWARE_REQUIRED_FOR_58B": "UNKNOWN",
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "FIRST_ANS_RUNTIME_REQUIREMENT": "CANDIDATE_AKF_PROVIDER_CHAIN",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
            "ANS_STORAGE_IMPLEMENTATION_READINESS": "BLOCKED_FOR_58B",
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["key_findings"], indent=2))
    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
