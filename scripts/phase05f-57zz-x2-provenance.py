#!/usr/bin/env python3
"""57ZZ: ARMIO thunk x2 provenance evidence."""

import json
import os

RUN = "build/phase05f-runtime/x2-prov-v1"
OUT_JSON = "artifacts/evidence/05f/phase05f-57zz-x2-provenance.json"
OUT_MD = "artifacts/evidence/05f/phase05f-57zz-x2-provenance.md"


def main():
    cap = json.load(open(os.path.join(RUN, "gdb-capture.json"), encoding="utf-8-sig"))
    summary = cap.get("summary", {})

    artifact = {
        "gate": "ARMIO_THUNK_X2_PROVENANCE",
        "method": "v9: thunk-only hbreak; at each hit, read x2 object vtable and chase pointers",
        "run": RUN,
        "summary": summary,
        "key_finding": {
            "x2_vtable_static": "0xfffffff007cc90f8",
            "x2_vtable_plus_0x40": "0xfffffff00aa4e744 (= IOService::start base)",
            "interpretation": (
                "All 40 x2 objects share vtable 0xfffffff007cc90f8 whose +0x40 "
                "slot resolves to 0xfffffff00aa4e744 (the independently anchored "
                "IOService::start base function). This means the x2 objects are "
                "IOService-family objects (likely IORegistryEntry or IOService "
                "subclasses), NOT ARMIODevice instances themselves. The ARMIODevice "
                "allocator is called to CREATE an ARMIODevice FROM these x2 source "
                "objects. The x2 objects are the DT-derived service entries that "
                "the platform expert passes to the allocator for conversion."
            ),
            "ANS_strings_found": len(summary.get("ans_related_strings", [])),
        },
        "verdicts": {
            "X2_OBJECT_FAMILY": "IOService-family (vtable +0x40 == IOService::start)",
            "X2_SPECIFIC_CLASS": "UNKNOWN (vtable 0xfffffff007cc90f8 not in known map)",
            "X2_IS_ARMIODevice_INSTANCE": "NO (ARMIODevice vtable is 0xfffffff007d336e0, different)",
            "X2_IS_DT_DERIVED_SERVICE": "SUPPORTED (IOService-family vtable + allocator context)",
            "ANS_SPECIFIC_ALLOCATION": "UNKNOWN (no 'ans' string found in x2 objects; name may not be inline)",
            "THUNK_X2_SEMANTIC_ROLE": (
                "LIKELY_DT_DERIVED_SERVICE_ENTRY (IOService-family object passed "
                "to ARMIODevice allocator as the source/registry object)"
            ),
            "NEXT_APPROACH": (
                "The x2 objects are IOService-family but their names are not inline "
                "strings. Next: instrument IORegistryEntry::getName or compareName "
                "at runtime with the specific x2 pointers as 'this' to extract names."
            ),
            "FIRST_QEMU_VISIBLE_PRIMITIVE": "BLOCKED",
            "ITERATION_58B_ENTRY_GATE": "BLOCKED_PROOF_INCOMPLETE",
        },
    }

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")

    md = [
        "# 57ZZ — ARMIO Thunk x2 Provenance",
        "",
        "## Key Finding",
        "",
        "All 40 thunk x2 objects share vtable `0xfffffff007cc90f8`.",
        "Its `+0x40` slot resolves to `0xfffffff00aa4e744` (IOService::start base).",
        "",
        "The x2 objects are IOService-family objects - likely the DT-derived",
        "service entries that the platform expert passes to the ARMIODevice",
        "allocator. They are NOT ARMIODevice instances (different vtable).",
        "",
        "No 'ans' string found inline in the x2 objects. The name property",
        "is likely stored as a separate OSString object, not inline.",
        "",
        "## Verdicts",
        "",
        "```",
    ]
    for k, v in artifact["verdicts"].items():
        md.append(f"{k}: {v}")
    md += ["```", ""]
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(json.dumps(artifact["verdicts"], indent=2))


if __name__ == "__main__":
    main()
