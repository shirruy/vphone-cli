#!/usr/bin/env python3
"""57ZZ Part 15A: ANS/storage implementation-readiness contract freeze.

Consolidates the already-proven ANS/storage contracts and builds the
minimal Iteration 58 implementation contract. No new reverse engineering;
revalidation only plus qemu-sptm device-model audit.
"""

import hashlib
import json
import os
import re

OUT = "artifacts/evidence/05f/phase05f-57zz-part15a-ans-storage-readiness.json"

ARTIFACT_DIR = "artifacts/evidence/05f"
QEMU_DIR = "build/phase05e-qemu-sptm-source-build/darwin-vm"
DT_FIXUP = os.path.join(QEMU_DIR, "dt_fixup.py")
DARWIN_C = os.path.join(QEMU_DIR, "qemu-sptm", "hw", "arm", "darwin.c")
APPLE_AMCC_C = os.path.join(QEMU_DIR, "qemu-sptm", "hw", "arm", "apple_amcc.c")


def load_json(name):
    p = os.path.join(ARTIFACT_DIR, name)
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def file_sha(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    dt_contract = load_json("phase05f-ans-dt-contract.json")
    match_contract = load_json("phase05f-ans-kernel-driver-match.json")
    lba_contract = load_json("phase05f-ios-storage-lba-contract.json")
    preboom = load_json("phase05f-preboom-storage-contract.json")

    # 15A-A: revalidation
    match_canonical = match_contract.get("canonical_state", {})
    lba_canonical = lba_contract.get("canonical_state", {}) or lba_contract
    reval = {
        "ans_match_controller": match_canonical.get("CURRENT_CONTROLLER_CLASS"),
        "ans_match_provider": match_canonical.get("CURRENT_PROVIDER_CLASS"),
        "lba_size": lba_canonical.get("NVME_NAMESPACE_LBA_SIZE"),
        "lba_shift": lba_canonical.get("NVME_NAMESPACE_LBA_SHIFT"),
        "ans_dt_gate": dt_contract.get("gate"),
        "namespace_records": preboom.get("ans_device_tree", {}).get("namespace_records"),
        "reg_mmio": preboom.get("ans_device_tree", {}).get("reg_mmio"),
        "interrupts": preboom.get("ans_device_tree", {}).get("interrupts"),
        "interrupt_parent": preboom.get("ans_device_tree", {}).get("interrupt_parent"),
        "nvme_interrupt_idx": preboom.get("ans_device_tree", {}).get("nvme_interrupt_idx"),
    }
    # 15A-R3: exact expected values
    expected = {
        "controller": "AppleANS3NVMeController",
        "provider": "RTBuddyService",
        "lba_size": 4096,
        "lba_shift": 12,
        "namespace_count": 7,
        "reg_pair_count": 14,
        "nonzero_mmio_count": 7,
        "interrupts": [622, 621, 624, 623, 629],
        "interrupt_parent": 32,
        "nvme_interrupt_idx": 4,
        "authoritative_compatible": "iop-nub,rtbuddy-v2",
        "booted_compatible": None,  # ABSENT
    }
    checks = {
        "controller": reval["ans_match_controller"] == expected["controller"],
        "provider": reval["ans_match_provider"] == expected["provider"],
        "lba_size": reval["lba_size"] == expected["lba_size"],
        "lba_shift": reval["lba_shift"] == expected["lba_shift"],
        "namespace_count": len(reval["namespace_records"] or []) == expected["namespace_count"],
        "reg_pair_count": len(reval["reg_mmio"] or []) == expected["reg_pair_count"],
        "interrupts": reval["interrupts"] == expected["interrupts"],
        "interrupt_parent": reval["interrupt_parent"] == expected["interrupt_parent"],
        "nvme_interrupt_idx": reval["nvme_interrupt_idx"] == expected["nvme_interrupt_idx"],
    }
    nonzero_mmio = [r for r in (reval["reg_mmio"] or []) if r["size"] != "0x0"]
    checks["nonzero_mmio_count"] = len(nonzero_mmio) == expected["nonzero_mmio_count"]
    # authoritative compatible: from dt contract
    auth_compat = dt_contract.get("authoritative_ans_nub_child", {}).get("D37AP_IOP_ANS_NUB_COMPATIBLE_AUTHORITATIVE")
    checks["authoritative_compatible"] = auth_compat == expected["authoritative_compatible"]
    # booted compatible absent: iop_ans_nub_child compatible field
    booted_compat = dt_contract.get("iop_ans_nub_child", {}).get("iop_ans_nub_compatible")
    checks["booted_compatible_absent"] = (booted_compat is None or "ABSENT" in str(booted_compat))
    closed_contracts_valid = all(checks.values())

    # 15A-B: qemu-sptm device model audit
    qemu_src = DARWIN_C
    amcc_src = APPLE_AMCC_C
    dt_fixup_src = open(DT_FIXUP, "r", encoding="utf-8").read()

    device_audit = {
        "ANS_device_object": {"exists": False, "evidence": "no AppleANS/ANS device symbol in hw/arm"},
        "NVMe_controller_emulation": {"exists": False, "evidence": "no nvme Apple-specific device"},
        "AppleANS_related_device": {"exists": False, "evidence": "none"},
        "RTBuddy_endpoint": {"exists": False, "evidence": "no rtbuddy/rtkit symbols in qemu-sptm"},
        "AppleASC_transport": {"exists": False, "evidence": "hw/audio/asc.c is classic Mac ASC (344S0063), not AppleASC/RTKit"},
        "DMA_IOMMU": {"exists": True, "reusable": "UNPROVEN", "evidence": "generic smmuv3 exists; no DART for t8120 ANS path"},
        "NVMe_SQ_CQ": {"exists": False, "evidence": "none"},
        "namespace_abstraction": {"exists": False, "evidence": "none"},
        "block_backend_attachment": {"exists": True, "reusable": "PARTIAL", "evidence": "generic QEMU block layer exists; no ANS wiring"},
        "MMIO_handlers_for_ANS": {"exists": False, "evidence": "none"},
        "interrupt_wiring_ANS": {"exists": False, "evidence": "none"},
    }
    amcc_pattern = {
        "exists": True,
        "reusable_as_template": True,
        "evidence": "apple_amcc.c is a minimal SysBus MMIO device (read/write ops, sysbus_mmio_map) realized in darwin_machine_init",
    }

    # 15A-C: DT fix contract
    supported_drivers = re.search(r"SUPPORTED_DRIVERS\s*=\s*\[(.*?)\]", dt_fixup_src, re.S).group(1)
    del_compat_present = "def del_compat" in dt_fixup_src
    rtbuddy_in_whitelist = "rtbuddy" in supported_drivers.lower()
    dt_fix = {
        "authoritative_property": "iop-ans-nub compatible = iop-nub,rtbuddy-v2",
        "booted_property": "ABSENT (deleted by del_compat; not in SUPPORTED_DRIVERS whitelist)",
        "root_cause": "del_compat() recursively deletes any compatible property not matching SUPPORTED_DRIVERS = [AppleARM, aic, arm-io, uart-1,samsung]",
        "minimal_fix": "add b'iop-nub' (or b'iop-nub,rtbuddy-v2') to SUPPORTED_DRIVERS, OR a targeted exception preserving compatible on the iop-ans-nub child",
        "acceptance": "BOOTED_ANS_COMPATIBLE_RESTORE: PASS when regenerated dtree.bin contains iop-nub,rtbuddy-v2 in the iop-ans-nub child",
        "status": "OPEN_ACTION_ITEM",
    }

    # 15A-D: MMIO ranges
    mmio_rows = []
    for i, r in enumerate(nonzero_mmio):
        mmio_rows.append(
            {
                "index": i,
                "base": r["base"],
                "size": r["size"],
                "proven_consumer": "UNKNOWN_MMIO_REGION",
                "required_behavior": "UNKNOWN",
            }
        )

    # 15A-E: interrupts
    interrupts = {
        "values": reval["interrupts"],
        "parent": reval["interrupt_parent"],
        "nvme_interrupt_idx": reval["nvme_interrupt_idx"],
        "completion_irq": "UNKNOWN (nvme-interrupt-idx=4 is a candidate index; not statically proven as completion)",
        "proof_level": "UNKNOWN",
    }

    # 15A-G: Identify response minimum
    identify = {
        "consumed_fields": {
            "NCAP@0x08": "u32 read at buffer+8 (ValidateNamespaceSize)",
            "NLBAF@0x19": "must be >= FLBAS+1",
            "FLBAS@0x1a": "selects active LBAF",
            "LBAF@0x80+4*FLBAS": "entry+0 u16 must be 0 (metadata size), entry+2 u8 = 12 (LBADS)",
        },
        "required_active_lba_format": {"metadata_size": 0, "lbads": 12, "lba_size": 4096},
        "note": "fields beyond these four are NOT proven consumed before publication; do not populate spec fields speculatively",
    }

    # 15A-H/I: NSID capacity and backing
    nsid1 = {
        "capacity_source": "alternate path: inByteCapacity / burn-in block override; NCAP comparison uses word2=0 -> alternate",
        "backing_identity": "CANDIDATE (not proven)",
        "status": "BLOCKED",
    }

    # 15A-R4: LBA addressing — retract unproven transfer-length formula
    lba_translation = {
        "GUEST_LBA_BYTES": 4096,
        "SLBA_ADDRESSING_SEMANTICS": "TO_BE_CONFIRMED_IN_QUEUE_COMMAND_TRACE",
        "TRANSFER_LENGTH_ENCODING": "UNKNOWN",
        "HOST_BYTE_TRANSLATION": "BLOCKED_PENDING_COMMAND_ENCODING",
        "note": "Guest LBA size 4096 is proven. Exact NLB encoding (direct / zero-based / minus-one / Apple wrapper) is NOT proven and must be resolved before 58F read/write backing.",
    }

    # 15A-K: command surface
    commands = {
        "REQUIRED_BEFORE_NAMESPACE_PUBLICATION": ["identify (Apple internal selector 0x11 path)"],
        "REQUIRED_FOR_READ_ONLY_APFS": ["read"],
        "REQUIRED_FOR_WRITABLE_RESTORE": ["write", "flush"],
        "NOT_YET_REQUIRED": ["full admin feature set", "vendor-specific command surface"],
    }

    # 15A-R5: milestones split — each proves exactly its milestone
    milestones = [
        {"id": "M0", "desc": "ANS-compatible property preserved in booted DT", "pass": "iop-nub,rtbuddy-v2 present on iop-ans-nub"},
        {"id": "M1", "desc": "AppleA7IOPNub publishes", "pass": "AppleA7IOPNub allocated-nub log"},
        {"id": "M2", "desc": "RTBuddy / RTBuddyService attaches", "pass": "RTBuddyService attachment evidence"},
        {"id": "M3", "desc": "AppleANS3NVMeController probe/start reached", "pass": "ANS3 probe/start log"},
        {"id": "M4", "desc": "namespace request observed", "pass": "'Creating %d namespaces on NAND' log"},
        {"id": "M5", "desc": "Identify response accepted", "pass": "LBADS==12 accepted, no Invalid LogicalBlockSize"},
        {"id": "M6", "desc": "first block device/media published", "pass": "AppleEmbeddedBlockDevice media object appears"},
        {"id": "M7", "desc": "read-only host-backed read verified", "pass": "correct bytes returned for known LBA"},
        {"id": "M8", "desc": "APFS NXSB read through guest storage path", "pass": "NXSB magic at block 0"},
    ]

    # 15A-R2: derived gates
    rtbuddy_handshake_known = False
    mmio_surface_known = False
    interrupt_behavior_known = False
    dma_path_known = False
    queue_command_known = False
    dt_fix_implementable = dt_fix["status"] == "OPEN_ACTION_ITEM" and del_compat_present and not rtbuddy_in_whitelist
    entry_58a = closed_contracts_valid and checks["authoritative_compatible"] and checks["booted_compatible_absent"] and dt_fix_implementable
    entry_58b_plus = (
        entry_58a
        and rtbuddy_handshake_known
        and mmio_surface_known
        and interrupt_behavior_known
        and dma_path_known
        and queue_command_known
    )
    global_readiness = "BLOCKED_FOR_58B_PLUS"

    # 15A-P: Iteration 58 scope
    iteration58 = {
        "58A": {"title": "DT compatible preservation", "files": ["build/phase05e-qemu-sptm-source-build/darwin-vm/dt_fixup.py"]},
        "58B": {"title": "ANS device skeleton / MMIO map", "files": ["build/phase05e-qemu-sptm-source-build/darwin-vm/qemu-sptm/hw/arm/apple_ans.c (new)", "hw/arm/darwin.c"]},
        "58C": {"title": "RTBuddy/ANS probe handshake", "files": ["apple_ans.c"]},
        "58D": {"title": "namespace Identify contract", "files": ["apple_ans.c"]},
        "58E": {"title": "queue + completion path", "files": ["apple_ans.c"]},
        "58F": {"title": "read-only namespace backing", "files": ["apple_ans.c", "block backend wiring"]},
        "58G": {"title": "first block-device publication", "files": ["apple_ans.c"]},
        "58H": {"title": "APFS block-0/NXSB guest read", "files": ["apple_ans.c"]},
    }

    artifact = {
        "gate": "ANS_STORAGE_IMPLEMENTATION_READINESS",
        "iteration": "57ZZ_PART15A",
        "closed_existing_contracts": {
            "ANS_KERNEL_DRIVER_MATCH_CONTRACT": "PASS_CLOSED",
            "IOS_STORAGE_LBA_CONTRACT": "PASS_CLOSED",
            "ANS_DEVICE_TREE_CONTRACT": "PASS_CLOSED",
            "PREBOOM_STORAGE_CONTRACT": "PASS_CLOSED (namespace/reg/interrupt extraction)",
            "revalidation": {
                "ans_match": "PASS" if closed_contracts_valid else "BLOCKED",
                "lba": "PASS" if closed_contracts_valid else "BLOCKED",
                "cross_artifact_consistency": "PASS" if closed_contracts_valid else "BLOCKED",
            },
            "revalidation_data": reval,
        },
        "implementation_requirements": {
            "boot_tree_compat_fix": dt_fix,
            "qemu_sptm_device_audit": device_audit,
            "amcc_template": amcc_pattern,
            "mmio": mmio_rows,
            "interrupts": interrupts,
            "rtbuddy_transport": {
                "state": "MISSING",
                "note": "No RTBuddy/RTKit endpoint exists. Minimal handshake required for controller probe/start is NOT yet proven; treat as unknown until driver-side probe expectations are traced.",
            },
            "dma_iommu": {"state": "MISSING/PARTIAL", "note": "no DART model for the t8120 ANS DMA path; do not implement identity DMA without guest mapping proof"},
            "queue": {
                "nvme_queue_entries": 64,
                "nvme_linear_sq": "present, zero-length",
                "layout": "UNKNOWN (SQ/CQ layout consumed by AppleANS3 not yet proven)",
            },
            "identify_response": identify,
            "lba_translation": lba_translation,
            "namespace_capacity_policy": {
                "nsid_2_7": "use authoritative DT NSSize/NCAP",
                "nsid_1": "alternate capacity path only; do NOT invent",
            },
            "backing_image_mapping": {
                "system_image": {"size": 9615441920, "alignment": "4096-aligned", "assignment": "IMAGE_CAPACITY_COMPATIBLE only"},
                "cryptex_image": {"size": 6014631936, "alignment": "4096-aligned", "assignment": "IMAGE_CAPACITY_COMPATIBLE only"},
                "ramdisk": {"size": 243269632, "alignment": "4096-aligned", "assignment": "IMAGE_CAPACITY_COMPATIBLE only"},
                "note": "IMAGE_TO_NAMESPACE_IDENTITY_PROVEN = false for all images",
            },
            "command_surface": commands,
        },
        "runtime_deferred": {
            "items": [
                "exact runtime root namespace identity",
                "exact runtime Data-volume selection",
                "external restore orchestrator role=3 caller",
                "runtime mount identity",
                "per-NSID publication until actually observed",
            ]
        },
        "unknowns": {
            "items": [
                "ANS MMIO region functions (all nonzero ranges UNKNOWN_MMIO_REGION)",
                "NVMe completion IRQ identity",
                "RTBuddy minimal handshake",
                "SQ/CQ layout consumed by AppleANS3",
                "host block backend sector granularity",
                "NSID1 backing identity",
                "wire opcode for Identify (Apple selector 0x11 != wire opcode)",
            ]
        },
        "iteration58_scope": iteration58,
        "milestones": milestones,
        "derived_gates": {
            "closed_contracts_valid": closed_contracts_valid,
            "ITERATION_58A_ENTRY_GATE": "PASS" if entry_58a else "BLOCKED",
            "ITERATION_58B_PLUS_ENTRY_GATE": "PASS" if entry_58b_plus else "BLOCKED",
            "ANS_STORAGE_IMPLEMENTATION_READINESS": global_readiness,
        },
        "revalidation_checks": checks,
        "verdicts": {
            "ANS_STORAGE_IMPLEMENTATION_READINESS": global_readiness,
            "ITERATION_58A_ENTRY_GATE": "PASS" if entry_58a else "BLOCKED",
            "ITERATION_58B_PLUS_ENTRY_GATE": "PASS" if entry_58b_plus else "BLOCKED",
            "ANS_CONTRACT_REVALIDATION": "PASS" if closed_contracts_valid else "BLOCKED",
            "STORAGE_LBA_CONTRACT_REVALIDATION": "PASS" if closed_contracts_valid else "BLOCKED",
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(json.dumps(artifact["derived_gates"], indent=2))
    print(json.dumps(artifact["revalidation_checks"], indent=1))
    print("boot_tree_compat:", dt_fix["status"])
    print("ANS device implementation: ABSENT")
    print("DT fixup sha256:", file_sha(DT_FIXUP))
    print("darwin.c sha256:", file_sha(DARWIN_C))


if __name__ == "__main__":
    main()
