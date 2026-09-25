import argparse
import hashlib
import json
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

import liblzfse

KOLY_SIZE = 512
SECTOR = 512
ZERO = 0x00000000
LZFSE = 0x80000007
BZIP2 = 0x80000006
TERM = 0xFFFFFFFF


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(tool: Path, *args: str, expect_success: bool = True):
    cp = subprocess.run(
        [str(tool), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if expect_success and cp.returncode != 0:
        raise RuntimeError(
            f"command failed: {tool} {' '.join(args)}\n"
            f"exit={cp.returncode}\nstdout={cp.stdout}\nstderr={cp.stderr}"
        )
    if not expect_success and cp.returncode == 0:
        raise RuntimeError(
            f"command unexpectedly succeeded: {tool} {' '.join(args)}"
        )
    return cp


def deterministic_payload(size: int) -> bytes:
    out = bytearray(size)
    state = 0xA5C31D97
    for i in range(size):
        state = (state * 1664525 + 1013904223 + i) & 0xFFFFFFFF
        if (i // (256 * 1024)) % 4 == 0:
            out[i] = (i // SECTOR) & 0xFF
        else:
            out[i] = (state ^ (state >> 9) ^ (i * 13)) & 0xFF
    out[: 1024 * 1024] = bytes(1024 * 1024)
    return bytes(out)


def checksum_none() -> bytes:
    return struct.pack(">II", 0, 0) + bytes(128)


def run_entry(kind, sector_number, sector_count, compressed_offset, compressed_length):
    return struct.pack(
        ">IIQQQQ",
        kind,
        0,
        sector_number,
        sector_count,
        compressed_offset,
        compressed_length,
    )


def build_mish(sector_count, data_fork, runs):
    header = bytearray()
    header += struct.pack(">IIQQQII", 0x6D697368, 1, 0, sector_count, 0, 520, 0xFFFFFFFE)
    header += struct.pack(">IIIIII", 0, 0, 0, 0, 0, 0)
    header += checksum_none()
    header += struct.pack(">I", len(runs) + 1)
    assert len(header) == 204

    body = bytearray()
    for run_def in runs:
        body += run_entry(*run_def)
    body += run_entry(TERM, sector_count, 0, len(data_fork), 0)
    return bytes(header + body)


def build_koly(data_fork_length, xml_offset, xml_length, sector_count):
    footer = bytearray(KOLY_SIZE)
    struct.pack_into(">IIII", footer, 0, 0x6B6F6C79, 4, 512, 1)
    struct.pack_into(">QQQQQ", footer, 16, 0, 0, data_fork_length, 0, 0)
    struct.pack_into(">QQ", footer, 216, xml_offset, xml_length)
    struct.pack_into(">I", footer, 488, 1)
    struct.pack_into(">Q", footer, 492, sector_count)
    return bytes(footer)


def make_udif(path: Path, raw: bytes, payload_type=LZFSE):
    chunk_size = 1024 * 1024
    data_fork = bytearray()
    runs = []

    for offset in range(0, len(raw), chunk_size):
        chunk = raw[offset : offset + chunk_size]
        sector_number = offset // SECTOR
        sector_count = len(chunk) // SECTOR

        if offset == 0:
            runs.append((ZERO, sector_number, sector_count, 0, 0))
            continue

        compressed = liblzfse.compress(chunk)
        if not compressed:
            raise RuntimeError("independent liblzfse encoder returned empty output")

        start = len(data_fork)
        data_fork += compressed
        runs.append((payload_type, sector_number, sector_count, start, len(compressed)))

    mish = build_mish(len(raw) // SECTOR, bytes(data_fork), runs)
    plist = plistlib.dumps(
        {
            "resource-fork": {
                "blkx": [
                    {
                        "Attributes": "0x0050",
                        "Data": mish,
                        "ID": "0",
                        "Name": "whole disk (unknown partition : 0)",
                        "CFName": "whole disk (unknown partition : 0)",
                    }
                ],
                "plst": [],
            }
        },
        fmt=plistlib.FMT_XML,
        sort_keys=False,
    )
    footer = build_koly(len(data_fork), len(data_fork), len(plist), len(raw) // SECTOR)
    path.write_bytes(bytes(data_fork) + plist + footer)


def corrupt_first_stream_magic(src: Path, dst: Path):
    data = bytearray(src.read_bytes())
    if len(data) < 8:
        raise RuntimeError("compressed fixture unexpectedly small")
    data[0] ^= 0xFF
    dst.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    tool = Path(args.tool).resolve()
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    raw = deterministic_payload(12 * 1024 * 1024)
    source = workdir / "source.raw"
    dmg = workdir / "lzfse.dmg"
    restored = workdir / "restored.raw"
    corrupt = workdir / "corrupt-lzfse.dmg"
    unsupported = workdir / "unsupported-bzip2.dmg"
    sentinel = workdir / "sentinel.raw"

    source.write_bytes(raw)
    make_udif(dmg, raw)

    inspect = run(tool, "inspect", str(dmg))
    info = json.loads(inspect.stdout)
    assert info["raw_data_fork"] is False
    assert info["sector_count"] == len(raw) // SECTOR

    decoded = run(tool, "dmg-to-raw", str(dmg), str(restored))
    result = json.loads(decoded.stdout)
    assert result["output_size"] == len(raw)
    assert result["sector_count"] == len(raw) // SECTOR
    assert result["peak_buffer_bytes"] <= 80 * 1024 * 1024
    assert sha256(source) == sha256(restored)

    corrupt_first_stream_magic(dmg, corrupt)
    sentinel.write_bytes(b"UNCHANGED")
    run(tool, "dmg-to-raw", str(corrupt), str(sentinel), expect_success=False)
    assert sentinel.read_bytes() == b"UNCHANGED"

    make_udif(unsupported, raw, payload_type=BZIP2)
    sentinel.write_bytes(b"UNCHANGED")
    run(tool, "dmg-to-raw", str(unsupported), str(sentinel), expect_success=False)
    assert sentinel.read_bytes() == b"UNCHANGED"

    print("UDIF_LZFSE_ORACLE_PASS")
    print("source_sha256=" + sha256(source))
    print("dmg_sha256=" + sha256(dmg))
    print("restored_sha256=" + sha256(restored))
    print("sector_count=" + str(len(raw) // SECTOR))
    print("payload_bytes=" + str(len(raw)))
    print("peak_buffer_bytes=" + str(result["peak_buffer_bytes"]))
    print("corrupt_lzfse_fail_closed=PASS")
    print("unsupported_bzip2_fail_closed=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
