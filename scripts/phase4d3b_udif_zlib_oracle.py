import argparse
import hashlib
import json
import plistlib
import struct
import subprocess
import sys
import zlib
from pathlib import Path

KOLY_SIZE = 512
SECTOR = 512
ZERO = 0x00000000
ADC = 0x80000004
ZLIB = 0x80000005
TERM = 0xFFFFFFFF


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
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


def pattern_bytes(size: int) -> bytes:
    out = bytearray(size)
    state = 0x13579BDF
    for i in range(size):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        if (i // (256 * 1024)) % 3 == 0:
            out[i] = (i // SECTOR) & 0xFF
        else:
            out[i] = ((state >> 11) ^ i) & 0xFF
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
    for run in runs:
        body += run_entry(*run)
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


def make_udif(path: Path, raw: bytes, override_first_payload_type=None):
    assert len(raw) % SECTOR == 0
    chunk_size = 1024 * 1024
    data_fork = bytearray()
    runs = []
    payload_run_index = 0

    for offset in range(0, len(raw), chunk_size):
        chunk = raw[offset : offset + chunk_size]
        sector_number = offset // SECTOR
        sector_count = len(chunk) // SECTOR

        if offset == 0:
            runs.append((ZERO, sector_number, sector_count, 0, 0))
            continue

        compressed = zlib.compress(chunk, level=6)
        start = len(data_fork)
        data_fork += compressed
        kind = ZLIB
        if override_first_payload_type is not None and payload_run_index == 0:
            kind = override_first_payload_type
        payload_run_index += 1
        runs.append((kind, sector_number, sector_count, start, len(compressed)))

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


def corrupt_first_zlib_payload(src: Path, dst: Path):
    data = bytearray(src.read_bytes())
    if len(data) < 8192:
        raise AssertionError("fixture unexpectedly small")
    data[1024] ^= 0x7F
    dst.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    tool = Path(args.tool).resolve()
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    raw_bytes = bytearray(pattern_bytes(12 * 1024 * 1024))
    raw_bytes[: 1024 * 1024] = bytes(1024 * 1024)
    raw = bytes(raw_bytes)
    raw_path = workdir / "source.raw"
    dmg = workdir / "compressed.dmg"
    restored = workdir / "restored.raw"
    corrupt = workdir / "corrupt.dmg"
    unsupported = workdir / "unsupported-adc.dmg"
    sentinel = workdir / "sentinel.raw"

    raw_path.write_bytes(raw)
    make_udif(dmg, raw)

    inspect = run(tool, "inspect", str(dmg))
    info = json.loads(inspect.stdout)
    assert info["raw_data_fork"] is False
    assert info["sector_count"] == len(raw) // SECTOR

    decode = run(tool, "dmg-to-raw", str(dmg), str(restored))
    result = json.loads(decode.stdout)
    assert result["output_size"] == len(raw)
    assert result["sector_count"] == len(raw) // SECTOR
    assert result["peak_buffer_bytes"] <= 20 * 1024 * 1024
    assert sha256(raw_path) == sha256(restored)

    corrupt_first_zlib_payload(dmg, corrupt)
    sentinel.write_bytes(b"UNCHANGED")
    run(tool, "dmg-to-raw", str(corrupt), str(sentinel), expect_success=False)
    assert sentinel.read_bytes() == b"UNCHANGED"

    make_udif(unsupported, raw, override_first_payload_type=ADC)
    sentinel.write_bytes(b"UNCHANGED")
    run(tool, "dmg-to-raw", str(unsupported), str(sentinel), expect_success=False)
    assert sentinel.read_bytes() == b"UNCHANGED"

    print("UDIF_ZLIB_ORACLE_PASS")
    print(f"source_sha256={sha256(raw_path)}")
    print(f"dmg_sha256={sha256(dmg)}")
    print(f"restored_sha256={sha256(restored)}")
    print(f"sector_count={len(raw) // SECTOR}")
    print(f"payload_bytes={len(raw)}")
    print(f"peak_buffer_bytes={result['peak_buffer_bytes']}")
    print("corrupt_zlib_fail_closed=PASS")
    print("unsupported_adc_fail_closed=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
