import argparse
import base64
import hashlib
import json
import os
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

KOLY_SIZE = 512
RAW_TYPE = 0x00000001
TERM_TYPE = 0xFFFFFFFF


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_pattern(path: Path, size: int) -> None:
    state = 0xA5A55A5A
    block = bytearray(1024 * 1024)
    remaining = size
    absolute = 0
    with path.open("wb") as f:
        while remaining:
            n = min(len(block), remaining)
            for i in range(n):
                state ^= (state << 13) & 0xFFFFFFFF
                state ^= state >> 17
                state ^= (state << 5) & 0xFFFFFFFF
                state &= 0xFFFFFFFF
                block[i] = ((state >> 9) ^ (absolute + i)) & 0xFF
            f.write(block[:n])
            absolute += n
            remaining -= n


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


def parse_footer(path: Path):
    size = path.stat().st_size
    if size < KOLY_SIZE:
        raise AssertionError("DMG smaller than koly footer")

    with path.open("rb") as f:
        f.seek(size - KOLY_SIZE)
        footer = f.read(KOLY_SIZE)

    if footer[:4] != b"koly":
        raise AssertionError("invalid koly magic")

    version, header_size, flags = struct.unpack_from(">III", footer, 4)
    data_offset = struct.unpack_from(">Q", footer, 24)[0]
    data_length = struct.unpack_from(">Q", footer, 32)[0]
    xml_offset = struct.unpack_from(">Q", footer, 216)[0]
    xml_length = struct.unpack_from(">Q", footer, 224)[0]
    image_variant = struct.unpack_from(">I", footer, 488)[0]
    sector_count = struct.unpack_from(">Q", footer, 492)[0]

    assert version == 4
    assert header_size == 512
    assert flags & 1 == 1
    assert data_offset == 0
    assert data_length == sector_count * 512
    assert xml_offset == data_length
    assert xml_offset + xml_length <= size - KOLY_SIZE
    assert image_variant == 1

    return {
        "size": size,
        "data_offset": data_offset,
        "data_length": data_length,
        "xml_offset": xml_offset,
        "xml_length": xml_length,
        "sector_count": sector_count,
    }


def parse_mish_from_plist(path: Path, footer):
    with path.open("rb") as f:
        f.seek(footer["xml_offset"])
        xml = f.read(footer["xml_length"])

    root = plistlib.loads(xml)
    entries = root["resource-fork"]["blkx"]
    assert len(entries) == 1

    mish = entries[0]["Data"]
    if isinstance(mish, str):
        mish = base64.b64decode(mish)

    assert mish[:4] == b"mish"
    version = struct.unpack_from(">I", mish, 4)[0]
    sector_number = struct.unpack_from(">Q", mish, 8)[0]
    sector_count = struct.unpack_from(">Q", mish, 16)[0]
    data_offset = struct.unpack_from(">Q", mish, 24)[0]
    entry_count = struct.unpack_from(">I", mish, 200)[0]

    assert version == 1
    assert sector_number == 0
    assert sector_count == footer["sector_count"]
    assert data_offset == 0
    assert entry_count == 2
    assert len(mish) == 204 + 2 * 40

    raw = struct.unpack_from(">IIQQQQ", mish, 204)
    term = struct.unpack_from(">IIQQQQ", mish, 244)

    assert raw[0] == RAW_TYPE
    assert raw[2] == 0
    assert raw[3] == footer["sector_count"]
    assert raw[4] == 0
    assert raw[5] == footer["data_length"]

    assert term[0] == TERM_TYPE
    assert term[2] == footer["sector_count"]
    assert term[3] == 0
    assert term[4] == footer["data_length"]
    assert term[5] == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    tool = Path(args.tool).resolve()
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    raw = workdir / "oracle-source.raw"
    dmg = workdir / "oracle-output.dmg"
    restored = workdir / "oracle-restored.raw"
    corrupt = workdir / "oracle-corrupt.dmg"
    sentinel = workdir / "oracle-sentinel.raw"

    raw_size = 8 * 1024 * 1024
    write_pattern(raw, raw_size)

    enc = run(tool, "raw-to-udrw", str(raw), str(dmg))
    enc_json = json.loads(enc.stdout)
    assert enc_json["input_size"] == raw_size
    assert enc_json["sector_count"] == raw_size // 512
    assert enc_json["peak_buffer_bytes"] <= 2 * 1024 * 1024

    footer = parse_footer(dmg)
    parse_mish_from_plist(dmg, footer)

    with dmg.open("rb") as f:
        raw_fork = f.read(footer["data_length"])
    assert hashlib.sha256(raw_fork).hexdigest() == sha256(raw)

    inspect = run(tool, "inspect", str(dmg))
    info = json.loads(inspect.stdout)
    assert info["raw_data_fork"] is True
    assert info["data_fork_length"] == raw_size
    assert info["sector_count"] == raw_size // 512

    dec = run(tool, "udrw-to-raw", str(dmg), str(restored))
    dec_json = json.loads(dec.stdout)
    assert dec_json["output_size"] == raw_size
    assert dec_json["peak_buffer_bytes"] <= 2 * 1024 * 1024
    assert sha256(raw) == sha256(restored)

    data = bytearray(dmg.read_bytes())
    data[-KOLY_SIZE:-KOLY_SIZE + 4] = b"bad!"
    corrupt.write_bytes(data)
    sentinel.write_bytes(b"UNCHANGED")

    run(
        tool,
        "udrw-to-raw",
        str(corrupt),
        str(sentinel),
        expect_success=False,
    )
    assert sentinel.read_bytes() == b"UNCHANGED"

    print("UDIF_ORACLE_PASS")
    print(f"source_sha256={sha256(raw)}")
    print(f"dmg_sha256={sha256(dmg)}")
    print(f"restored_sha256={sha256(restored)}")
    print(f"sector_count={footer['sector_count']}")
    print(f"payload_bytes={raw_size}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
