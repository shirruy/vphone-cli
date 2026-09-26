import argparse
import hashlib
import json
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

KOLY_SIZE = 512
SECTOR = 512
ADC = 0x80000004
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


def deterministic_payload(size: int, chunk_size: int = 1024 * 1024) -> bytes:
    out = bytearray()
    chunk_index = 0
    while len(out) < size:
        pattern = bytes(
            ((i * 37) ^ (chunk_index * 29) ^ ((i >> 2) * 11) ^ 0x5A) & 0xFF
            for i in range(128)
        )
        remaining = min(chunk_size, size - len(out))
        chunk = (pattern * ((remaining + len(pattern) - 1) // len(pattern)))[:remaining]
        out += chunk
        chunk_index += 1
    return bytes(out)


def adc_encode_chunk(data: bytes) -> bytes:
    if not data:
        return b""

    encoded = bytearray()
    pos = 0
    used_two_byte = False

    first = min(128, len(data))
    encoded.append(0x80 | (first - 1))
    encoded += data[:first]
    pos = first

    while pos < len(data):
        remaining = len(data) - pos

        if pos >= 128 and not used_two_byte and remaining >= 3:
            count = min(18, remaining)
            offset = 127
            control = ((count - 3) << 2) | ((offset >> 8) & 0x03)
            encoded += bytes((control, offset & 0xFF))
            pos += count
            used_two_byte = True
            continue

        if pos >= 128 and remaining >= 4:
            count = min(67, remaining)
            offset = 127
            control = 0x40 | (count - 4)
            encoded += bytes((control, (offset >> 8) & 0xFF, offset & 0xFF))
            pos += count
            continue

        count = min(128, remaining)
        encoded.append(0x80 | (count - 1))
        encoded += data[pos : pos + count]
        pos += count

    return bytes(encoded)


def adc_reference_decode(data: bytes) -> bytes:
    out = bytearray()
    pos = 0

    while pos < len(data):
        control = data[pos]
        pos += 1

        if control & 0x80:
            count = (control & 0x7F) + 1
            if pos + count > len(data):
                raise ValueError("truncated ADC literal")
            out += data[pos : pos + count]
            pos += count
            continue

        if control & 0x40:
            count = (control & 0x3F) + 4
            if pos + 2 > len(data):
                raise ValueError("truncated ADC 3-byte back-reference")
            offset = (data[pos] << 8) | data[pos + 1]
            pos += 2
        else:
            count = ((control & 0x3F) >> 2) + 3
            if pos >= len(data):
                raise ValueError("truncated ADC 2-byte back-reference")
            offset = ((control & 0x03) << 8) | data[pos]
            pos += 1

        distance = offset + 1
        if distance > len(out):
            raise ValueError("ADC back-reference before start of output")

        for _ in range(count):
            out.append(out[-distance])

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


def make_udif(path: Path, raw: bytes, fault: str | None = None):
    chunk_size = 1024 * 1024
    data_fork = bytearray()
    runs = []

    for index, offset in enumerate(range(0, len(raw), chunk_size)):
        chunk = raw[offset : offset + chunk_size]
        if len(chunk) % SECTOR:
            raise ValueError("test payload must be sector aligned")

        compressed = bytearray(adc_encode_chunk(chunk))
        if adc_reference_decode(bytes(compressed)) != chunk:
            raise AssertionError("independent ADC encoder/reference decoder mismatch")

        if index == 0 and fault == "corrupt":
            compressed[0] = 0x00
        elif index == 0 and fault == "truncated":
            compressed = compressed[:-1]
        elif index == 0 and fault == "trailing":
            compressed += b"\x80\x00"

        start = len(data_fork)
        data_fork += compressed
        runs.append(
            (
                ADC,
                offset // SECTOR,
                len(chunk) // SECTOR,
                start,
                len(compressed),
            )
        )

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

    footer = build_koly(
        len(data_fork),
        len(data_fork),
        len(plist),
        len(raw) // SECTOR,
    )
    path.write_bytes(bytes(data_fork) + plist + footer)


def assert_fail_closed(tool: Path, dmg: Path, sentinel: Path):
    sentinel.write_bytes(b"UNCHANGED")
    run(tool, "dmg-to-raw", str(dmg), str(sentinel), expect_success=False)
    if sentinel.read_bytes() != b"UNCHANGED":
        raise AssertionError("failed ADC decode modified destination")


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
    dmg = workdir / "adc.dmg"
    restored = workdir / "restored.raw"
    corrupt = workdir / "corrupt-adc.dmg"
    truncated = workdir / "truncated-adc.dmg"
    trailing = workdir / "trailing-adc.dmg"
    sentinel = workdir / "sentinel.raw"

    source.write_bytes(raw)
    make_udif(dmg, raw)
    make_udif(corrupt, raw, fault="corrupt")
    make_udif(truncated, raw, fault="truncated")
    make_udif(trailing, raw, fault="trailing")

    inspect = run(tool, "inspect", str(dmg))
    info = json.loads(inspect.stdout)
    assert info["raw_data_fork"] is False
    assert info["sector_count"] == len(raw) // SECTOR

    decoded = run(tool, "dmg-to-raw", str(dmg), str(restored))
    result = json.loads(decoded.stdout)
    assert result["output_size"] == len(raw)
    assert result["sector_count"] == len(raw) // SECTOR
    assert result["peak_buffer_bytes"] <= 8 * 1024 * 1024
    assert sha256(source) == sha256(restored)

    assert_fail_closed(tool, corrupt, sentinel)
    assert_fail_closed(tool, truncated, sentinel)
    assert_fail_closed(tool, trailing, sentinel)

    print("UDIF_ADC_ORACLE_PASS")
    print("source_sha256=" + sha256(source))
    print("dmg_sha256=" + sha256(dmg))
    print("restored_sha256=" + sha256(restored))
    print("sector_count=" + str(len(raw) // SECTOR))
    print("payload_bytes=" + str(len(raw)))
    print("peak_buffer_bytes=" + str(result["peak_buffer_bytes"]))
    print("two_byte_backref=PASS")
    print("three_byte_backref=PASS")
    print("corrupt_adc_fail_closed=PASS")
    print("truncated_adc_fail_closed=PASS")
    print("trailing_adc_fail_closed=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
