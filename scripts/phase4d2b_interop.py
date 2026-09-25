import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from aea import aea


def deterministic_payload(size: int) -> bytes:
    out = bytearray(size)
    state = 0x6D2B79F5
    for i in range(size):
        state = (state * 1664525 + 1013904223 + i) & 0xFFFFFFFF
        if i < size // 3:
            out[i] = ord("A") + (i % 4)
        else:
            out[i] = (state ^ (state >> 13) ^ (i * 17)) & 0xFF
    return bytes(out)


def run(cmd):
    print("+", " ".join(str(x) for x in cmd), flush=True)
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with exit code {result.returncode}")
    return result


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--workdir", required=True)
    args = parser.parse_args()

    tool = Path(args.tool).resolve()
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    source = workdir / "source.bin"
    cpp_archive = workdir / "cpp-generated.aea"
    cpp_restored = workdir / "cpp-restored.bin"
    py_archive = workdir / "python-generated.aea"

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9bacbdcedfe0f"
    )
    key_hex = key.hex()
    auth = b"vphone-independent-aea-interoperability"
    auth_hex = auth.hex()

    cluster_size = 0x4000 * 32
    payload = deterministic_payload(cluster_size * 2 + 32117)
    source.write_bytes(payload)

    # Direction 1: native Windows encoder -> independent Python decoder.
    run([
        str(tool),
        "encrypt",
        str(source),
        str(cpp_archive),
        key_hex,
        auth_hex,
        "0x4000",
        "32",
    ])

    decoded_by_python = aea.decode(
        cpp_archive.read_bytes(),
        symmetric_key=key,
    )

    if decoded_by_python != payload:
        raise RuntimeError("independent Python decoder did not reproduce C++ plaintext")

    # Direction 2: independent Python encoder -> native Windows decoder.
    encoded_by_python = aea.encode(
        payload,
        symmetric_key=key,
        auth_data=auth,
        segment_size=0x4000,
        segments_per_cluster=32,
        checksum_algorithm=aea.ChecksumAlgorithm.SHA256,
        compression_algorithm=aea.CompressionAlgorithm.LZFSE,
    )
    py_archive.write_bytes(encoded_by_python)

    run([
        str(tool),
        "decrypt",
        str(py_archive),
        str(cpp_restored),
        key_hex,
    ])

    if cpp_restored.read_bytes() != payload:
        raise RuntimeError("native Windows decoder did not reproduce Python plaintext")

    print("AEA_INTEROP_PASS")
    print("source_sha256=" + sha256(source))
    print("cpp_archive_sha256=" + sha256(cpp_archive))
    print("python_archive_sha256=" + sha256(py_archive))
    print("payload_bytes=" + str(len(payload)))


if __name__ == "__main__":
    main()
