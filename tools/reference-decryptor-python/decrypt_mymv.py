#!/usr/bin/env python3
"""Standalone MYMV v2 main-vault decryptor.

This script is a Python reading companion to docs/format.md. It intentionally
does not call the myminivault Go code. AES-GCM support requires:

    python3 -m pip install cryptography
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover - exercised only without dependency
    raise SystemExit(
        "missing dependency: install with `python3 -m pip install cryptography`"
    ) from exc


MAGIC = b"MYMV"
VERSION = 2
HEADER_SIZE = 8
SALT_SIZE = 16
NONCE_SIZE = 12
CHECKSUM_SIZE = 32


def decrypt_file(path: Path, password: bytes) -> bytes:
    data = path.read_bytes()
    kind, salt, ciphertext, aad, metadata = parse_mymv2(data)
    if kind != 1:
        raise ValueError(f"unsupported container kind {kind}: expected main vault")

    key = hashlib.scrypt(
        password,
        salt=salt,
        n=metadata["scrypt_n"],
        r=metadata["scrypt_r"],
        p=metadata["scrypt_p"],
        dklen=metadata["key_size"],
    )
    return strip_checksum(decrypt_payload(ciphertext, key, aad))


def parse_mymv2(data: bytes) -> tuple[int, bytes, bytes, bytes, dict[str, object]]:
    if len(data) < HEADER_SIZE + SALT_SIZE:
        raise ValueError("container too short")
    if data[:4] != MAGIC:
        raise ValueError("missing MYMV magic")
    if data[4] != VERSION:
        raise ValueError(f"unsupported MYMV version {data[4]}")

    kind = data[5]
    metadata_len = struct.unpack(">H", data[6:8])[0]
    payload_offset = HEADER_SIZE + metadata_len
    if len(data) < payload_offset + SALT_SIZE:
        raise ValueError("container metadata or salt truncated")

    metadata = json.loads(data[HEADER_SIZE:payload_offset])
    validate_metadata(metadata)

    aad_end = payload_offset + SALT_SIZE
    return kind, data[payload_offset:aad_end], data[aad_end:], data[:aad_end], metadata


def validate_metadata(metadata: dict[str, object]) -> None:
    expected = {
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "salt_size": SALT_SIZE,
        "nonce_size": NONCE_SIZE,
        "key_size": 32,
        "payload": "sha256-prefix-json",
        "ciphertext_layout": "nonce-prefixed",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"unsupported metadata {key}={metadata.get(key)!r}")
    for key in ("scrypt_n", "scrypt_r", "scrypt_p"):
        if not isinstance(metadata.get(key), int) or metadata[key] < 1:
            raise ValueError(f"invalid {key}")


def decrypt_payload(ciphertext: bytes, key: bytes, aad: bytes) -> bytes:
    if len(ciphertext) < NONCE_SIZE:
        raise ValueError("ciphertext too short")
    nonce = ciphertext[:NONCE_SIZE]
    encrypted = ciphertext[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, encrypted, aad)


def strip_checksum(payload: bytes) -> bytes:
    if len(payload) <= CHECKSUM_SIZE:
        raise ValueError("payload too short")
    expected = payload[:CHECKSUM_SIZE]
    plaintext = payload[CHECKSUM_SIZE:]
    actual = hashlib.sha256(plaintext).digest()
    if expected != actual:
        raise ValueError("checksum failed")
    return plaintext


def main() -> int:
    parser = argparse.ArgumentParser(description="decrypt a MYMV v2 main vault")
    parser.add_argument("--password-file", required=True)
    parser.add_argument("vault")
    args = parser.parse_args()

    password = Path(args.password_file).read_bytes().rstrip(b"\r\n")
    plaintext = decrypt_file(Path(args.vault), password)
    sys.stdout.buffer.write(plaintext + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
