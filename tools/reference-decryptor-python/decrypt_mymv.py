#!/usr/bin/env python3
"""Standalone MYMV v1/v2 main, recovery, and shared-token vault decryptor.

This script is a Python reading companion to docs/format.md. It intentionally
does not call the myminivault Go code. AES-GCM support requires:

    python3 -m pip install cryptography
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover - exercised only without dependency
    raise SystemExit(
        "missing dependency: install with `python3 -m pip install cryptography`"
    ) from exc

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:  # pragma: no cover - depends on installed cryptography version
    Argon2id = None


MAGIC = b"MYMV"
VERSION = 2
LEGACY_VERSION = 1
HEADER_SIZE = 8
SALT_SIZE = 16
NONCE_SIZE = 12
CHECKSUM_SIZE = 32
KIND_MAIN_VAULT = 1
KIND_RECOVERY_VAULT = 2
KIND_SHARED_TOKEN = 3


def decrypt_file(path: Path, password: bytes) -> bytes:
    return decrypt_file_kind(path, password, KIND_MAIN_VAULT)


def decrypt_v1_main_file(path: Path, password: bytes, n: int, r: int, p: int) -> bytes:
    data = path.read_bytes()
    if len(data) < HEADER_SIZE + SALT_SIZE + NONCE_SIZE:
        raise ValueError("MYMV v1 container too short")
    if data[:4] != MAGIC or data[4] != LEGACY_VERSION or data[5] != KIND_MAIN_VAULT or data[6:8] != b"\0\0":
        raise ValueError("expected MYMV v1 main vault header")
    salt = data[HEADER_SIZE : HEADER_SIZE + SALT_SIZE]
    key = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=32)
    # MYMV v1 has no authenticated header; AES-GCM authenticates only its payload.
    return strip_checksum(decrypt_payload(data[HEADER_SIZE + SALT_SIZE :], key, None))


def decrypt_recovery_file(path: Path, recovery_key: bytes) -> bytes:
    plaintext = decrypt_file_kind(path, recovery_key, KIND_RECOVERY_VAULT)
    vault = json.loads(plaintext)
    recovery = vault.get("recovery")
    if not isinstance(recovery, dict) or not isinstance(recovery.get("recovery_key_hash"), str):
        raise ValueError("missing recovery key verifier")
    # Recovery keys contain 32 random bytes; this matches the stored verifier.
    expected = base64.b64decode(recovery["recovery_key_hash"], validate=True)
    if not hmac.compare_digest(expected, hashlib.sha256(recovery_key).digest()):
        raise ValueError("recovery key verifier mismatch")
    return plaintext


def decrypt_shared_token_file(path: Path, token_master_key: bytes) -> bytes:
    if len(token_master_key) != 32:
        raise ValueError("token master key must be exactly 32 bytes")
    return decrypt_file_kind(path, token_master_key, KIND_SHARED_TOKEN)


def decrypt_file_kind(path: Path, key_material: bytes, expected_kind: int) -> bytes:
    data = path.read_bytes()
    kind, salt, ciphertext, aad, metadata = parse_mymv2(data)
    if kind != expected_kind:
        raise ValueError(f"unsupported container kind {kind}: expected {expected_kind}")
    if kind == KIND_MAIN_VAULT and metadata["kdf"] == "hkdf-sha256":
        raise ValueError("HKDF is not supported for main vaults")
    if kind in (KIND_RECOVERY_VAULT, KIND_SHARED_TOKEN) and metadata["kdf"] != "hkdf-sha256":
        raise ValueError("reference tool supports only HKDF recovery and shared-token vaults")

    key = derive_key(key_material, salt, metadata, kind)
    return strip_checksum(decrypt_payload(ciphertext, key, aad))


def derive_key(key_material: bytes, salt: bytes, metadata: dict[str, object], kind: int) -> bytes:
    if metadata["kdf"] == "argon2id":
        if Argon2id is None:
            raise ValueError("installed cryptography package does not provide Argon2id")
        return Argon2id(
            salt=salt,
            length=metadata["key_size"],
            iterations=metadata["argon2_time"],
            lanes=metadata["argon2_threads"],
            memory_cost=metadata["argon2_memory_kib"],
        ).derive(key_material)
    if metadata["kdf"] == "hkdf-sha256":
        info = b"myminivault:recovery-vault"
        if kind == KIND_SHARED_TOKEN:
            info = b"myminivault:shared-token-vault"
        return HKDF(
            algorithm=hashes.SHA256(),
            length=metadata["key_size"],
            salt=salt,
            info=info,
        ).derive(key_material)
    return hashlib.scrypt(
        key_material,
        salt=salt,
        n=metadata["scrypt_n"],
        r=metadata["scrypt_r"],
        p=metadata["scrypt_p"],
        dklen=metadata["key_size"],
    )


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
        "salt_size": SALT_SIZE,
        "nonce_size": NONCE_SIZE,
        "key_size": 32,
        "payload": "sha256-prefix-json",
        "ciphertext_layout": "nonce-prefixed",
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f"unsupported metadata {key}={metadata.get(key)!r}")
    if metadata.get("kdf") == "argon2id":
        if not isinstance(metadata.get("argon2_memory_kib"), int) or not (
            19 * 1024 <= metadata["argon2_memory_kib"] <= 256 * 1024
        ):
            raise ValueError("invalid argon2_memory_kib")
        if not isinstance(metadata.get("argon2_time"), int) or not (1 <= metadata["argon2_time"] <= 8):
            raise ValueError("invalid argon2_time")
        if not isinstance(metadata.get("argon2_threads"), int) or not (1 <= metadata["argon2_threads"] <= 8):
            raise ValueError("invalid argon2_threads")
    elif metadata.get("kdf") == "scrypt":
        for key in ("scrypt_n", "scrypt_r", "scrypt_p"):
            if not isinstance(metadata.get(key), int) or metadata[key] < 1:
                raise ValueError(f"invalid {key}")
    elif metadata.get("kdf") == "hkdf-sha256":
        pass
    else:
        raise ValueError(f"unsupported metadata kdf={metadata.get('kdf')!r}")


def decrypt_payload(ciphertext: bytes, key: bytes, aad: bytes | None) -> bytes:
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
    parser = argparse.ArgumentParser(description="decrypt a MYMV v2 main, recovery, or shared-token vault")
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--password-file")
    key_group.add_argument("--recovery-key-file")
    key_group.add_argument("--token-key-file")
    parser.add_argument("--legacy-scrypt-n", type=int)
    parser.add_argument("--legacy-scrypt-r", type=int)
    parser.add_argument("--legacy-scrypt-p", type=int)
    parser.add_argument("vault")
    args = parser.parse_args()

    legacy_params = (args.legacy_scrypt_n, args.legacy_scrypt_r, args.legacy_scrypt_p)
    legacy_requested = any(value is not None for value in legacy_params)
    if legacy_requested and (
        not args.password_file or any(value is None or value < 1 for value in legacy_params)
        or args.legacy_scrypt_n < 2
    ):
        parser.error("MYMV v1 requires --password-file and positive --legacy-scrypt-n, --legacy-scrypt-r, and --legacy-scrypt-p")

    if args.token_key_file:
        key_material = Path(args.token_key_file).read_bytes()
        plaintext = decrypt_shared_token_file(Path(args.vault), key_material)
    elif args.recovery_key_file:
        key_material = Path(args.recovery_key_file).read_bytes().rstrip(b"\r\n")
        plaintext = decrypt_recovery_file(Path(args.vault), key_material)
    else:
        key_material = Path(args.password_file).read_bytes().rstrip(b"\r\n")
        if legacy_requested:
            plaintext = decrypt_v1_main_file(Path(args.vault), key_material, *legacy_params)
        else:
            plaintext = decrypt_file(Path(args.vault), key_material)
    sys.stdout.buffer.write(plaintext + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
