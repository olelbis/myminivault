import base64
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

if importlib.util.find_spec("cryptography") is None:
    raise unittest.SkipTest("cryptography is not installed")

from decrypt_mymv import (
    decrypt_file,
    decrypt_recovery_file,
    decrypt_shared_token_file,
    parse_mymv2,
)


class ReferenceDecryptorPythonTest(unittest.TestCase):
    def write_fixture(self, name: str) -> Path:
        root = Path(__file__).resolve().parents[2]
        fixture = root / "internal" / "storage" / "testdata" / "compat" / name
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / name.removesuffix(".b64")
        path.write_bytes(base64.b64decode(fixture.read_text().strip()))
        return path

    def test_reads_go_compatibility_fixture(self):
        root = Path(__file__).resolve().parents[2]
        fixture = root / "tools" / "reference-decryptor" / "testdata" / "main-vault-v2.b64"
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault.db"
            vault.write_bytes(base64.b64decode(fixture.read_text().strip()))

            plaintext = decrypt_file(vault, b"fixture-password").decode()

        self.assertIn('"API_KEY": "fixture-secret"', plaintext)
        self.assertIn('"version": "fixture-v0"', plaintext)
        self.assertIn('"vault_id": "fixture-vault"', plaintext)

    def test_rejects_wrong_password(self):
        root = Path(__file__).resolve().parents[2]
        fixture = root / "tools" / "reference-decryptor" / "testdata" / "main-vault-v2.b64"
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault.db"
            vault.write_bytes(base64.b64decode(fixture.read_text().strip()))

            with self.assertRaises(Exception):
                decrypt_file(vault, b"wrong-password")

    def test_reads_recovery_hkdf_fixture(self):
        path = self.write_fixture("mymv-v2-recovery-hkdf.b64")
        key = b"compat-recovery-key-hkdf-000000"
        vault = json.loads(decrypt_recovery_file(path, key))
        self.assertEqual(vault["data"]["API_KEY"], "compat-recovery-hkdf-secret")
        self.assertEqual(vault["metadata"]["vault_id"], "compat-recovery-hkdf-vault")
        with self.assertRaises(Exception):
            decrypt_recovery_file(path, b"wrong-recovery-key")
        with self.assertRaises(ValueError):
            decrypt_file(path, key)

    def test_rejects_recovery_verifier_mismatch(self):
        wrong_verifier = base64.b64encode(b"x" * 32).decode()
        payload = json.dumps({"recovery": {"recovery_key_hash": wrong_verifier}}).encode()
        with patch("decrypt_mymv.decrypt_file_kind", return_value=payload):
            with self.assertRaisesRegex(ValueError, "verifier mismatch"):
                decrypt_recovery_file(Path("unused"), b"compat-recovery-key-hkdf-000000")

    def test_reads_shared_token_hkdf_fixture(self):
        path = self.write_fixture("mymv-v2-shared-token-hkdf.b64")
        key = b"0123456789abcdef0123456789abcdef"
        vault = json.loads(decrypt_shared_token_file(path, key))
        self.assertEqual(vault["data"]["TOKEN_KEY"], "compat-shared-hkdf-secret")
        self.assertEqual(vault["metadata"]["vault_id"], "compat-shared-hkdf-vault")
        with self.assertRaises(Exception):
            decrypt_shared_token_file(path, b"1123456789abcdef0123456789abcdef")
        with self.assertRaises(ValueError):
            decrypt_shared_token_file(path, key + b"\n")
        with self.assertRaises(ValueError):
            decrypt_recovery_file(path, key)

    def test_rejects_tampered_shared_token_aad(self):
        path = self.write_fixture("mymv-v2-shared-token-hkdf.b64")
        data = bytearray(path.read_bytes())
        aad = parse_mymv2(data)[3]
        data[len(aad) - 1] ^= 1
        path.write_bytes(data)
        with self.assertRaises(Exception):
            decrypt_shared_token_file(path, b"0123456789abcdef0123456789abcdef")


if __name__ == "__main__":
    unittest.main()
