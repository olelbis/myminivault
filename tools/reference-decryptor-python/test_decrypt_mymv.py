import base64
import importlib.util
import tempfile
import unittest
from pathlib import Path

if importlib.util.find_spec("cryptography") is None:
    raise unittest.SkipTest("cryptography is not installed")

from decrypt_mymv import decrypt_file


class ReferenceDecryptorPythonTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
