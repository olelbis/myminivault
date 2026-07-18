# myminivault Encrypted File Format

This document describes the encrypted runtime file format used by current
myminivault releases. Its goal is to make the format reviewable without reading
the whole CLI.

myminivault is still experimental and unaudited. Treat this document as the
current implementation contract, not as a formal long-term standard.

## Runtime Files

Current releases write three encrypted vault-like runtime files:

| File | Container kind | Key material |
| --- | --- | --- |
| `vault.db` | `main-vault` | master password |
| `vault.db.recovery` | `recovery-vault` | printed recovery key |
| `shared-token-vault.json` | `shared-token-vault` | local token master key |

Older backups such as `vault.db.bak` and `shared-token-vault.json.bak` use the
same format as the file they back up.

The default runtime directory is `~/.myminivault/`. `MYMINIVAULT_HOME` can point
the CLI at a different runtime directory.

## Current Container: `MYMV` v2

Current saves use a cleartext container header followed by authenticated
ciphertext.

```text
offset  size      field
0       4         magic bytes: "MYMV"
4       1         container version: 0x02
5       1         container kind
6       2         metadata JSON length, unsigned big-endian
8       N         metadata JSON
8+N     16        salt
8+N+16  rest      ciphertext payload
```

Container kind values:

| Value | Meaning |
| --- | --- |
| `1` | main vault |
| `2` | recovery vault |
| `3` | shared token vault |

The header, metadata JSON, and salt are AES-GCM additional authenticated data
(AAD). They are not encrypted, but changing any byte in that cleartext context
causes decryption to fail.

## Metadata JSON

The v2 metadata JSON contains non-sensitive crypto and layout information:

```json
{
  "algorithm": "AES-256-GCM",
  "kdf": "scrypt",
  "scrypt_n": 32768,
  "scrypt_r": 8,
  "scrypt_p": 1,
  "key_size": 32,
  "salt_size": 16,
  "nonce_size": 12,
  "payload": "sha256-prefix-json",
  "ciphertext_layout": "nonce-prefixed"
}
```

Load paths validate the algorithm, KDF, payload layout, nonce size, and bounded
scrypt parameters before deriving keys from v2 metadata.

Metadata must not contain stored keys, values, recovery metadata, compact
tokens, token secrets, or encrypted vault metadata.

## Key Derivation

All current encrypted runtime files use scrypt.

Default parameters:

| Parameter | Value |
| --- | --- |
| `N` | `32768` |
| `r` | `8` |
| `p` | `1` |
| key size | `32` bytes |
| salt size | `16` bytes |

Key inputs differ by file:

- `vault.db`: UTF-8 bytes of the master password read by the CLI
- `vault.db.recovery`: bytes of the recovery key entered by the user
- `shared-token-vault.json`: 32-byte token master key from macOS Keychain or `vault-token.key`

The derived 32-byte key is used directly as the AES-256-GCM key.

## Ciphertext Layout

The encrypted payload uses AES-256-GCM with a random 12-byte nonce.

The ciphertext field stored after the salt is:

```text
nonce || AES-GCM-seal(plaintext, aad)
```

Where:

- `nonce` is 12 random bytes
- `aad` is the v2 cleartext container context: fixed header, metadata JSON, and salt
- `AES-GCM-seal` returns encrypted bytes plus the GCM authentication tag

## Plaintext Payload

After successful AES-GCM authentication and decryption, the plaintext payload is:

```text
sha256(json_payload) || json_payload
```

The first 32 bytes are the SHA-256 checksum of the remaining JSON payload. This
checksum is verified after decryption. AES-GCM is the primary authenticity
mechanism; the checksum is an additional corruption guard around serialized
payloads.

The JSON payload is an `ExtendedVault` object:

```json
{
  "data": {
    "API_KEY": "secret-value"
  },
  "recovery": {
    "recovery_key_hash": "...",
    "created_at": "2026-07-18T00:00:00Z",
    "use_count": 0
  },
  "token_manager": {
    "tokens": {},
    "secret_key": "..."
  },
  "sync": {
    "updated_at": {},
    "deleted_at": {}
  },
  "metadata": {
    "version": "0.12.18",
    "created_at": "2026-07-18T00:00:00Z",
    "last_access": "2026-07-18T00:00:00Z",
    "access_count": 1,
    "vault_id": "...",
    "revision": 1
  }
}
```

Optional fields may be absent. `data` is initialized to an empty object when it
is missing.

## Legacy Formats

myminivault can still read older encrypted files:

- headerless legacy files: `salt || ciphertext`
- `MYMV` v1 files: fixed header plus `salt || ciphertext`, without structured metadata

Legacy and v1 files use the runtime fallback crypto configuration instead of
authenticated metadata from the file. When an older file is saved again, current
releases rewrite it as `MYMV` v2.

Legacy plaintext payloads may be either:

- the current `ExtendedVault` JSON object
- an older plain JSON object mapping string keys to string values

The older key/value map is upgraded in memory to the current vault structure
when loaded.

## Review-Relevant Invariants

- The cleartext v2 header identifies format version and container kind only.
- The v2 header, metadata JSON, and salt are authenticated as AES-GCM AAD.
- The file kind must match the loader expectation.
- Unsupported algorithms, KDFs, payload layouts, nonce sizes, or out-of-bounds
  scrypt parameters fail before decryption.
- Nonces are generated with `crypto/rand`.
- Main-vault saves use a transaction marker, restrictive temp file creation,
  directory sync, `.bak` preservation, and atomic rename.
- A valid recovery key plus matching `vault.db.recovery` is sufficient to
  recover the recovery snapshot.
- A valid token master key plus `shared-token-vault.json` is sufficient to read
  the shared token vault.

## Non-Goals

The format does not attempt to hide that a file is a myminivault encrypted
container, which kind of container it is, or which KDF parameters are needed to
open it.

The format does not protect against a compromised binary, malware running as the
same OS user, terminal capture, process memory inspection, weak master
passwords, or theft of both an encrypted recovery file and its valid recovery
key.
