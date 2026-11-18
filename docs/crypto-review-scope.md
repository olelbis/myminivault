# Crypto Review Scope

This document narrows the security-review target for myminivault. The project
is experimental and unaudited; the goal is to make a focused external review
possible in a short sitting.

## Suggested Review Question

Is the current local encrypted-vault design sound for an experimental
single-user CLI that uses Argon2id-derived AES-256-GCM keys for password-based
main-vault saves, HKDF-SHA256-derived AES-256-GCM keys for high-entropy recovery
and shared-token vault saves, authenticated cleartext container metadata, local
recovery snapshots, and local token access?

In particular, review:

- key derivation boundaries
- AES-GCM nonce and AAD usage
- encrypted file format parsing
- recovery-vault encryption
- shared-token-vault encryption
- legacy format compatibility
- failure behavior around tampered headers, wrong passwords, and interrupted saves

## Primary Files

These are the most important files for a first review:

| Area | Files |
| --- | --- |
| Encryption primitives | `internal/crypto/crypto.go` |
| KDF metadata policy | `internal/crypto/kdf_policy.go` |
| Container header and AAD | `internal/container/container.go` |
| Main vault load/save | `internal/storage/storage.go` |
| Recovery logic | `internal/recovery/recovery.go` |
| Token vault logic | `internal/token/token.go` |
| Shared-token import policy | `internal/sync/sync.go` |
| Data model | `internal/model/model.go` |

Supporting files:

| Area | Files |
| --- | --- |
| Runtime paths and no-follow helpers | `internal/paths/*` |
| Rollback warning state | `internal/rollback/*` |
| CLI orchestration | `cmd/vault/*` |
| Security model | `docs/security.md` |
| File format | `docs/format.md` |
| Review request | `docs/review-request.md` |
| Token sync policy | `docs/token-sync-policy.md` |
| Recovery policy | `docs/recovery-policy.md` |
| Rollback policy | `docs/rollback-policy.md` |
| Go reference decryptor | `tools/reference-decryptor/*` |
| Python reference decryptor | `tools/reference-decryptor-python/*` |

## Current Design Summary

- Master vault data is encrypted with AES-256-GCM.
- Main-vault encryption keys use Argon2id by default for new password-based saves. An explicit scrypt configuration can still write new main-vault files; scrypt also remains readable for compatibility.
- Recovery and shared-token vault encryption keys for new high-entropy-key saves are derived with HKDF-SHA256.
- Current encrypted files use a cleartext `MYMV` v2 header.
- The `MYMV` v2 header, metadata JSON, and salt are authenticated as AES-GCM
  additional authenticated data.
- The ciphertext layout is `nonce || ciphertext+tag`.
- The decrypted payload is `sha256(json_payload) || json_payload`.
- Recovery uses a separate encrypted recovery snapshot and a dedicated random
  recovery salt.
- Token commands use a local token master key to encrypt active read scopes and authorized pending writes. The same key exposes all retained token scopes; individual bearer tokens do not have separate encryption keys.
- New compact tokens are v3 HMAC-SHA256 tokens signed with a 32-byte HKDF-SHA256 subkey (empty salt, context `myminivault:compact-token-signing:v3`), separate from the shared-vault encryption context. Forged signatures are rejected before loading the shared vault. Six-field and v2 compact tokens are retired and rejected before key/vault access; owners must revoke and reissue them with the master password.
- Only marked, authorized writes are imported from current shared state. Usage is merged monotonically; tombstones block stale resurrection; durable interruption markers block stale token use. Restore/recovery and authenticated key rotation revoke grants. Keychain lifecycle tests use an injected store, not live OS ACL testing.
- Standalone Go and Python reference decryptors check MYMV v2 main-vault files
  with Argon2id or scrypt independently from the production loader. Both
  readers also check the existing HKDF recovery and shared-token fixtures,
  including the embedded recovery-key verifier. Both readers also check the
  existing MYMV v1 main-vault fixture with explicit fallback scrypt parameters.
  Neither reader covers headerless legacy files.

## Current Non-Goals

The project does not claim protection from:

- malware or arbitrary code execution as the same OS user
- a malicious or modified binary after the user enters credentials
- process memory inspection by the same user
- terminal capture, shell history, screenshots, or clipboard managers
- weak master passwords and offline guessing after encrypted file theft
- distributed multi-device sync conflicts
- audited password-manager-grade assurance

## Review Checklist

Reviewers should focus on whether:

- Argon2id, HKDF-SHA256, and scrypt compatibility metadata bounds are reasonable
- all AES-GCM decryptions use the same AAD that was authenticated at encryption
  time
- nonce generation is random and nonce reuse is unlikely under current save
  behavior
- container kind checks prevent opening one encrypted runtime file as another
  where that matters
- legacy parsing does not weaken current v2 files
- recovery file semantics are clearly equivalent to access to that recovery
  snapshot when paired with the recovery key
- token master-key compromise is documented and handled honestly
- interrupted-save recovery avoids making corruption worse
- docs accurately describe what is and is not protected

## Known Tradeoffs

- Go cannot guarantee full memory wiping of all secret copies.
- Current Linux token key storage is file-backed; macOS can use Keychain.
- Rollback detection warns by default and can block password-based commands when `rollback_mode` is `block`.
- Local sync metadata is best-effort and not a distributed merge model.
- Export and terminal display commands intentionally expose plaintext only when
  explicit flags are used.

## How To Ask For External Review

Suggested short post:

```text
I am looking for focused review of the crypto/file-format layer of an
experimental local Go CLI vault.

Scope: Argon2id for password-based main vaults, HKDF-SHA256 for high-entropy recovery/shared-token vaults, scrypt compatibility + AES-256-GCM, MYMV v2 header authenticated as AAD, recovery snapshot encryption, and shared token vault encryption.

Review docs:
- docs/format.md
- docs/crypto-review-scope.md
- docs/security.md

Primary code:
- internal/crypto
- internal/container
- internal/storage
- internal/recovery
- internal/token

I am especially interested in mistakes around AAD, KDF metadata validation,
HKDF context separation, legacy compatibility, recovery semantics, token
signature validation order, and interrupted-save behavior.
```
