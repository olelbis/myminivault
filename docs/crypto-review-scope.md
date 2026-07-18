# Crypto Review Scope

This document narrows the security-review target for myminivault. The project
is experimental and unaudited; the goal is to make a focused external review
possible in a short sitting.

## Suggested Review Question

Is the current local encrypted-vault design sound for an experimental
single-user CLI that uses scrypt-derived AES-256-GCM keys, authenticated
cleartext container metadata, local recovery snapshots, and local token access?

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
| Token sync policy | `docs/token-sync-policy.md` |
| Recovery policy | `docs/recovery-policy.md` |
| Rollback policy | `docs/rollback-policy.md` |

## Current Design Summary

- Master vault data is encrypted with AES-256-GCM.
- Encryption keys are derived with scrypt.
- Current encrypted files use a cleartext `MYMV` v2 header.
- The `MYMV` v2 header, metadata JSON, and salt are authenticated as AES-GCM
  additional authenticated data.
- The ciphertext layout is `nonce || ciphertext+tag`.
- The decrypted payload is `sha256(json_payload) || json_payload`.
- Recovery uses a separate encrypted recovery snapshot and a dedicated random
  recovery salt.
- Token commands use a local token master key to encrypt the shared token vault.
- Token writes are staged in `shared-token-vault.json` and imported into
  `vault.db` by master-password commands or `vault sync-tokens`.

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

- scrypt parameters and metadata bounds are reasonable
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
- Rollback detection is warning-based, not strict blocking.
- Local sync metadata is best-effort and not a distributed merge model.
- Export and terminal display commands intentionally expose plaintext only when
  explicit flags are used.

## How To Ask For External Review

Suggested short post:

```text
I am looking for focused review of the crypto/file-format layer of an
experimental local Go CLI vault.

Scope: scrypt + AES-256-GCM, MYMV v2 header authenticated as AAD, recovery
snapshot encryption, and shared token vault encryption.

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
legacy compatibility, recovery semantics, and interrupted-save behavior.
```
