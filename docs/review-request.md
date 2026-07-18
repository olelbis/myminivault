# Request For Focused Crypto And File-Format Review

myminivault is an experimental local CLI vault written in Go. It is not audited
and is not presented as a production password manager.

This page is a ready-to-share request for focused review of the small part of
the project that handles encryption, file containers, recovery snapshots, and
token-vault storage.

## Review Request

I am looking for focused review of the crypto/file-format layer of myminivault,
an experimental single-user local CLI vault written in Go.

Scope:

- scrypt + AES-256-GCM
- `MYMV` v2 cleartext header authenticated as AES-GCM AAD
- encrypted main-vault payload format
- recovery snapshot encryption
- shared token vault encryption
- legacy format compatibility
- interrupted-save behavior

I am especially interested in mistakes around:

- AAD construction and validation
- KDF metadata parsing and bounds
- AES-GCM nonce handling
- container kind separation
- recovery semantics
- token-vault separation
- legacy compatibility paths
- docs that overclaim or understate risk

## Best Starting Points

Review docs:

- [Encrypted File Format](format.md)
- [Crypto Review Scope](crypto-review-scope.md)
- [Security Model And Threat Model](security.md)
- [Recovery Policy](recovery-policy.md)
- [Token Sync Policy](token-sync-policy.md)
- [Rollback Policy](rollback-policy.md)

Primary code:

- `internal/crypto`
- `internal/container`
- `internal/storage`
- `internal/recovery`
- `internal/token`
- `internal/sync`
- `internal/model`

Reference readers:

- `tools/reference-decryptor`
- `tools/reference-decryptor-python`
- `tools/reference-decryptor/testdata/main-vault-v2.b64`

## How To Report Feedback

For non-sensitive review comments, open a public GitHub issue using the
`Focused crypto review` issue template.

For vulnerabilities with exploitable details, use GitHub private security
advisories instead of public issues:

```text
https://github.com/olelbis/myminivault/security/advisories/new
```

Please do not attach real vault files, recovery keys, compact tokens, passwords,
or secret values.

Valid findings can be publicly credited in the README or release notes unless
the reporter prefers to remain anonymous.

## Short External Post

```text
I am looking for focused review of the crypto/file-format layer of myminivault,
an experimental local Go CLI vault.

Scope:
- scrypt + AES-256-GCM
- MYMV v2 cleartext header authenticated as AES-GCM AAD
- encrypted main-vault payload format
- recovery snapshot encryption
- shared token vault encryption
- legacy format compatibility

Docs:
- docs/format.md
- docs/crypto-review-scope.md
- docs/security.md

Reference readers:
- tools/reference-decryptor
- tools/reference-decryptor-python
- tools/reference-decryptor/testdata/main-vault-v2.b64

I am especially interested in mistakes around AAD usage, KDF metadata
validation, nonce handling, file-format parsing, recovery semantics,
token-vault separation, and interrupted-save behavior.
```
