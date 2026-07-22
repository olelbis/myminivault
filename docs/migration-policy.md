# Migration Policy

myminivault keeps encrypted runtime files readable across format changes when
that can be done safely and with clear tests. This document is a skeleton for
future `vault migrate` work and for deciding when old compatibility paths can be
removed.

## Current Supported Formats

| Format | Read support | Write support | Notes |
| --- | --- | --- | --- |
| legacy salt-plus-ciphertext | yes | no | Rewritten as `MYMV` v2 after a normal save. |
| `MYMV` v1 | yes | no | Older headered format without structured metadata. |
| `MYMV` v2 | yes | yes | Current format with authenticated metadata and salt as AES-GCM AAD. |

Current saves always write `MYMV` v2.

## Compatibility Fixtures

The compatibility fixture corpus lives in
`internal/storage/testdata/compat/`.

Current fixture coverage:

- legacy salt-plus-ciphertext main vault
- `MYMV` v1 main vault
- `MYMV` v2 main vault
- `MYMV` v2 recovery vault
- `MYMV` v2 shared token vault

The fixtures use intentionally weak test-only scrypt parameters so they run
quickly in unit tests. They are not production examples.

## Future `vault migrate` Shape

Migration starts with a non-mutating dry-run command. A future real migration
command should be explicit and non-destructive by default.

Proposed command shape:

```bash
vault migrate --dry-run
vault migrate
```

Current status:

- `vault migrate --dry-run` is implemented as an inspection-only preview.
- `vault migrate` is not implemented yet.
- Dry-run does not ask for passwords, decrypt secrets, take the vault lock, or
  modify runtime files.

Expected behavior:

- inspect active runtime files without printing secrets
- report each encrypted file's current container format
- preview which files would be rewritten
- create backups before rewriting
- rewrite readable legacy/v1 files to the current format
- keep file permissions restrictive
- fail clearly when a file cannot be parsed, decrypted, or backed up
- never delete old backups automatically during the first migration design

## Deprecation Rules

Before removing read support for any old format:

1. The old format must be documented here.
2. A fixture for that format must exist.
3. At least one release must warn that support is planned for removal.
4. Migration guidance must exist in README, user manual, and release notes.
5. The removal must be a minor release or larger.

## Open Questions

- Should `vault migrate` update recovery and shared-token vaults in one command
  or expose separate flags?
- Should migration require `--yes` when it rewrites multiple files?
- Should migration update rollback trusted state after rewriting `vault.db`?
- Should old-format read support ever be removed before `v1.0.0`?
