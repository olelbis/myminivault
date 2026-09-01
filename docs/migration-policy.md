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
| `MYMV` v2 with scrypt | yes | no | Deprecated KDF profile; readable for compatibility and rewritten with Argon2id on save. |
| `MYMV` v2 main vault with Argon2id | yes | yes | Current password-based main-vault format with authenticated metadata and salt as AES-GCM AAD. |
| `MYMV` v2 recovery/shared-token vault with HKDF-SHA256 | yes | yes | Current high-entropy-key format for generated recovery keys and token master keys. |
| `MYMV` v2 recovery/shared-token vault with Argon2id | yes | no | Deprecated experimental profile; readable for compatibility and rewritten with HKDF-SHA256 on save. |

Current saves always write `MYMV` v2. Main-vault saves use Argon2id by default;
recovery and shared-token vault saves use HKDF-SHA256 because their keys are
generated high-entropy material.

## Legacy Sunset Policy

Deprecated read support is kept to protect existing users, but every readable
format remains parser surface. During the experimental `0.x` series,
myminivault keeps scrypt-based `MYMV` v2, `MYMV` v1, and headerless legacy files
readable by default. Before a future `1.0`, the project should decide whether
deprecated formats remain always-readable or require an explicit opt-in such as
`--allow-legacy`.

Any future removal must be staged:

- announce the target format and release window in this document, the user
  manual, and the changelog
- keep fixtures for the deprecated format until the removal release
- provide a non-mutating `vault migrate --dry-run` result that identifies files
  requiring user action
- remove the read path only after a documented migration window

## Compatibility Fixtures

The compatibility fixture corpus lives in
`internal/storage/testdata/compat/`.

Current fixture coverage:

- legacy salt-plus-ciphertext main vault
- `MYMV` v1 main vault
- `MYMV` v2 main vault with deprecated scrypt metadata
- `MYMV` v2 main vault with current Argon2id metadata
- `MYMV` v2 recovery vault with deprecated Argon2id metadata
- `MYMV` v2 recovery vault with current HKDF-SHA256 metadata
- `MYMV` v2 shared token vault with deprecated Argon2id metadata
- `MYMV` v2 shared token vault with current HKDF-SHA256 metadata

Fixture policy:

- keep every historical format fixture until the corresponding read path is
  removed
- add a fixture before changing parser behavior for legacy, v1, v2, recovery,
  or shared-token vault payloads
- include at least one negative/tamper test when metadata authentication or KDF
  bounds change
- keep fixture passwords and KDF parameters clearly test-only

Some fixtures use intentionally weak test-only scrypt parameters so they run
quickly in unit tests. They are compatibility fixtures, not production examples.

## Deprecated Format Strategy

Migration starts and stops with a non-mutating inspection command for now. The
project intentionally does not plan a mutating `vault migrate` command in the
near term because rewriting encrypted files through a separate migration path
would add risk and maintenance surface.

Current command shape:

```bash
vault migrate --dry-run
```

Current status:

- `vault migrate --dry-run` is implemented as an inspection-only preview.
- `vault migrate` without `--dry-run` is intentionally unsupported.
- Dry-run does not ask for passwords, decrypt secrets, take the vault lock, or
  modify runtime files.
- Normal authenticated save paths already rewrite readable deprecated files to
  the current `MYMV` v2 write profile.

Operational guidance:

- use `vault migrate --dry-run` to identify deprecated runtime files
- unlock and perform the relevant normal save operation to refresh a readable
  deprecated file
- keep backups before manual cleanup of old runtime files
- keep compatibility fixtures until the read path is removed
- prefer explicit deprecation windows over automatic bulk rewrites

## Deprecation Rules

Before removing read support for any old format:

1. The old format must be documented here.
2. A fixture for that format must exist.
3. At least one release must warn that support is planned for removal.
4. Refresh or deprecation guidance must exist in README, user manual, and release notes.
5. The removal must be a minor release or larger.

## Open Questions

- Should `vault migrate` update recovery and shared-token vaults in one command
  or expose separate flags?
- Should migration require `--yes` when it rewrites multiple files?
- Should migration update rollback trusted state after rewriting `vault.db`?
- Should old-format read support ever be removed before `v1.0.0`?
