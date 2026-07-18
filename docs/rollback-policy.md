# Rollback Policy

This document describes the rollback-detection policy for `myminivault`.
The initial implementation is warning-only: it detects suspicious local rollback
conditions and reports them, but it does not yet block commands or provide an
explicit restore-acceptance command.

## Problem

Authenticated encryption proves that an encrypted vault file was created with a
valid key and was not modified after encryption. It does not prove that the file
is the newest valid vault.

An attacker or sync tool that can replace `vault.db` may restore an older valid
copy. The master password would still decrypt it, and AES-GCM would still
authenticate it, but recently added keys could disappear and deleted keys could
reappear.

## Goals

- detect likely replacement with an older valid main vault
- keep normal local use simple
- avoid silently breaking intentional backup restores
- preserve snapshot-based recovery semantics
- keep legacy vault files readable
- make `doctor` and `inspect-runtime` useful before enforcing stricter behavior

## Non-Goals

- distributed multi-device conflict resolution
- protection from same-user malware while the CLI is running
- protection when both the vault and trusted rollback state are restored together
- preventing a user from intentionally opening an older backup
- replacing backups, recovery snapshots, or export workflows

## Proposed Model

Use encrypted vault revision metadata and a separate local trusted-state file.

The encrypted main vault payload carries a monotonic revision field:

```json
{
  "metadata": {
    "version": "0.x.y",
    "created_at": "...",
    "last_access": "...",
    "access_count": 10,
    "revision": 42,
    "vault_id": "random-stable-id"
  }
}
```

The revision is encrypted inside `vault.db`, so it does not expose usage
frequency to someone who only sees the file. It is authenticated with the rest
of the vault payload.

A separate local trusted-state file, `rollback-state.json`, records the highest
accepted revision for the active runtime home:

```json
{
  "vault_id": "random-stable-id",
  "highest_revision": 42,
  "updated_at": "..."
}
```

This trusted-state file is not secret, but it is security-relevant local state.
It lives in the active runtime home, uses restrictive permissions, rejects
symlinks, uses checked writes, and is included in `doctor` and
`inspect-runtime` output.

## Load Policy

When loading `vault.db`:

1. Decrypt and authenticate the vault normally.
2. If the vault has no revision metadata, treat it as legacy and initialize
   trusted state on the next successful save.
3. If there is no trusted-state file, initialize it from the loaded vault after
   a successful password-authenticated load.
4. If `vault_id` differs from trusted state, warn or require an explicit accept
   command in a future strict mode.
5. If `revision` is lower than `highest_revision`, report a rollback warning or
   warning.
6. If `revision` is equal or higher, accept the vault and update trusted state
   after successful mutating saves.

## Save Policy

On every successful main-vault mutation:

1. Load current trusted state.
2. Increment the encrypted vault revision before saving.
3. Save the main vault atomically.
4. Update trusted state only after the main vault save succeeds.

If trusted-state update fails after the vault save succeeds, the command should
report a clear warning or error. The safest default is to fail the command after
the save has completed and tell the user to run `vault doctor` or a future
`vault rollback-state repair` command.

## Restore Policy

Intentional restore should become explicit before strict blocking is enabled.

Opening an older backup does not silently lower trusted state. A future command
should make this action deliberate, for example:

```bash
vault accept-rollback --from vault.db.20260718-120000.bak
```

or, if a restore command is added later:

```bash
vault restore vault.db.20260718-120000.bak --accept-older-revision
```

The command should print the current trusted revision, the candidate vault
revision, timestamps, and the consequence of accepting the older state.

## Recovery Policy

Recovery remains snapshot-based.

`vault recover` may legitimately produce a vault whose revision is older than
the highest trusted main-vault revision. That should be treated as an explicit
recovery event, not as silent rollback.

After successful recovery, the CLI should either:

- assign a new revision above the previous trusted high-water mark, or
- require an explicit recovery acceptance step that resets trusted state.

The preferred implementation is to assign a new revision above the trusted
high-water mark when trusted state is available. That preserves monotonic local
history while keeping recovery usable.

## Token Sync Policy

The shared token vault is a local convenience mirror, not the source of truth.
Main-vault rollback detection should run before token sync import/export work.

If a main-vault rollback is detected, token sync should not silently import newer
shared-token data into the older main vault. The command should stop and ask for
explicit rollback/restore handling first.

## Modes

The initial implementation behaves like `warn`. Future modes may include:

- `off`: do not check rollback state; useful for debugging and legacy recovery
- `warn`: report suspicious rollback but allow read-only commands
- `strict`: block commands until the user accepts or repairs the state

After the behavior matures and restore workflows are documented, `strict` can be
considered for mutating commands.

## Doctor And Inspect Output

`vault doctor` reports:

- whether trusted rollback state exists
- active `vault_id`
- current vault revision
- trusted highest revision
- rollback status: OK, WARN, or FAIL
- stale or unreadable trusted-state file

`vault inspect-runtime` lists the trusted-state file and shows non-secret
rollback-state metadata. It does not decrypt the main vault to print encrypted
`vault_id` or `revision`.

## Migration

Legacy vaults without revision metadata should remain readable.

On first successful mutating save after the feature is introduced:

- generate `vault_id` if missing
- set `revision` to `1` if missing
- create trusted state with `highest_revision=1`

Read-only commands should not force a migration.

## Residual Risk

This policy detects many accidental or malicious replacements of `vault.db`
alone. It does not protect against an attacker who can roll back both `vault.db`
and the trusted-state file, nor against malware that runs as the same user while
the CLI is executing.

For stronger rollback protection, the trusted high-water mark would need an
OS-backed store, hardware-backed storage, signed remote transparency log, or
another trust anchor outside the runtime directory.

## Remaining Implementation Plan

1. Add an explicit accept/repair command before introducing strict blocking.
2. Add a restore command that can deliberately accept an older revision.
3. Add config support for `off`, `warn`, and `strict` modes.
4. Add stronger smoke coverage for rollback warning output across full CLI
   backup/restore simulations.
5. Evaluate OS-backed trusted state for platforms that provide a better trust
   anchor than a file in the runtime directory.
