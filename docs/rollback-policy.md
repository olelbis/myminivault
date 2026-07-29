# Rollback Policy

This document describes the rollback-detection policy for `myminivault`.
The default implementation is warning-only, but the CLI also supports an
opt-in blocking mode and an explicit restore-acceptance command.

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
- make `doctor` and `inspect-runtime` useful before enabling stricter behavior

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
4. If `vault_id` differs from trusted state, warn by default or fail in block
   mode until the current vault is explicitly accepted.
5. If `revision` is lower than `highest_revision`, report a rollback warning or
   fail in block mode.
6. If `revision` is equal or higher, accept the vault and update trusted state
   after successful mutating saves.

## Save Policy

On every successful main-vault mutation:

1. Load current trusted state.
2. Increment the encrypted vault revision before saving.
3. Save the main vault atomically.
4. Update trusted state only after the main vault save succeeds.

If trusted-state update fails after the vault save succeeds, the command reports
a clear save error so the user can inspect the runtime state with `vault doctor`
or `vault inspect-runtime`.

## Restore Policy

Opening an older backup does not silently lower trusted state. Restore is still a
manual file operation today: copy the intended backup over `vault.db`, unlock it,
verify that it is really the vault you wanted, and then explicitly accept its
rollback metadata:

```bash
vault rollback-accept
```

`rollback-accept` requires the master password because it must decrypt the
current vault before trusting its encrypted `vault_id` and `revision`. It updates
`rollback-state.json` to the current vault metadata and prints the accepted
revision. Only use it after verifying that the current restore is intentional.

A future `vault restore <backup>` command may combine backup selection,
inspection, replacement, and acceptance in one safer flow.

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

`vault-config.json` supports these `rollback_mode` values:

- `off`: do not check rollback state; useful for debugging and legacy recovery
- `warn`: report suspicious rollback but allow read-only commands
- `block`: report suspicious rollback as a failure until the user accepts the
  current vault with `vault rollback-accept`

Example:

```json
{
  "rollback_mode": "block"
}
```

Rollback checks run before token sync import so an older main vault does not
silently absorb newer staged token writes.

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

1. Add a safer `vault restore <backup>` command that previews candidate metadata
   before replacing `vault.db`.
2. Add smoke coverage for intentional restore acceptance.
3. Add stronger smoke coverage for rollback warning output across full CLI
   backup/restore simulations.
4. Evaluate OS-backed trusted state for platforms that provide a better trust
   anchor than a file in the runtime directory.
