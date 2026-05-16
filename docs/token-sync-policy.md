# Token And Shared Vault Sync Policy

This document records the current `myminivault` token synchronization policy. It is intentionally explicit because this is one of the most subtle parts of the project.

## Summary

Current decision: keep automatic import of token writes before master-password commands, keep `sync-tokens` as an explicit manual import command, and keep last-writer-wins conflict behavior for now.

No per-key timestamps, revision counters, or delete tombstones are currently stored.

## Runtime Files

Token synchronization uses two encrypted vault files:

- `vault.db`: the main master-password vault
- `shared-token-vault.json`: the encrypted shared vault used by token commands

Token metadata also uses:

- `vault-token.key`: local token master key
- `vault-tokens.json`: token registry metadata

## Current Flow

### Master-Password Commands

When a command uses the master password, the CLI:

1. loads and decrypts `vault.db`
2. imports staged token writes from `shared-token-vault.json` if it exists
3. cleans up expired or fully used tokens
4. runs the requested command
5. saves `vault.db` when the command mutates state
6. mirrors the main vault back to `shared-token-vault.json` for `set`, `delete`, `clear`, and `import`

Read-only commands such as `get`, `list`, `search`, `export`, and `stats` import token writes into memory before running, but they do not save `vault.db`.

### Token Commands

Token commands use `shared-token-vault.json` directly.

Token `get`, `list`, and `search` read from the shared token vault.

Token `set` writes immediately to the shared token vault. The write becomes visible to the main vault when:

- a master-password command imports staged token writes, or
- the user runs `sync-tokens`

## `sync-tokens`

`sync-tokens` imports staged token writes from `shared-token-vault.json` into the main vault and then saves `vault.db`.

It is useful when the user wants to make token writes durable in the main vault immediately instead of waiting for another master-password command.

## Conflict Policy

Current conflict behavior is last-writer-wins at the key level.

There is no per-key timestamp, revision counter, merge base, or tombstone metadata. If the same key changes in both vaults before synchronization, the value imported last wins.

## Delete Semantics

Deletes from master-password commands are authoritative after the main vault is mirrored back to the shared token vault.

This means a deleted key is removed from the shared token vault when a mutating master-password command saves and mirrors the main vault.

There are no delete tombstones today. The current design relies on full data replacement during main-to-shared mirroring.

## Why Keep Automatic Import For Now

Automatic import makes token writes easier to use:

- token-set values are picked up by normal master-password workflows
- users do not need to remember `sync-tokens` after every token write
- existing CLI smoke tests already protect this behavior

The cost is complexity:

- users must understand that read-only master commands may show staged token writes without saving them to `vault.db`
- conflicts are not richly represented
- future multi-device or remote sync would need a stronger model

## Deferred Decisions

Future work may revisit:

- requiring explicit `sync-tokens` for all token writes
- adding per-key timestamps or revision counters
- adding delete tombstones
- separating staged token writes from full shared vault mirroring
- changing command output to show when token writes were imported

Until then, documentation and command output should describe the automatic import behavior clearly.
