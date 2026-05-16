# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Last committed milestone: `4b27f76 Update module Go version`
- Backup folder created before split: `/Users/MGIANINI/vscode/myminivault-backup-20260515-223123`
- Main CLI package: `cmd/vault`
- Runtime vault files are ignored by Git.
- Historical branch `codex/split-monolith` has been fast-forwarded into `main`.

## What Has Been Done

- Initialized Git for the project.
- Added `.gitignore` for runtime vault files, keys, logs, build output, and `test.txt`.
- Fixed `change-password` so the old password does not immediately overwrite the new save.
- Split `cmd/vault/myminivault.go` into focused files under `cmd/vault`.
- Removed the duplicate root monolith `myv.go`.
- Fixed `delete` so removed keys are not restored from the shared token vault on the next run.
- Changed `.bak` loading so an existing `vault.db` with a wrong password does not fall back to `vault.db.bak`.
- Added `Sync()` before atomic rename for main vault saves.
- Added `README.md` with current usage and feature documentation.
- Added `BACKLOG.md` as a handoff file for future sessions.
- Updated `go.mod` to Go `1.26`.
- Fast-forwarded `main` to the completed split/fix/docs state and pushed it to GitHub.
- Added inter-process file locking via `.myminivault.lock` on branch `codex/file-locking`.

## Current Verification

These commands passed after the split and fixes:

```bash
GOCACHE=/private/tmp/myminivault-gocache go test ./...
```

Manual smoke tests were run in `/private/tmp` with fake data:

- build CLI
- `set`
- `get`
- `delete`
- `get` after delete
- `change-password`
- old password rejected after password change
- new password accepted after password change

## Current Project Layout

```text
cmd/
  vault/
    main.go       CLI dispatch and command flow
    commands.go   basic key/value commands, import/export, stats
    config.go     config loading/display
    crypto.go     encryption, decryption, random bytes, key derivation
    recovery.go   recovery and password-change flows
    storage.go    main vault load/save
    sync.go       main/shared vault synchronization
    token.go      token creation, validation, token commands
    types.go      shared data structures
  splitter/
    splitter.go   legacy split helper; likely removable later
```

## Next Recommended Steps

### 1. Add Automated CLI Smoke Tests

Create a repeatable test script or Go integration test that runs in a temporary directory and checks:

- `set`
- `get`
- `delete`
- `list`
- `backup`
- `change-password`
- wrong password rejection
- token creation
- token `get`
- token `set`

Keep all runtime files inside a temporary directory.

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests
```

### 2. Hardening: Recovery

Recovery is the highest-priority security area.

Known concerns:

- recovery key entropy is low for a vault recovery secret
- recovery file update behavior should be explicit and reliable
- recovery flow should have automated smoke coverage

Possible approach:

- generate a longer random recovery secret
- store only a verifier/hash in the main vault
- document that recovery can only recover the snapshot stored in `vault.db.recovery`
- make recovery file refresh behavior explicit after setup

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/recovery-hardening
```

### 3. Hardening: Token/Shared Vault Sync

The current sync is better after the delete fix, but the design should be clarified.

Questions to answer:

- Is `vault.db` always the main source of truth?
- Should token writes be merged into main immediately or only by explicit `sync-tokens`?
- How should conflicts be resolved?
- Should deletes have tombstones or should mirroring remain authoritative?

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-sync-policy
```

### 4. Make Export Shell-Safe

Current export output is simple:

```bash
export KEY="value"
```

It should safely escape:

- quotes
- `$`
- backticks
- backslashes
- newlines

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/export-shell-safe
```

### 5. Reduce Token Side Effects

Currently ordinary password commands can create token runtime files because sync initializes the shared token vault.

Goal:

- create `vault-token.key` and `shared-token-vault.json` only when token features are actually used, or clearly document why they are always created.

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-side-effects
```

### 6. Validate Configuration

`vault-config.json` is loaded without validation.

Add guards for:

- minimum/maximum scrypt parameters
- key size
- backup count
- malformed JSON

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/config-validation
```

### 7. Decide Fate Of `cmd/splitter`

Options:

- remove it because the monolith has already been split
- keep it as a development helper and document it
- move it under a tools directory

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/remove-splitter
```

### 8. Later Refactor To `internal/...`

The current split keeps everything in package `main`, which was intentionally conservative.

Later, move stable areas into packages:

- `internal/crypto`
- `internal/storage`
- `internal/token`
- `internal/recovery`
- `internal/config`

Do this only after smoke tests exist.

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/internal-packages
```

## Useful Commands

Run all checks:

```bash
GOCACHE=/private/tmp/myminivault-gocache go test ./...
```

Build:

```bash
go build -o bin/vault ./cmd/vault
```

Check Git status:

```bash
git status --short --branch
```

Show latest commit:

```bash
git log --oneline -5
```
