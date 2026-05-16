# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Last committed milestone: `9e92d9b Add inter-process vault file locking`
- Backup folder created before split: `/Users/MGIANINI/vscode/myminivault-backup-20260515-223123`
- Main CLI package: `cmd/vault`
- Runtime vault files are ignored by Git.
- Only `main` is currently kept locally and on GitHub; completed task branches were merged and deleted.

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
- Added inter-process file locking via `.myminivault.lock`.
- Merged and deleted completed task branches: `codex/split-monolith` and `codex/file-locking`.
- Added automated CLI smoke tests for basic vault commands, wrong-password rejection, and token read/write flows.

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
- concurrent `set` commands serialized correctly through `.myminivault.lock`

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

### 1. Extend Automated CLI Smoke Tests

Automated smoke tests now cover:

- `set`
- `get`
- `delete`
- `list`
- `backup`
- wrong password rejection
- token creation
- token `get`
- token `set`

Remaining coverage to add:

- `change-password` through a pseudo-terminal or refactored testable input path
- recovery setup/test/recover flow after recovery hardening
- concurrent command smoke test for `.myminivault.lock`

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests-extended
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

## Product Ideas After Hardening

These are intentionally lower priority than the stability/security work above. Revisit them after smoke tests, recovery hardening, sync policy, shell-safe export, config validation, and package cleanup are in place.

### 9. `vault run -- <command>`

Run a command with vault entries injected as environment variables, without printing secrets:

```bash
vault run -- npm start
vault run -- go test ./...
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/vault-run-command
```

### 10. Project Profiles

Support separate vault contexts for different projects or environments:

```bash
vault profile create myapp
vault profile use myapp
vault profile list
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/project-profiles
```

### 11. Namespaces

Support namespaced keys for environments such as `dev`, `staging`, and `prod`:

```bash
vault set prod.DB_PASSWORD ...
vault list prod.*
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/namespaces
```

### 12. Clipboard Command

Copy a secret to the system clipboard and optionally clear it after a timeout:

```bash
vault copy API_KEY
vault copy API_KEY --ttl 30s
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/clipboard-copy
```

### 13. Token UX Cleanup

Make token commands more consistent and automation-friendly:

```bash
vault token create --read "API_*" --ttl 30m
vault token inspect <id>
vault token revoke <id>
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-ux
```

### 14. `vault doctor`

Add a health-check command for local setup and runtime files:

```bash
vault doctor
```

Checks could include file permissions, lock file behavior, config validity, token state, backup presence, and recovery status.

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/doctor-command
```

### 15. Terminal UI

Add an optional TUI for browsing/searching keys, viewing token status, editing values, and triggering copy/export flows:

```bash
vault ui
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/tui
```

### 16. Secret Rotation Hooks

Support command-driven rotation workflows:

```bash
vault rotate API_KEY --cmd './scripts/regenerate-api-key'
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/secret-rotation
```

### 17. Hook System

Allow local scripts to run after selected events such as `set`, `delete`, `backup`, or `token create`:

```bash
vault hook add after-set ./scripts/audit.sh
```

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/hooks
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
