# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Current baseline release: `v0.1.2`
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
- Merged and deleted completed task branches: `codex/split-monolith`, `codex/file-locking`, `codex/cli-smoke-tests`, and `codex/recovery-hardening`.
- Added automated CLI smoke tests for basic vault commands, wrong-password rejection, and token read/write flows.
- Added automated concurrent lock smoke coverage.
- Hardened recovery key generation to use 32 secure random bytes encoded as grouped base32.
- Made recovery file saves atomic and added unit tests for recovery key validation and recovery file writes.
- Added end-to-end `recover` smoke coverage and fixed piped password input for recovery flows.
- Clarified the main/shared token vault sync policy in code and documentation.
- Added smoke coverage for automatic token-write import by master-password commands.
- Removed the legacy `cmd/splitter` helper after the monolith split was complete.
- Made `export` output shell-safe with POSIX single-quote escaping and added smoke/unit coverage.
- Added `CHANGELOG.md` and adopted Git release tags such as `v0.1.0`, kept in sync with the CLI-visible version.

## Current Verification

Current automated checks:

```bash
go test ./...
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
```

## Next Recommended Steps

### 0. Versioning And Changelog

Status: baseline changelog added for `v0.1.0`.

Guidelines:

- use `v0.x.y` while the CLI is still evolving quickly
- patch releases (`v0.1.1`) for small fixes
- minor releases (`v0.2.0`) for backlog items that add or change behavior
- document every merged branch in `CHANGELOG.md`
- keep the CLI-visible version in sync with the current release tag

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
- automatic import of token writes by master-password commands
- shell-safe `export` output
- concurrent command serialization through `.myminivault.lock`

Remaining coverage to add:

- `change-password` through a pseudo-terminal or refactored testable input path
- recovery setup/test flow after recovery hardening

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests-extended
```

### 2. Finish Recovery Hardening

Recovery is the highest-priority security area.

Known concerns:

- recovery setup/test flow should have automated smoke coverage

Completed:

- recovery key generation now uses a high-entropy random secret
- recovery file writes are atomic
- unit tests cover recovery key validation and recovery file writes
- end-to-end smoke coverage verifies `recover` changes the master password

Remaining:

- document that recovery can only recover the snapshot stored in `vault.db.recovery`
- add end-to-end recovery setup/test smoke coverage
- consider whether recovery metadata should store only a stronger verifier/hash strategy over time

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/recovery-setup-test
```

### 3. Hardening: Token/Shared Vault Sync

The sync policy is now explicit in code and docs.

Current policy:

- `vault.db` is the source of truth after master-password commands save.
- token writes are staged in `shared-token-vault.json`.
- master commands import staged token writes before executing.
- master mutations mirror the full main vault back to the shared vault after saving.
- deletes remain authoritative because mirroring replaces shared vault data with main vault data.
- conflict handling is currently last-writer-wins at the vault-key level.

Remaining questions:

- Should token writes require explicit `sync-tokens` instead of automatic import on master commands?
- Should conflicts use timestamps or per-key revision metadata?
- Should delete tombstones be added for more precise conflict handling?
- Document this area thoroughly in a future user manual, including the main/shared vault model, automatic imports, explicit `sync-tokens`, conflict behavior, and delete semantics.

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-sync-conflicts
```

### 4. Make Export Shell-Safe

Status: implemented with POSIX single-quote escaping and smoke/unit coverage.

Current export output is shell-safe:

```bash
export KEY='value'
```

Covered cases:

- quotes
- `$`
- backticks
- backslashes
- newlines

Remaining follow-up: improve `import` parsing if imported files need to round-trip every shell-escaped export exactly.

### 5. Reduce Token Side Effects

Status: implemented with smoke coverage.

Current behavior:

- ordinary password commands do not create `vault-token.key`, `shared-token-vault.json`, or `vault-tokens.json`
- token runtime files are created when token features are used
- main vault mutations mirror back to the shared token vault only after token runtime has been initialized

### 6. Validate Configuration

Status: implemented with unit coverage.

Current behavior:

- malformed `vault-config.json` is rejected
- `scrypt_n` must be a power of two between `32768` and `1048576`
- `scrypt_r` must be between `1` and `16`
- `scrypt_p` must be between `1` and `8`
- `key_size` must be `16`, `24`, or `32`
- `max_backups` must be between `1` and `100`

### 7. Draft User Manual

The README is enough for development, but the CLI should eventually have a user-facing manual.

Cover at least:

- basic key/value workflows
- backups and recovery
- password changes
- token creation, usage, expiration, revocation, and cleanup
- main/shared vault sync policy
- file locking and concurrent CLI usage expectations
- import/export behavior and shell-safety notes
- troubleshooting common errors

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/user-manual
```

### 8. Later Refactor To `internal/...`

The current split keeps everything in package `main`, which was intentionally conservative.

Later, move stable areas into packages:

- `internal/crypto`
- `internal/storage`
- `internal/token`
- `internal/recovery`
- `internal/config`

Do this only after smoke tests exist. During the refactor, add concise English comments for non-obvious invariants and flows, especially around encryption boundaries, recovery, token validation, shared-vault sync, and file locking.

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
