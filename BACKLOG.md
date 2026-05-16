# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Current baseline release: `v0.2.0`
- Backup folder created before split: `/Users/MGIANINI/vscode/myminivault-backup-20260515-223123`
- Main CLI package: `cmd/vault`
- Runtime vault files are ignored by Git.
- Only `main` is currently kept locally and on GitHub; completed task branches were merged and deleted.

## Project Assessment

Current assessment: `myminivault` is a solid local/personal CLI vault project with a clean release workflow, meaningful smoke tests, and a clearer package structure than the original monolith. It should still be treated as an experimental personal security tool, not as a production-grade password manager.

Main strengths:

- release discipline with Git tags, GitHub releases, and a changelog
- focused `internal/...` packages for crypto, config, model, recovery, storage, and token logic
- automated CLI smoke coverage for critical workflows
- explicit handling for recovery, token sync, locking, backups, export, and password changes
- a handoff backlog that can restart work from a fresh chat

Main risks:

- the project handles real secrets, so security assumptions must be documented and reviewed carefully
- token/shared-vault synchronization is powerful but conceptually complex
- package-level unit coverage is improving, but more edge-case coverage is still useful as behavior grows
- `cmd/vault` still contains some orchestration and command logic that may deserve future extraction
- the README has been split into focused docs, but the security model still needs a dedicated review

Strategic guidance:

- prefer documentation, security review, and test depth before adding new features
- keep product ideas below hardening work unless they reduce operational risk
- document behavior before changing user-facing semantics
- avoid claiming production security until a threat model and focused security review exist

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
- Added core unit coverage for crypto, token helpers, key validation, and import parsing.
- Moved crypto helpers into `internal/crypto` with focused English comments.
- Moved config loading and validation into `internal/config` with focused English comments.
- Added automated CLI smoke coverage for `change-password`.
- Moved shared data structures into `internal/model` with compatibility aliases in `cmd/vault`.
- Moved vault load/save, checksum, and atomic write helpers into `internal/storage`.
- Moved token signing, validation, registry, and encrypted shared token vault helpers into `internal/token`.
- Moved recovery key generation, validation, recovery vault decryption, and recovery file writes into `internal/recovery`.
- Renamed `cmd/vault` CLI wrapper files so they are easier to distinguish from similarly named `internal/...` packages.
- Added MIT license, README badges, and a project-local pixel art vault image.
- Split documentation into a concise README, `docs/user-manual.md`, and `docs/development.md`.
- Added terminal-style SVG screenshots for quick start, token, and recovery workflows.
- Expanded `docs/development.md` with practical test commands for full, package, focused, verbose, cached, and manual smoke-test runs.
- Added `docs/security.md` with the current security model, non-goals, sensitive assets, runtime-file risks, recovery limits, token boundaries, and compromise guidance.
- Added `docs/token-sync-policy.md` documenting the current automatic token-write import policy, `sync-tokens`, conflict behavior, delete semantics, and deferred decisions.
- Clarified token command output and help text around staged token writes and main-vault import.
- Added package-level tests for `internal/storage`, `internal/token`, and `internal/recovery`.
- Added crypto coverage for tampered ciphertext rejection.
- Fixed legacy vault loading for old JSON payloads longer than the checksum prefix size.
- Added CLI smoke coverage for expired tokens, used-up tokens, token revocation, `list-tokens`, and `token-info`.
- Added CLI smoke coverage for malformed config handling.
- Added a basic import/export round-trip smoke test.
- Added `docs/recovery-policy.md` documenting recovery snapshot behavior, divergence semantics, verifier policy, and rotation caveats.
- Linked the recovery policy from README, user manual, security model, and development docs.
- Added `vault doctor` for local runtime health checks covering config validity, file permissions, locks, backups, recovery files, token files, and logs.
- Hardened sensitive runtime writes to prefer `0600` permissions for main vaults, backups, shared token vaults, and logs.
- Added automated CLI smoke coverage for `vault doctor`.

## Current Verification

Current automated checks:

```bash
go test ./...
```

Package-level coverage now includes:

- `internal/storage`: checksum failure, legacy vault JSON, `.bak` fallback only when primary is missing, and atomic write behavior
- `internal/token`: token master key validation, registry load/save, encrypted shared vault tamper rejection, forged token rejection, and usage count persistence
- `internal/recovery`: grouped key generation, verifier validation, valid recovery decrypt, wrong-key rejection, checksum failure, missing verifier rejection, and atomic recovery file writes
- `internal/crypto`: round trip, wrong key rejection, tampered ciphertext rejection, and short ciphertext rejection

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

Automated CLI smoke coverage includes:

- basic vault commands, backup, wrong password rejection, and `change-password`
- token create/get/set, automatic token-write import, expired token rejection, used-up token rejection, revocation rejection, `list-tokens`, and `token-info`
- recovery setup, recovery validation, and master password recovery
- shell-safe export output and basic import/export round-trip behavior
- malformed config handling, `vault doctor`, and concurrent command serialization through `.myminivault.lock`

## Current Project Layout

```text
assets/
  myminivault-pixel.png README pixel art vault image
  screenshots/          README terminal-style SVG screenshots
cmd/
  vault/
    main.go             CLI dispatch and command flow
    commands.go         basic key/value commands, import/export, stats
    config_cli.go       config loading/display
    crypto.go           encryption, decryption, random bytes, key derivation
    doctor_cli.go       local runtime health checks
    recovery_cli.go     recovery and password-change flows
    storage_bridge.go   main vault load/save wrappers
    sync.go             main/shared vault synchronization
    token_cli.go        token creation, validation, token commands
    types.go            compatibility aliases for shared data structures
internal/
  config/
    config.go           config defaults, loading, and validation
  crypto/
    crypto.go           key derivation, encryption, decryption, secure random bytes
  model/
    model.go            vault, recovery, token, and metadata structs
  recovery/
    recovery.go         recovery keys, recovery vault decryption, and recovery file writes
  storage/
    storage.go          vault load/save, checksum, and atomic writes
  token/
    token.go            token signing, validation, registry, and shared token vault persistence
docs/
  user-manual.md        user-facing workflows and operational notes
  development.md        architecture, test, and release workflow notes
  security.md           security model, assumptions, limits, and compromise guidance
  recovery-policy.md    recovery snapshot, verifier, divergence, and rotation policy
  token-sync-policy.md  main/shared token vault sync policy and deferred decisions
```

## Next Recommended Steps

### 1. Logging Cleanup

Priority: medium.

Reduce metadata leakage from `vault.log`.

Current concerns:

- logs can reveal command names, key names, and token ID prefixes
- key names may be sensitive even when values are encrypted
- logging is not currently configurable

Possible directions:

- add a config flag to disable audit logging
- stop logging key names by default
- further truncate or hash token IDs in logs
- keep log writes at `0600`
- document the chosen default in the security model and user manual

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/logging-cleanup
```

### 2. Additional CLI Smoke Tests

Automated smoke tests currently cover:

- `set`
- `get`
- `delete`
- `list`
- `backup`
- wrong password rejection
- `change-password`
- token creation
- token `get`
- token `set`
- automatic import of token writes by master-password commands
- expired token rejection
- used-up token rejection
- token revocation followed by failed use
- `token-info` and `list-tokens`
- shell-safe `export` output
- basic import/export round-trip behavior
- malformed config from the CLI
- recovery `setup-recovery`
- recovery `test-recovery`
- recovery `recover`
- concurrent command serialization through `.myminivault.lock`

Additional smoke coverage to consider:

- `security-audit`
- backup/restore expectations if restore is added later
- exact import/export round-trip expectations for shell-escaped special values

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests-more
```

### 3. Import/Export Round-Trip Review

Priority: medium.

Status: export is implemented with POSIX single-quote escaping and smoke/unit coverage.

Current export output is shell-safe:

```bash
export KEY='value'
```

Covered export cases:

- quotes
- `$`
- backticks
- backslashes
- newlines

Remaining:

- decide whether imported files must round-trip every shell-escaped export exactly
- improve `import` parsing if exact round-trip behavior becomes a requirement
- document safe shell usage and shell history caveats

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/import-export-roundtrip
```

### 4. Future Refactor Candidates

Priority: low unless a bug or feature makes the extraction useful.

Stable internal packages already extracted:

- `internal/config`
- `internal/crypto`
- `internal/model`
- `internal/recovery`
- `internal/storage`
- `internal/token`

Possible future extractions:

- `internal/sync`: main/shared vault synchronization policy
- `internal/lock`: file lock handling
- `internal/commands`: command-independent key/value operations
- `internal/audit`: security audit reporting

Continue only with well-covered areas and add concise English comments for non-obvious invariants.

Future token sync simplification:

- If `sync-tokens` should become mandatory instead of automatic import, first separate token writes from the shared vault mirror into a pending-write log.
- Add per-key revision/timestamp metadata and delete tombstones before changing the policy, otherwise a later master-vault mirror can overwrite unsynced token writes.
- Document the final behavior in the user manual once the policy is stable.

## Product Ideas After Hardening

These are intentionally lower priority than the stability/security work above. Revisit them after documentation cleanup, security review, token sync policy review, and test-depth work are in better shape.

### 5. `vault run -- <command>`

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

### 6. Project Profiles

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

### 7. Namespaces

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

### 8. Clipboard Command

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

### 9. Token UX Cleanup

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

### 10. Terminal UI

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

### 11. Secret Rotation Hooks

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

### 12. Hook System

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
