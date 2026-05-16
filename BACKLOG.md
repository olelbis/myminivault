# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Current baseline release: `v0.1.17`
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
- most high-value tests are end-to-end smoke tests; more package-level unit tests are still useful
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
assets/
  myminivault-pixel.png README pixel art vault image
  screenshots/          README terminal-style SVG screenshots
cmd/
  vault/
    main.go             CLI dispatch and command flow
    commands.go         basic key/value commands, import/export, stats
    config_cli.go       config loading/display
    crypto.go           encryption, decryption, random bytes, key derivation
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
```

## Next Recommended Steps

### 1. Token And Shared Vault Policy Review

Priority: highest.

The token/shared-vault model is the most complex behavior in the project and needs an explicit policy decision.

Current policy:

- `vault.db` is the source of truth after master-password commands save
- token writes are staged in `shared-token-vault.json`
- master commands import staged token writes before executing
- master mutations mirror the full main vault back to the shared vault after saving
- deletes remain authoritative because mirroring replaces shared vault data with main vault data
- conflict handling is currently last-writer-wins at the vault-key level

Decisions to make:

- keep automatic import on master commands, or require explicit `sync-tokens`
- keep last-writer-wins, or add per-key timestamps/revisions
- add delete tombstones, or keep full mirror replacement semantics
- make token write behavior more explicit in command output
- document exact behavior in `docs/user-manual.md`

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-sync-policy-review
```

### 2. Test Depth For `internal/...`

Priority: medium-high.

Smoke tests protect real workflows, but package-level tests should cover internal behavior directly.

Add focused unit tests for:

- `internal/storage`: checksum failure, legacy vault JSON, `.bak` fallback only when primary is missing, atomic write behavior
- `internal/token`: signature validation, forged token rejection, usage count persistence, registry load/save, encrypted shared vault checksum failure
- `internal/recovery`: checksum failure, wrong recovery key, valid recovery decrypt, recovery file atomic write
- `internal/config`: boundary values and malformed JSON cases already covered, expand only if config grows
- `internal/crypto`: ciphertext tamper rejection and short ciphertext behavior

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/internal-unit-tests
```

### 3. Extend Automated CLI Smoke Tests

Priority: medium.

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
- shell-safe `export` output
- recovery `setup-recovery`
- recovery `test-recovery`
- recovery `recover`
- concurrent command serialization through `.myminivault.lock`

Additional smoke coverage to consider:

- token expiration and max-use cleanup
- token revocation followed by failed use
- `token-info` and `list-tokens`
- `security-audit`
- malformed config from the CLI
- backup/restore expectations if restore is added later
- import/export round-trip expectations

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests-extended
```

### 4. Recovery Policy And Verifier Review

Priority: medium.

Completed:

- recovery key generation uses a high-entropy random secret
- recovery file writes are atomic
- tests cover recovery key validation and recovery file writes
- end-to-end smoke coverage verifies `recover` changes the master password
- end-to-end smoke coverage verifies `setup-recovery` and `test-recovery`

Remaining:

- document that recovery can recover only the snapshot stored in `vault.db.recovery`
- decide whether recovery metadata should use a stronger verifier strategy over time
- document what happens when the main vault and recovery snapshot diverge
- document operational guidance for rotating/replacing a recovery key

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/recovery-policy-review
```

### 5. Import/Export Round-Trip Review

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

### 6. Runtime File Permissions And `vault doctor`

Priority: medium.

Add a health-check command for local setup and runtime files:

```bash
vault doctor
```

Checks could include:

- file permissions for vault, token key, shared vault, registry, recovery file, backups, and logs
- stale lock file behavior
- config validity
- token runtime state
- backup presence
- recovery status
- warnings for files that should not be committed

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/doctor-command
```

### 7. Future Refactor Candidates

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

## Product Ideas After Hardening

These are intentionally lower priority than the stability/security work above. Revisit them after documentation cleanup, security review, token sync policy review, and test-depth work are in better shape.

### 8. `vault run -- <command>`

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

### 9. Project Profiles

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

### 10. Namespaces

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

### 11. Clipboard Command

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

### 12. Token UX Cleanup

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

### 13. Terminal UI

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

### 14. Secret Rotation Hooks

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

### 15. Hook System

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
