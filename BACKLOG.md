# myminivault Backlog

This file is the project handoff note. Use it to resume work from a fresh chat or a new development session.

## Current Snapshot

- Project path: `/Users/MGIANINI/vscode/myminivault`
- Stable branch: `main`
- Remote: `origin` -> `https://github.com/olelbis/myminivault.git`
- Current baseline release: `v0.3.2`
- Backup folder created before split: `/Users/MGIANINI/vscode/myminivault-backup-20260515-223123`
- Main CLI package: `cmd/vault`
- Runtime vault files are ignored by Git.
- Only `main` is currently kept locally and on GitHub; completed task branches were merged and deleted.

## Project Assessment

Current assessment score: `8.4 / 10`.

`myminivault` is a solid local/personal CLI vault project with a clean release workflow, meaningful smoke tests, GitHub CI across Linux and macOS, release packaging for common Linux/macOS targets, a formal threat model, a clearer package structure than the original monolith, stronger local security checks, timestamp-aware token sync metadata, and safer alternatives to printing plaintext secrets. It should still be treated as an experimental personal security tool, not as a production-grade password manager.

Main strengths:

- release discipline with Git tags, GitHub releases, and a changelog
- GitHub CI for formatting, vetting, and automated tests across Linux and macOS
- release package automation for Linux amd64, Linux arm64, and macOS arm64
- formal threat model covering assets, attackers, trust boundaries, data flows, residual risks, and incident response
- focused `internal/...` packages for crypto, config, model, recovery, storage, and token logic
- automated CLI smoke coverage for critical workflows
- explicit handling for recovery, token sync, locking, backups, export, and password changes
- a handoff backlog that can restart work from a fresh chat

Main risks:

- the project handles real secrets, so the threat model must stay current as behavior changes
- token/shared-vault synchronization is better guarded than before, but still conceptually complex
- package-level unit coverage is improving, but more edge-case coverage is still useful as behavior grows
- `cmd/vault` still contains some orchestration and command logic that may deserve future extraction
- the security model is clearer, but it is still self-reviewed and not an external audit

Strategic guidance:

- prefer documentation, security review, and test depth before adding new features
- keep product ideas below hardening work unless they reduce operational risk
- document behavior before changing user-facing semantics
- avoid claiming production security without external review

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
- Added GitHub Actions CI for `gofmt`, `go vet`, and `go test ./...`.
- Added focused Go doc comments for exported internal package identifiers.
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
- Added `audit_log` config support so audit logging can be disabled.
- Reduced audit-log metadata leakage by omitting key names and token identifiers by default.
- Improved import parsing for shell-safe export output with apostrophes and embedded newlines.
- Added `vault doctor` freshness warnings for stale recovery snapshots and shared token vaults newer than the main vault.
- Added per-key sync metadata for main/shared vault updates and delete markers.
- Changed token sync so older shared-vault values do not overwrite newer main-vault values when both sides have metadata.
- Added tests for sync metadata conflict decisions.
- Added `copy <key>` with clipboard warning and TTL-based clearing when supported.
- Added `export --output <file>` to write shell-safe exports directly to a `0600` file.
- Added best-effort core dump disabling on supported Unix-like systems.
- Documented clipboard, export, and runtime memory exposure limits.
- Added GitHub Actions release packaging for Linux amd64, Linux arm64, and macOS arm64 archives.
- Added README and CLI help credits for `olelbis`.
- Expanded GitHub Actions CI to run `gofmt`, `go vet`, and `go test ./...` on Linux and macOS.
- Reworked `docs/security.md` into a formal threat model with assets, attacker assumptions, trust boundaries, data flows, residual risks, and incident response guidance.

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
- shell-safe export output and export/import round-trip behavior for apostrophes and embedded newlines
- export to `0600` files and clipboard clear behavior
- audit-log redaction, disabled audit logging, malformed config handling, `vault doctor`, and concurrent command serialization through `.myminivault.lock`

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
    core_dump_unix.go   best-effort core dump disabling on Unix-like systems
    core_dump_other.go  no-op core dump hook for unsupported systems
    crypto.go           encryption, decryption, random bytes, key derivation
    doctor_cli.go       local runtime health checks
    recovery_cli.go     recovery and password-change flows
    storage_bridge.go   main vault load/save wrappers
    sync.go             main/shared vault synchronization
    sync_metadata.go    per-key sync update/delete metadata helpers
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

### 1. Token Sync Policy Next Steps

Priority: low-medium unless sync behavior changes again.

Token sync is now timestamp-aware when both vaults have metadata, but it is still not a distributed merge system.

Remaining concerns:

- master commands import token-side writes automatically
- legacy vaults without metadata fall back to simple import behavior
- there is no revision counter or merge-base record
- delete markers are timestamp metadata, not a full distributed tombstone system
- sync is still local-file oriented, not multi-device oriented

Possible directions:

- introduce pending-write metadata before making sync explicit-only
- add revision counters or merge-base records if conflict handling grows
- upgrade delete markers into explicit tombstones if sync becomes more distributed
- keep `vault doctor` warnings for shared-token-vault freshness
- document any policy change before changing command behavior

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/token-sync-next
```

### 2. Quality Roadmap Toward 8.5

Priority: medium-high.

These items are the most direct path from the current `8.4 / 10` assessment toward roughly `8.5 / 10`. Prefer them before adding new product features.

Recommended order:

1. add coverage reporting, then decide whether to enforce a minimum threshold
2. continue improving release binaries and install paths after the first package workflow
3. continue reducing broad orchestration in `cmd/vault` only where tests already protect behavior

Suggested branches:

```bash
git switch main
git pull
git switch -c codex/install-packaging
```

```bash
git switch main
git pull
git switch -c codex/coverage-reporting
```

### 3. Coverage Reporting

Priority: medium.

Current CI runs formatting, `go vet`, and `go test ./...` on Linux and macOS. The next quality step is to publish coverage information from CI.

Next actions:

- add a coverage job or coverage artifact
- decide later whether coverage should be informational only or enforce a minimum threshold

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/coverage-reporting
```

### 4. Install And Release Packaging

Priority: medium.

The README now documents `go install`, and release package automation builds Linux amd64, Linux arm64, and macOS arm64 archives when a GitHub release is published.

Recommended progression:

- verify the first package workflow run after publishing `v0.3.2`
- decide whether Linux/macOS amd64 and arm64 are enough for the first public phase
- consider Homebrew only after release binaries and public positioning are more mature
- keep checksums in release assets if binaries are published

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/install-packaging
```

### 5. Additional CLI Smoke Tests

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
- export/import round-trip behavior for shell-escaped special values
- malformed config from the CLI
- `vault doctor`
- audit-log redaction and disabled audit logging
- recovery `setup-recovery`
- recovery `test-recovery`
- recovery `recover`
- concurrent command serialization through `.myminivault.lock`

Additional smoke coverage to consider:

- `security-audit`
- backup/restore expectations if restore is added later

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/cli-smoke-tests-more
```

### 6. Import/Export Format Review

Priority: low-medium.

Status: export is implemented with POSIX single-quote escaping, and import now round-trips that output for quotes, apostrophes, backslashes, `$`, backticks, and embedded newlines.

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

- document safe shell usage and shell history caveats in more detail
- decide whether a future non-shell JSON export format should exist for safer machine round-trips

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/import-export-format
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

Future token sync simplification:

- If `sync-tokens` should become mandatory instead of automatic import, first separate token writes from the shared vault mirror into a pending-write log.
- Per-key timestamps now exist; consider revision counters, merge-base metadata, or fuller delete tombstones before changing the policy further.
- Document the final behavior in the user manual once the policy is stable.

### 8. Memory Exposure Hardening Next Steps

Priority: low-medium.

The project now disables core dumps on supported Unix-like systems as a best-effort mitigation. It still cannot fully prevent memory dumps or same-user process inspection on a normal desktop, especially in Go. The goal is mitigation rather than a hard guarantee.

Ideas to revisit:

- reduce plaintext lifetime in memory where practical
- prefer `[]byte` over `string` for password/secret handling where the code can zero buffers afterward
- add best-effort zeroing for derived keys and password buffers where Go semantics make that meaningful
- evaluate macOS Keychain for protecting `vault-token.key` or a future local wrapping key at rest

Suggested branch:

```bash
git switch main
git pull
git switch -c codex/memory-exposure-next
```

## Product Ideas After Hardening

These are intentionally lower priority than the stability/security work above. Revisit them after documentation cleanup, security review, token sync policy review, and test-depth work are in better shape.

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
test -z "$(gofmt -l .)"
go vet ./...
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
