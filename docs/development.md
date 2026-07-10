# myminivault Development Guide

This document captures architecture, test, and release workflow notes for future development sessions.

## Project Layout

```text
assets/
  myminivault-pixel.png README pixel art vault image
  screenshots/          README terminal-style screenshots
cmd/
  vault/
    main.go             CLI dispatch and top-level command flow
    command_policy.go   command logging and shared-vault mirror policy
    commands.go         basic key/value commands, import/export, stats
    config_cli.go       config loading/display
    core_dump_unix.go   best-effort core dump disabling on Unix-like systems
    core_dump_other.go  no-op core dump hook for unsupported systems
    crypto.go           compatibility wrappers for internal crypto
    doctor_cli.go       local runtime health checks
    recovery_cli.go     recovery and password-change CLI flows
    storage_bridge.go   main vault load/save wrappers
    sync.go             main/shared vault synchronization
    token_execute_cli.go token command execution and JSON/plaintext output policy
    token_key_cli.go     token master-key storage and keychain selection
    token_manage_cli.go  token creation, revocation, listing, audit status
    types.go            compatibility aliases for shared data structures
internal/
  config/
    config.go           config defaults, loading, and validation
  container/
    container.go        cleartext MYMV runtime file framing
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
  lock/
    lock.go             advisory file lock helper with timeout support
  paths/
    paths.go            runtime home resolution and secure directory creation
  audit/
    audit.go            redacted audit log formatting and writes
  sync/
    sync.go             sync metadata and shared-vault import policy helpers
  commands/
    commands.go         export/import/key validation helpers
  clipboard/
    clipboard.go        clipboard backend detection and clear-if-unchanged helper
  export/
    export.go           shell export rendering and restrictive export-file writes
  keychain/
    keychain.go         OS keychain detection and macOS token key storage
  health/
    metadata.go         non-decrypting runtime health metadata checks
docs/
  man/
    vault.1              manual page installed by release packages
  user-manual.md        user-facing workflows and operational notes
  development.md        architecture, test, and release workflow notes
  security.md           security model, assumptions, limits, and compromise guidance
  recovery-policy.md    recovery snapshot, verifier, divergence, and rotation policy
  token-sync-policy.md  main/shared token vault sync policy and deferred decisions
```

## Architecture Notes

`cmd/vault` owns command-line interaction: argument parsing, prompts, output, and command orchestration.

`internal/...` packages own reusable behavior:

- `internal/config`: config defaults, JSON loading, validation
- `internal/container`: cleartext `MYMV` framing for encrypted runtime files
- `internal/crypto`: scrypt, AES-GCM, secure random bytes
- `internal/model`: persisted data structures
- `internal/recovery`: recovery keys, verifier checks, recovery snapshot decrypt, recovery file write
- `internal/storage`: main vault load/save, checksum, atomic writes, legacy payload parsing
- `internal/token`: token signing, validation, registry, encrypted shared token vault
- `internal/lock`: advisory file locking with timeout support for cooperating local CLI processes
- `internal/audit`: redacted audit log formatting and writes
- `internal/sync`: sync metadata and shared-vault import policy helpers
- `internal/commands`: export/import/key validation helpers
- `internal/clipboard`: clipboard backend detection and best-effort clearing
- `internal/export`: shell export rendering and restrictive export-file writes
- `internal/keychain`: OS keychain availability detection and macOS token master-key storage through the `security` tool
- `internal/health`: reusable runtime health checks that do not decrypt secrets

The project still keeps command-line parsing, prompts, output, and top-level orchestration in `cmd/vault`. Future extractions should happen only when tests cover the behavior well enough.

Encrypted runtime file framing lives in `internal/container`. Current saves write a cleartext `MYMV v2` container header containing the container version, file kind, and non-sensitive crypto metadata before the existing salt+ciphertext payload. That v2 cleartext context is authenticated with AES-GCM AAD, so header or metadata tampering fails during decryption. Legacy salt+ciphertext files and earlier `MYMV v1` files remain readable, and `vault doctor` plus `vault inspect-runtime` use the header for non-decrypting format inspection.

## Cryptography

The vault currently uses:

- AES-GCM for authenticated encryption
- AES-GCM AAD for current container header, metadata, and salt authentication
- scrypt for key derivation
- SHA-256 checksums over serialized vault data
- HMAC-SHA256 for token signatures
- random salt per vault encryption
- random nonce per AES-GCM encryption

This project is not security-audited. Security claims should stay conservative until an external review exists.

See [Security Model](security.md) for current assumptions, non-goals, sensitive runtime files, and known limitations. See [Recovery Policy](recovery-policy.md) for recovery snapshot and rotation semantics.

## Test Workflow

Run the full test suite from the repository root:

```bash
go test ./...
```

Use an isolated Go build cache when you want repeatable local checks that do not touch the default user cache:

```bash
GOCACHE=/private/tmp/myminivault-gocache go test ./...
```

Run tests for a single package:

```bash
go test ./cmd/vault
go test ./internal/crypto
go test ./internal/config
```

Run one focused test by name:

```bash
go test ./tests -run TestCLISmokeTokenReadAndWrite
go test ./tests -run TestCLISmokeSetupAndTestRecovery
go test ./cmd/vault -run TestCreateShortSignedTokenRoundTrip
```

Run with verbose output when diagnosing a failure:

```bash
go test -v ./tests -run TestCLISmokeTokenReadAndWrite
```

Run the coverage gate locally:

```bash
go test -covermode=atomic -coverprofile=internal-coverage.out ./internal/...
go tool cover -func=internal-coverage.out
```

Clear the Go test cache if a cached result is hiding a behavior change:

```bash
go clean -testcache
go test ./...
```

Build the vault command:

```bash
go build -o bin/vault ./cmd/vault
```

Suggested manual smoke-test pattern in an isolated temporary directory:

```bash
tmpdir=$(mktemp -d /tmp/myminivault-smoke-XXXXXX)
go build -o "$tmpdir/vault" ./cmd/vault
cd "$tmpdir"
printf 'oldpass\n' | ./vault set TEST_KEY hello
printf 'oldpass\n' | ./vault get TEST_KEY --show
```

The automated CLI smoke tests live in `./tests`, create temporary directories, and use fake data. Do not run manual smoke commands in a directory that contains real vault files unless that is intentional.

Current automated checks cover CLI smoke flows, token lifecycle behavior, token JSON output, config error handling, `vault doctor`, `vault inspect-runtime`, shell-safe import/export round trips, export-to-file behavior, clipboard clear behavior, audit-log redaction, disabled audit logging, token sync metadata decisions, token master-key and compact-token helper behavior, core unit behavior, and package-level coverage for `internal/storage`, `internal/token`, `internal/recovery`, `internal/lock`, `internal/audit`, `internal/sync`, `internal/commands`, `internal/clipboard`, `internal/export`, `internal/container`, `internal/paths`, `internal/config`, and `internal/keychain`. CI enforces `80.0%` minimum coverage for `./internal/...`.

## Branch Workflow

Use `main` as the stable base branch.

Create a focused branch for each backlog item:

```bash
git switch main
git pull
git switch -c <task-name>
```

Keep branches small and merge with fast-forward when possible.

Docs-only maintenance can be committed directly on `main` when it only changes documentation or handoff notes and does not change Go code, workflows, release assets, generated package contents, CLI-visible behavior, version numbers, or tests. Examples include backlog cleanup, README wording, user manual clarification, development notes, and threat-model wording that documents existing behavior.

Create a normal task branch and release tag when a change affects executable behavior, packaging, CI workflows, tests, versioned man-page content, or generated release artifacts.

## Release Workflow

For each completed branch:

1. Update the CLI-visible version in `cmd/vault/config_cli.go`.
2. Update the help banner in `cmd/vault/main.go`.
3. Update `CHANGELOG.md`.
4. Update `BACKLOG.md` when project state or priorities change.
5. Run `go test ./...`.
6. Commit the branch.
7. Push the branch.
8. Fast-forward merge to `main`.
9. Run `go test ./...` again on `main`.
10. Create and push the release tag.
11. Create the GitHub release.
12. Wait for the release package workflow to upload archives, `.deb`, `.rpm`, `.pkg`, per-target checksums, the aggregate `SHA256SUMS` manifest, and artifact attestations.
13. Delete the completed branch locally and remotely.

Current versioning style:

- use `v0.x.y` while the CLI is evolving quickly
- patch releases such as `v0.3.1` for docs, tests, fixes, and small refactors after `v0.3.0`
- reserve minor releases such as `v0.3.0` for user-facing behavior changes

Release packaging currently publishes:

- `.tar.gz` archives for Linux amd64, Linux arm64, and macOS arm64
- `.deb` packages for Linux amd64 and Linux arm64
- `.rpm` packages for Linux x86_64 and Linux aarch64
- `.pkg` packages for macOS arm64
- SHA-256 checksum manifests for each target
- an aggregate `SHA256SUMS` manifest and GitHub artifact attestations for workflow-built artifacts

## Runtime Files

Runtime files live in `~/.myminivault/` by default. Set `MYMINIVAULT_HOME=/path/to/dir` to isolate a development or test run from the real user runtime directory.

Examples:

```bash
MYMINIVAULT_HOME="$(mktemp -d /tmp/myminivault-dev-XXXXXX)" go test ./tests
MYMINIVAULT_HOME=/tmp/myminivault-manual go run ./cmd/vault set DEV_KEY hello
MYMINIVAULT_HOME=/tmp/myminivault-manual go run ./cmd/vault config
MYMINIVAULT_HOME=/tmp/myminivault-manual go run ./cmd/vault inspect-runtime
```

Development notes:

- tests should set `MYMINIVAULT_HOME` when executing the compiled CLI
- do not point development runs at the real `~/.myminivault/` unless you intend to use real local vault state
- path resolution lives in `internal/paths`
- CLI globals are initialized by `initRuntimePaths`
- runtime inspection output lives in `cmd/vault/runtime_inspect.go`
- recovery freshness and compatibility checks live in `cmd/vault/doctor_cli.go` and are reused by `inspect-runtime`
- legacy cwd migration is intentionally conservative and skips files when the runtime-home target already exists

Runtime files are ignored by Git and should not be committed:

- `vault.db`
- `vault.db.bak`
- `vault.db.recovery`
- `vault-token.key` when file-backed token key storage is used
- `shared-token-vault.json`
- `shared-token-vault.json.bak`
- `vault-tokens.json`
- `vault.log`
- `vault-config.json`
- `.myminivault.lock`

## Documentation Assets

README images live in:

- `assets/myminivault-pixel.png`
- `assets/screenshots/*.svg`

Screenshots are terminal-style SVGs rather than captured runtime secrets. Keep them synthetic and avoid real secret values.
