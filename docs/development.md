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
    commands.go         basic key/value commands, import/export, stats
    config_cli.go       config loading/display
    crypto.go           compatibility wrappers for internal crypto
    recovery_cli.go     recovery and password-change CLI flows
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

## Architecture Notes

`cmd/vault` owns command-line interaction: argument parsing, prompts, output, and command orchestration.

`internal/...` packages own reusable behavior:

- `internal/config`: config defaults, JSON loading, validation
- `internal/crypto`: scrypt, AES-GCM, secure random bytes
- `internal/model`: persisted data structures
- `internal/recovery`: recovery keys, verifier checks, recovery snapshot decrypt, recovery file write
- `internal/storage`: main vault load/save, checksum, atomic writes
- `internal/token`: token signing, validation, registry, encrypted shared token vault

The project still keeps some orchestration in `cmd/vault`, especially sync and command behavior. Future extractions should happen only when tests cover the behavior well enough.

## Cryptography

The vault currently uses:

- AES-GCM for authenticated encryption
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
go test ./cmd/vault -run TestCLISmokeTokenReadAndWrite
go test ./cmd/vault -run TestCLISmokeSetupAndTestRecovery
go test ./cmd/vault -run TestCreateShortSignedTokenRoundTrip
```

Run with verbose output when diagnosing a failure:

```bash
go test -v ./cmd/vault -run TestCLISmokeTokenReadAndWrite
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
printf 'oldpass\n' | ./vault get TEST_KEY
```

The automated CLI smoke tests create temporary directories and fake data. Do not run manual smoke commands in a directory that contains real vault files unless that is intentional.

Current automated checks cover CLI smoke flows, token lifecycle behavior, config error handling, basic import/export round trips, core unit behavior, and package-level coverage for `internal/storage`, `internal/token`, and `internal/recovery`.

## Branch Workflow

Use `main` as the stable base branch.

Create a focused branch for each backlog item:

```bash
git switch main
git pull
git switch -c codex/<task-name>
```

Keep branches small and merge with fast-forward when possible.

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
12. Delete the completed branch locally and remotely.

Current versioning style:

- use `v0.x.y` while the CLI is evolving quickly
- patch releases such as `v0.1.21` for docs, tests, fixes, and small refactors
- reserve minor releases such as `v0.2.0` for user-facing behavior changes

## Runtime Files

Runtime files are ignored by Git and should not be committed:

- `vault.db`
- `vault.db.bak`
- `vault.db.recovery`
- `vault-token.key`
- `shared-token-vault.json`
- `vault-tokens.json`
- `vault.log`
- `vault-config.json`
- `.myminivault.lock`

## Documentation Assets

README images live in:

- `assets/myminivault-pixel.png`
- `assets/screenshots/*.svg`

Screenshots are terminal-style SVGs rather than captured runtime secrets. Keep them synthetic and avoid real secret values.
