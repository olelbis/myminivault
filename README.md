# myminivault

`myminivault` is a local command-line vault written in Go. It stores key/value secrets in an encrypted vault file, supports password recovery, temporary access tokens, backup/import/export utilities, and basic security auditing.

The main CLI lives in `cmd/vault`.

## Versioning

Application releases use Git tags such as `v0.1.13` and are documented in `CHANGELOG.md`.

The CLI-visible version is kept in sync with the current release tag. When the vault file format changes, the version should be updated together with migration notes in the changelog.

## Current Status

The vault command has been split from a monolithic source file into focused files under `cmd/vault` while keeping the package as `main`.

The current implementation supports the full CLI flow, but the project should still be treated as a local/personal vault rather than a hardened production password manager. Some areas, especially recovery and cross-process locking, are marked in this README as operational notes.

## Build

Build the CLI from the repository root:

```bash
go build -o bin/vault ./cmd/vault
```

Run it:

```bash
./bin/vault help
```

For development, you can also run it directly:

```bash
go run ./cmd/vault help
```

## Files Created At Runtime

The CLI stores runtime files in the current working directory where the command is executed.

| File | Purpose |
| --- | --- |
| `vault.db` | Main encrypted vault |
| `vault.db.bak` | Backup of previous main vault version |
| `vault.db.recovery` | Recovery-encrypted vault copy, when recovery is configured |
| `vault-token.key` | Local token master key, created when token features are used |
| `shared-token-vault.json` | Encrypted shared vault used by token access, created when token features are used |
| `vault-tokens.json` | Token registry metadata, created when tokens are created |
| `vault.log` | Audit log |
| `vault-config.json` | Optional config override |
| `.myminivault.lock` | Inter-process lock file used while vault commands run |

These files are ignored by Git because they may contain encrypted secrets, keys, logs, or local runtime state.

## Password Model

Most commands ask for the master password. If the vault does not exist yet, entering a new password creates it.

Example:

```bash
./bin/vault set API_KEY secret-value
```

The CLI prompts:

```text
Password:
```

Use the same password for later commands.

## Basic Commands

### Set A Secret

```bash
./bin/vault set API_KEY secret-value
```

Stores a key/value pair in the encrypted vault.

Keys must:

- not be empty
- be at most 255 characters
- not contain spaces, quotes, backslashes, `=`, `:`, `;`, or `,`

### Get A Secret

```bash
./bin/vault get API_KEY
```

Prints the stored value for the key.

### Delete A Secret

```bash
./bin/vault delete API_KEY
```

Deletes a key from the main vault and mirrors the updated main vault to the shared token vault.

### List Keys

```bash
./bin/vault list
```

Lists key names only. Values are not printed.

### Search Keys

```bash
./bin/vault search API
```

Searches keys by case-insensitive substring and prints matching key/value pairs.

### Clear Vault

```bash
./bin/vault clear
```

Deletes all entries after confirmation.

### Stats

```bash
./bin/vault stats
```

Shows vault metadata:

- number of keys
- vault version
- created timestamp
- access count
- last access timestamp
- recovery status
- token summary

## Import And Export

### Export

```bash
./bin/vault export
```

Prints entries as shell-safe `export KEY='value'` lines.

Operational note: export uses POSIX single-quote escaping, so values containing quotes, `$`, backticks, backslashes, and newlines are printed without triggering shell expansion.

### Import

```bash
./bin/vault import secrets.env
```

Imports lines in either format:

```text
API_KEY=secret-value
export API_KEY="secret-value"
```

Blank lines and lines starting with `#` are ignored.

## Backup

Create a timestamped backup of `vault.db`:

```bash
./bin/vault backup
```

The backup filename looks like:

```text
vault.db.2026-05-15_22-30-00.bak
```

The normal save path also keeps `vault.db.bak` as the previous version of the vault. The loader uses `vault.db.bak` only when `vault.db` is missing, not as a fallback for wrong passwords.

## Password Recovery

### Setup Recovery

```bash
./bin/vault setup-recovery
```

Generates a high-entropy recovery key and asks you to retype it to confirm that you saved it. The key is a grouped base32 string derived from 32 secure random bytes.

### Test Recovery

```bash
./bin/vault test-recovery
```

Checks whether a recovery key matches the configured recovery data.

### Recover Master Password

```bash
./bin/vault recover
```

Uses the recovery key to decrypt the recovery vault copy and set a new master password.

### Change Master Password

```bash
./bin/vault change-password
```

Prompts for the current master password first, then asks for the new password and confirmation.

Operational note: recovery uses a high-entropy recovery key, writes the recovery file atomically, and has end-to-end smoke coverage for `setup-recovery`, `test-recovery`, and `recover`.

## Token System

The token system creates temporary signed tokens that can access only matching keys and only with selected permissions.

Token access uses:

- a compact signed token string
- token expiration time
- max-use limits
- key pattern restrictions
- read/write permissions
- encrypted shared token vault

### Create Token

```bash
./bin/vault create-token --keys="API_*" --duration="2h" --permissions="read" --max-uses=20
```

Arguments:

| Option | Required | Description |
| --- | --- | --- |
| `--keys=<pattern>` | Yes | Key pattern. `*` is supported as a wildcard |
| `--duration=<duration>` | Yes | Go duration such as `30m`, `2h`, `24h` |
| `--permissions=read,write` | No | Defaults to `read` |
| `--max-uses=N` | No | Defaults to `100` |

Maximum token duration is 24 hours.

Examples:

```bash
./bin/vault create-token --keys="API_*" --duration="2h" --permissions="read"
./bin/vault create-token --keys="*" --duration="1h" --permissions="read,write" --max-uses=50
```

### Use Token To Read

```bash
./bin/vault use-token <token> get API_KEY
```

### Use Token To Write

```bash
./bin/vault use-token <token> set API_KEY new-value
```

Requires a token with `write` permission and a matching key pattern.

### Use Token To List Accessible Keys

```bash
./bin/vault use-token <token> list
```

### Use Token To Search

```bash
./bin/vault use-token <token> search API
```

### List Tokens

```bash
./bin/vault list-tokens
```

Shows active, expired, and used-up token status.

### Token Info

```bash
./bin/vault token-info <token-id>
```

Prints token details:

- ID
- key pattern
- permissions
- creation time
- expiration time
- usage count
- status

### Revoke Token

```bash
./bin/vault revoke-token <token-id>
```

Removes a token from the vault.

### Cleanup Tokens

```bash
./bin/vault cleanup-tokens
```

Removes expired or fully used tokens.

### Regenerate Token Key

```bash
./bin/vault regenerate-token-key
```

Generates a new token master key. This invalidates all existing tokens.

## Synchronization

The CLI keeps a main vault and a shared token vault:

- `vault.db` is the main password-protected vault
- `shared-token-vault.json` is an encrypted shared vault used for token commands

Commands that mutate the main vault, such as `set`, `delete`, `clear`, and `import`, mirror the main vault back to the shared token vault after saving only when token runtime files already exist or token data is configured.

Token write operations save immediately to the shared token vault. Master-password commands import token-side changes from the shared vault before running, and you can also import them explicitly with:

```bash
./bin/vault sync-tokens
```

Operational note: vault commands use `.myminivault.lock` to serialize separate CLI processes while they access runtime vault files. This reduces cross-process write races around `vault.db`, token files, and the shared token vault.

Sync policy:

- `vault.db` is the master-password source of truth after a master command saves.
- token writes are staged in `shared-token-vault.json`.
- master commands import staged token writes before they execute.
- ordinary password commands do not create token runtime files until token features are used.
- master mutations mirror the full main vault back to the shared vault after saving once token runtime files exist, so deletes remain deleted.
- conflict handling is currently last-writer-wins at the vault-key level.

## Security Audit

```bash
./bin/vault security-audit
```

Reports:

- recovery status
- active/expired token counts
- token master key presence
- vault key count and access count
- vault version
- last access time
- main vault file status
- recovery file status
- shared token vault status

## Configuration

Show current config:

```bash
./bin/vault config
```

Default values:

| Setting | Default |
| --- | --- |
| `scrypt_n` | `32768` |
| `scrypt_r` | `8` |
| `scrypt_p` | `1` |
| `key_size` | `32` |
| `max_backups` | `5` |

The program can load `vault-config.json` from the current working directory.

Config validation:

- `scrypt_n` must be a power of two between `32768` and `1048576`
- `scrypt_r` must be between `1` and `16`
- `scrypt_p` must be between `1` and `8`
- `key_size` must be `16`, `24`, or `32`
- `max_backups` must be between `1` and `100`

If `vault-config.json` is malformed or unsafe, the CLI stops with a config error.

## Cryptography

The vault currently uses:

- AES-GCM for authenticated encryption
- scrypt for key derivation
- SHA-256 checksums over serialized vault data
- HMAC-SHA256 for token signatures
- random salt per vault encryption
- random nonce per AES-GCM encryption

## Development

Use `main` as the stable base branch. Create a focused branch for each backlog item:

```bash
git switch main
git pull
git switch -c codex/recovery-setup-test
```

Run all package checks:

```bash
go test ./...
```

Build the vault command:

```bash
go build -o bin/vault ./cmd/vault
```

Suggested isolated smoke-test pattern:

```bash
tmpdir=$(mktemp -d /tmp/myminivault-smoke-XXXXXX)
go build -o "$tmpdir/vault" ./cmd/vault
cd "$tmpdir"
printf 'oldpass\n' | ./vault set TEST_KEY hello
printf 'oldpass\n' | ./vault get TEST_KEY
```

## Project Layout

```text
cmd/
  vault/
    main.go       CLI dispatch and top-level command flow
    commands.go   basic key/value commands, import/export, stats
    config_cli.go       config loading/display
    crypto.go     encryption, decryption, random bytes, key derivation
    recovery_cli.go     recovery key and password change flows
    storage_bridge.go   main vault load/save wrappers
    sync.go       main/shared vault synchronization
    token_cli.go        token creation, validation, token commands
    types.go      compatibility aliases for shared data structures
internal/
  config/
    config.go     config defaults, loading, and validation
  crypto/
    crypto.go     key derivation, encryption, decryption, secure random bytes
  model/
    model.go      vault, recovery, token, and metadata structs
  recovery/
    recovery.go   recovery keys, recovery vault decryption, and recovery file writes
  storage/
    storage.go    vault load/save, checksum, and atomic writes
  token/
    token.go      token signing, validation, registry, and shared token vault persistence
```

## Recommended Next Hardening Work

Recommended follow-up tasks:

- rewrite documentation into a concise README plus dedicated user and development docs
