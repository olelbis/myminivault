# myminivault User Manual

`myminivault` is a local command-line vault for key/value secrets. It is intended as a personal, local tool.

> Experimental personal project. Not audited. Do not rely on it as a production password manager.

## Build And Run

Build the CLI from the repository root:

```bash
go build -o bin/vault ./cmd/vault
```

Show help:

```bash
./bin/vault help
```

## Password Model

Most commands ask for the master password. If the vault does not exist yet, entering a new password creates it. Use the same password for later commands.

```bash
./bin/vault set API_KEY secret-value
```

## Basic Workflows

### Set A Secret

```bash
./bin/vault set API_KEY secret-value
```

Keys must:

- not be empty
- be at most 255 characters
- not contain spaces, quotes, backslashes, `=`, `:`, `;`, or `,`

### Get A Secret

```bash
./bin/vault get API_KEY
```

### Delete A Secret

```bash
./bin/vault delete API_KEY
```

Deletes a key from the main vault and mirrors the updated main vault to the shared token vault when token runtime files exist.

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

Shows vault metadata, recovery status, token summary, access count, and timestamps.

## Import And Export

### Export

```bash
./bin/vault export
```

Prints entries as shell-safe `export KEY='value'` lines. Export uses POSIX single-quote escaping, so values containing quotes, `$`, backticks, backslashes, and newlines are printed without triggering shell expansion.

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

Recovery can recover only the snapshot stored in `vault.db.recovery`. If the main vault and recovery snapshot diverge, recovery behavior follows the recovery snapshot.

### Change Master Password

```bash
./bin/vault change-password
```

Prompts for the current master password first, then asks for the new password and confirmation.

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

| Option | Required | Description |
| --- | --- | --- |
| `--keys=<pattern>` | Yes | Key pattern. `*` is supported as a wildcard |
| `--duration=<duration>` | Yes | Go duration such as `30m`, `2h`, `24h` |
| `--permissions=read,write` | No | Defaults to `read` |
| `--max-uses=N` | No | Defaults to `100` |

Maximum token duration is 24 hours.

### Use Token

Read a key:

```bash
./bin/vault use-token <token> get API_KEY
```

Write a key:

```bash
./bin/vault use-token <token> set API_KEY new-value
```

List accessible keys:

```bash
./bin/vault use-token <token> list
```

Search accessible keys:

```bash
./bin/vault use-token <token> search API
```

### Manage Tokens

```bash
./bin/vault list-tokens
./bin/vault token-info <token-id>
./bin/vault revoke-token <token-id>
./bin/vault cleanup-tokens
```

Regenerate the token master key:

```bash
./bin/vault regenerate-token-key
```

This invalidates all existing tokens.

## Main And Shared Vault Synchronization

The CLI keeps a main vault and a shared token vault:

- `vault.db` is the main password-protected vault
- `shared-token-vault.json` is an encrypted shared vault used for token commands

Commands that mutate the main vault, such as `set`, `delete`, `clear`, and `import`, mirror the main vault back to the shared token vault after saving only when token runtime files already exist or token data is configured.

Token write operations save immediately to the shared token vault. Master-password commands import token-side changes from the shared vault before running, and you can also import them explicitly with:

```bash
./bin/vault sync-tokens
```

Sync policy:

- `vault.db` is the master-password source of truth after a master command saves
- token writes are staged in `shared-token-vault.json`
- master commands import staged token writes before they execute
- ordinary password commands do not create token runtime files until token features are used
- master mutations mirror the full main vault back to the shared vault after saving once token runtime files exist, so deletes remain deleted
- conflict handling is currently last-writer-wins at the vault-key level

## Locking And Concurrent CLI Usage

Vault commands use `.myminivault.lock` to serialize separate CLI processes while they access runtime vault files. This reduces cross-process write races around `vault.db`, token files, and the shared token vault.

## Security Audit

```bash
./bin/vault security-audit
```

Reports recovery status, token status, vault key count, access count, vault version, last access time, and runtime file presence.

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

## Runtime Files

| File | Purpose |
| --- | --- |
| `vault.db` | Main encrypted vault |
| `vault.db.bak` | Backup of previous main vault version |
| `vault.db.recovery` | Recovery-encrypted vault copy |
| `vault-token.key` | Local token master key |
| `shared-token-vault.json` | Encrypted shared vault used by token access |
| `vault-tokens.json` | Token registry metadata |
| `vault.log` | Audit log |
| `vault-config.json` | Optional config override |
| `.myminivault.lock` | Inter-process lock file |

These files are ignored by Git because they may contain encrypted secrets, keys, logs, or local runtime state.

## Troubleshooting

### Wrong Password

If `vault.db` exists and the password is wrong, the CLI rejects access. It does not silently fall back to `vault.db.bak`.

### Missing Runtime Files

If no vault exists, the first password-protected write creates one. Token runtime files are created only when token features are used.

### Token Changes Not Visible

Run:

```bash
./bin/vault sync-tokens
```

Master-password commands also import staged token writes before running.

### Recovery Key Does Not Work

Check whether recovery was configured and whether `vault.db.recovery` exists. Recovery can recover only the recovery-encrypted snapshot.
