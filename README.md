<p align="center">
  <img src="assets/myminivault-pixel.png" alt="myminivault pixel art vault" width="220">
</p>

<h1 align="center">myminivault</h1>

<p align="center">
  A local encrypted command-line vault written in Go.
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white">
  <img alt="Latest release" src="https://img.shields.io/github/v/release/olelbis/myminivault?sort=semver">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-experimental-orange">
  <img alt="CLI" src="https://img.shields.io/badge/interface-CLI-2f3337">
</p>

`myminivault` stores key/value secrets in an encrypted local vault file. It supports password recovery, temporary access tokens, backup/import/export utilities, and basic security auditing.

> Experimental personal project. Not audited. Do not rely on it as a production password manager.

## Preview

![Quick start terminal screenshot](assets/screenshots/quickstart.svg)

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

## Quick Start

Create or update a secret:

```bash
./bin/vault set API_KEY secret-value
```

Read it back:

```bash
./bin/vault get API_KEY
```

List keys without printing values:

```bash
./bin/vault list
```

Create a backup:

```bash
./bin/vault backup
```

## Common Commands

| Command | Purpose |
| --- | --- |
| `set <key> <value>` | Store or update a value |
| `get <key>` | Print a stored value |
| `delete <key>` | Delete a key |
| `list` | List key names |
| `search <pattern>` | Search keys |
| `backup` | Create a timestamped backup |
| `export` | Print shell-safe export lines |
| `import <file>` | Import values from a file |
| `setup-recovery` | Create a recovery key |
| `recover` | Reset the master password with the recovery key |
| `create-token` | Create temporary token access |
| `use-token` | Use a temporary token |
| `security-audit` | Print local vault status |
| `doctor` | Check runtime file permissions and local health |

## Screenshots

![Token workflow terminal screenshot](assets/screenshots/token-flow.svg)

![Recovery workflow terminal screenshot](assets/screenshots/recovery.svg)

## Documentation

- [User Manual](docs/user-manual.md)
- [Development Guide](docs/development.md)
- [Security Model](docs/security.md)
- [Recovery Policy](docs/recovery-policy.md)
- [Token Sync Policy](docs/token-sync-policy.md)
- [Changelog](CHANGELOG.md)
- [Backlog](BACKLOG.md)

## Runtime Files

The CLI stores runtime files in the current working directory where the command is executed. These files are ignored by Git because they may contain encrypted secrets, keys, logs, or local runtime state.

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

## Versioning

Application releases use Git tags such as `v0.2.0` and are documented in `CHANGELOG.md`.

The CLI-visible version is kept in sync with the current release tag. When the vault file format changes, the version should be updated together with migration notes in the changelog.

## License

MIT. See [LICENSE](LICENSE).
