<p align="center">
  <img src="assets/myminivault-pixel.png" alt="myminivault pixel art vault" width="220">
</p>

<h1 align="center">myminivault</h1>

<p align="center">
  A local encrypted command-line vault written in Go.
</p>

<p align="center">
  <img alt="CI" src="https://github.com/olelbis/myminivault/actions/workflows/ci.yml/badge.svg">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white">
  <img alt="Latest release" src="https://img.shields.io/github/v/release/olelbis/myminivault?sort=semver">
  <img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/olelbis/myminivault.svg">
  <img alt="Internal coverage" src="https://img.shields.io/badge/internal_coverage-70.8%25-yellowgreen">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-experimental-orange">
  <img alt="CLI" src="https://img.shields.io/badge/interface-CLI-2f3337">
</p>

`myminivault` stores key/value secrets in an encrypted local vault file. It supports password recovery, temporary access tokens, backup/import/export utilities, and basic security auditing.

> Experimental personal project. Not audited. Do not rely on it as a production password manager.

## Preview

![Quick start terminal screenshot](assets/screenshots/quickstart.svg)

## Build

Install the latest tagged release with Go:

```bash
go install github.com/olelbis/myminivault/cmd/vault@latest
```

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
| `copy <key>` | Copy a value to the clipboard without printing it |
| `delete <key>` | Delete a key |
| `list` | List key names |
| `search <pattern>` | Search keys |
| `backup` | Create a timestamped backup |
| `export` | Print shell-safe export lines or write them to a file |
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
- [Coverage Notes](docs/coverage.md)
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

`myminivault` uses `v0.x.y` releases while the CLI is still evolving.

Each release is published as a Git tag and a GitHub Release, with notes recorded in `CHANGELOG.md`. Release assets currently include Linux and macOS archives plus SHA-256 checksum files.

The CLI-visible version is kept in sync with the current release tag. Patch releases are used for documentation, tests, packaging, fixes, and small refactors. Minor releases are reserved for user-facing behavior changes or larger security/compatibility work.

If the vault file format changes, the release notes should include migration guidance and any compatibility limits.

## License

MIT. See [LICENSE](LICENSE).

## Credits

Created and maintained by [olelbis](https://github.com/olelbis).
