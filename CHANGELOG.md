# Changelog

All notable project changes are recorded here. Application releases use Git tags such as `v0.1.0`, and the CLI-visible version is kept in sync with the current release tag.

## [v0.1.0] - 2026-05-16

Initial tracked baseline for the current Go CLI.

### Added

- Local encrypted key/value vault CLI under `cmd/vault`.
- Master-password protected commands for `set`, `get`, `delete`, `list`, `search`, `clear`, `import`, `export`, `backup`, and `stats`.
- Password recovery setup, recovery testing, master password recovery, and password change flows.
- Temporary token system with read/write permissions, key pattern restrictions, max-use limits, expiration, token listing, revocation, cleanup, and token info.
- Main/shared token vault synchronization with explicit policy documentation.
- Inter-process file locking through `.myminivault.lock`.
- Automated CLI smoke tests for basic commands, wrong-password handling, token read/write flows, automatic token-write import, shell-safe export, recovery, and concurrent command locking.
- Unit coverage for recovery helpers and shell quoting.
- README and backlog documentation for usage, hardening work, and future product ideas.

### Changed

- Split the original vault monolith into focused files under `cmd/vault`.
- Hardened recovery key generation to use 32 secure random bytes encoded as grouped base32.
- Made recovery file writes atomic.
- Made `export` output shell-safe with POSIX single-quote escaping.
- Clarified the main/shared token vault policy so token writes are staged in the shared vault and imported by master-password commands.

### Fixed

- Prevented `change-password` from immediately overwriting the newly saved password with the old password.
- Prevented deleted keys from being restored from the shared token vault.
- Stopped wrong-password loads from falling back to `vault.db.bak` when `vault.db` exists.
- Added `Sync()` before atomic rename for main vault saves.

### Removed

- Removed the duplicate root monolith `myv.go`.
- Removed the legacy `cmd/splitter` helper after the split was complete.
