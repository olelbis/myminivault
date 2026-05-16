# Changelog

All notable project changes are recorded here. Application releases use Git tags such as `v0.2.0`, and the CLI-visible version is kept in sync with the current release tag.

## [v0.2.0] - 2026-05-16

### Added

- Added `vault doctor` to check runtime file permissions, config health, lock-file presence, backups, recovery, token files, and logs.
- Added CLI smoke coverage for `vault doctor`.

### Changed

- Hardened sensitive runtime file writes to prefer `0600` permissions for main vaults, backups, shared token vaults, and logs.

## [v0.1.21] - 2026-05-16

### Added

- Added `docs/recovery-policy.md` documenting recovery snapshot behavior, divergence semantics, verifier policy, and rotation caveats.

### Changed

- Linked the recovery policy from README, user manual, security model, and development docs.

## [v0.1.20] - 2026-05-16

### Added

- Added CLI smoke coverage for expired tokens, used-up tokens, token revocation, `list-tokens`, and `token-info`.
- Added CLI smoke coverage for malformed config handling.
- Added a basic import/export round-trip smoke test.

## [v0.1.19] - 2026-05-16

### Added

- Added package-level tests for `internal/storage`, `internal/token`, and `internal/recovery`.
- Added crypto coverage for tampered ciphertext rejection.

### Fixed

- Fixed legacy vault loading for old JSON payloads longer than the checksum prefix size.

## [v0.1.18] - 2026-05-16

### Added

- Added `docs/token-sync-policy.md` documenting the current main/shared vault sync policy, conflict behavior, delete semantics, and deferred decisions.

### Changed

- Clarified token command output and help text around staged token writes and `sync-tokens`.

## [v0.1.17] - 2026-05-16

### Added

- Added `docs/security.md` with the current security model, non-goals, sensitive assets, runtime-file risks, recovery limits, token boundaries, and compromise guidance.

### Changed

- Linked the security model from README and docs.

## [v0.1.16] - 2026-05-16

### Changed

- Expanded `docs/development.md` with practical commands for running the full suite, package tests, focused tests, verbose tests, cache-cleared tests, and manual smoke checks.

## [v0.1.15] - 2026-05-16

### Added

- Added `docs/user-manual.md` and `docs/development.md`.
- Added terminal-style SVG screenshots for quick start, token, and recovery workflows.

### Changed

- Reworked `README.md` into a concise project overview with links to detailed docs.

## [v0.1.14] - 2026-05-16

### Added

- Added MIT license.
- Added README badges and a project-local pixel art vault image.

### Changed

- Refreshed the README header with a concise tagline and experimental security caveat.

## [v0.1.13] - 2026-05-16

### Changed

- Reorganized `BACKLOG.md` around project assessment, risks, strategic guidance, and prioritized next steps.
- Moved product ideas below documentation, security, token sync policy, and test-depth work.

## [v0.1.12] - 2026-05-16

### Changed

- Renamed `cmd/vault` CLI wrapper files to distinguish them from similarly named `internal/...` packages.
- Kept internal package file names unchanged to follow Go package conventions.

## [v0.1.11] - 2026-05-16

### Changed

- Moved recovery key generation, validation, recovery vault decryption, and recovery file writes into `internal/recovery`.
- Kept recovery prompts and password-change CLI output in `cmd/vault`.

## [v0.1.10] - 2026-05-16

### Changed

- Moved token signing, validation, registry, and encrypted shared token vault helpers into `internal/token`.
- Kept CLI token handlers in `cmd/vault` while the refactor continues.

## [v0.1.9] - 2026-05-16

### Changed

- Moved vault load/save, checksum, and atomic write helpers into `internal/storage`.
- Kept compatibility wrappers in `cmd/vault` while the refactor continues.

## [v0.1.8] - 2026-05-16

### Changed

- Moved shared vault, recovery, token, and metadata structs into `internal/model`.
- Kept compatibility aliases in `cmd/vault` while the rest of the refactor continues.

## [v0.1.7] - 2026-05-16

### Added

- Added end-to-end CLI smoke coverage for `change-password`.
- Added backlog note for post-refactor documentation cleanup.

## [v0.1.6] - 2026-05-16

### Changed

- Moved config loading and validation into `internal/config`.
- Added concise English comments around config default/override behavior.

## [v0.1.5] - 2026-05-16

### Changed

- Moved core crypto helpers into `internal/crypto`.
- Added concise English comments around crypto boundaries and ciphertext layout.

## [v0.1.4] - 2026-05-16

### Added

- Added unit tests for crypto roundtrip and decrypt failure cases.
- Added unit tests for token pattern matching, token signing, and permission helper behavior.
- Added unit tests for key validation and import parsing.

## [v0.1.3] - 2026-05-16

### Added

- Added end-to-end CLI smoke coverage for `setup-recovery` and `test-recovery`.

## [v0.1.2] - 2026-05-16

### Added

- Added validation for `vault-config.json`, including malformed JSON, scrypt bounds, AES key size, and backup count.
- Added unit tests for config validation and loading.

## [v0.1.1] - 2026-05-16

### Changed

- Avoid creating token runtime files during ordinary master-password commands before token features are used.

### Added

- Added smoke coverage to verify ordinary password commands do not initialize token runtime files.

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
