# Changelog

All notable project changes are recorded here. Application releases use Git tags such as `v0.3.0`, and the CLI-visible version is kept in sync with the current release tag.

## [v0.4.7] - 2026-05-22

### Added

- Added `token_key_storage` config validation with `auto`, `file`, and `keychain` modes.
- Added best-effort OS keychain detection for future token master-key storage.
- Added `vault doctor` reporting for token key storage mode, keychain availability, and file fallback status.
- Added focused coverage for keychain detection and token key storage config validation.

### Changed

- Documented that this release detects and reports OS keychain availability but does not move `vault-token.key` storage yet.
- Made explicit `token_key_storage="keychain"` fail token commands clearly until real keychain storage is implemented.
- Updated coverage baselines to `35.6%` full repository and `83.0%` internal packages.
- Updated the CLI-visible version to `0.4.7`.

## [v0.4.6] - 2026-05-20

### Added

- Added a cleartext `MYMV` container header with a container version and file kind for newly saved encrypted runtime files.
- Added `vault doctor` and `vault inspect-runtime` reporting for encrypted runtime file format without decrypting vault contents.
- Added focused coverage for container wrapping, legacy parsing, unsupported header rejection, and non-decrypting format descriptions.

### Changed

- Kept legacy salt-plus-ciphertext vault files readable while writing new main, recovery, and shared-token vault files with the headered container format.
- Updated coverage baselines to `35.4%` full repository and `82.8%` internal packages.
- Updated the CLI-visible version to `0.4.6`.

## [v0.4.5] - 2026-05-18

### Fixed

- Fixed RPM package generation by accepting the automatically compressed `vault(1)` man page in the RPM file manifest.

### Changed

- Updated the CLI-visible version to `0.4.5`.

## [v0.4.4] - 2026-05-18

### Added

- Added a `vault(1)` man page under `docs/man/vault.1`.
- Added release workflow output for Linux `.deb`, Linux `.rpm`, and macOS `.pkg` packages in addition to the existing `.tar.gz` archives.
- Added GitHub artifact attestations for release artifacts built by the release workflow.

### Changed

- Updated README, development, security, and backlog documentation for installable packages, checksums, and artifact attestations.
- Updated the CLI-visible version to `0.4.4`.

## [v0.4.3] - 2026-05-17

### Fixed

- Fixed token max-use enforcement so a token with `--max-uses=1` can complete its first allowed command and is rejected on the next use.
- Rejected invalid token creation limits, including zero or negative durations, zero or negative max uses, malformed max-use values, and colon-delimited key patterns that would break compact token parsing.
- Made cryptographic random byte generation fail fast if the OS random source fails instead of silently returning weak random data.
- Made token cleanup logging robust for unexpectedly short token IDs.
- Enforced `max_backups` retention for timestamped manual backups.

### Changed

- Updated the coverage baselines to `34.8%` full repository and `83.3%` internal packages.
- Updated security/development documentation and the CLI-visible version to `0.4.3`.

## [v0.4.2] - 2026-05-17

### Added

- Added `inspect-runtime` to list active and legacy runtime files without decrypting vault data.

### Changed

- Added focused internal coverage for runtime path handling, empty-vault loading, storage atomic-write errors, recovery file replacement/errors, token key-file encryption, token vault parse errors, and token atomic-write behavior.
- Updated the coverage baselines to `34.6%` full repository and `83.5%` internal packages.
- Updated the CLI-visible version to `0.4.2`.

## [v0.4.1] - 2026-05-17

### Added

- Added `inspect-runtime` to list active and legacy runtime files without decrypting vault data.

## [v0.4.0] - 2026-05-17

### Changed

- Moved sensitive runtime files into `~/.myminivault/` by default.
- Added and documented `MYMINIVAULT_HOME` to override the runtime directory for tests, automation, and isolated vaults.
- Added startup migration for legacy runtime files found in the current working directory when the runtime directory does not already contain matching files.
- Added focused runtime path and legacy migration tests.
- Updated the coverage baselines to `34.7%` full repository and `80.5%` internal packages.

## [v0.3.7] - 2026-05-17

### Changed

- Moved end-to-end CLI smoke tests into the top-level `tests` package.
- Removed duplicate sync wrapper tests from `cmd/vault`; equivalent behavior remains covered by `internal/sync`.
- Removed unused CLI wrapper functions and unused logger parameters flagged by `gopls`.
- Kept audit logging redacted while simplifying call sites that no longer pass key or token identifiers.

## [v0.3.6] - 2026-05-17

### Changed

- Clarified recovery-file plus recovery-key risk across security, recovery, and user documentation.
- Added an `80.0%` internal package coverage floor to CI and documented the local coverage gate.
- Extracted command logging and shared-vault mirror policy helpers from `cmd/vault` orchestration and added focused unit coverage.
- Raised the full repository coverage baseline to `34.4%`.
- Refined the user manual with a practical pre-use checklist, common workflows, and clearer plaintext/recovery/token warnings.

## [v0.3.5] - 2026-05-17

### Changed

- Added focused `internal/token` coverage for master-key creation/loading, registry parse errors, encrypted-vault error paths, malformed token parsing, missing token-manager cases, helper functions, generated token IDs, and expiry/max-use checks.
- Raised `internal/token` coverage to `82.0%`, full repository coverage to `34.1%`, and internal package coverage to `81.2%`.
- Updated the internal coverage badge, documentation baselines, CLI-visible version, and project score.
- Switched future branch examples away from the old `codex/` prefix.

## [v0.3.4] - 2026-05-17

### Changed

- Moved clipboard backend detection and best-effort clear-if-unchanged behavior into `internal/clipboard` with focused unit coverage.
- Moved shell export rendering and restrictive export-file writes into `internal/export` with focused unit coverage.
- Kept `cmd/vault` thinner by leaving export and clipboard command handlers as CLI orchestration only.
- Updated coverage documentation, the internal coverage badge, and the CLI-visible version to `0.3.4`.

## [v0.3.3] - 2026-05-17

### Changed

- Expanded GitHub Actions CI to run formatting, `go vet`, and tests on Linux and macOS.
- Reworked `docs/security.md` into a formal threat model with assets, attacker assumptions, trust boundaries, data flows, residual risks, and incident response guidance.
- Added CI coverage reporting, a coverage artifact, coverage notes, and an internal coverage badge.
- Moved file lock handling into `internal/lock` with focused unit coverage.
- Moved redacted audit log formatting and writing into `internal/audit` with focused unit coverage.
- Moved sync metadata and import decision logic into `internal/sync` with focused unit coverage.
- Moved export/import/key validation helpers into `internal/commands` with focused unit coverage.
- Updated the CLI-visible version to `0.3.3`.

## [v0.3.2] - 2026-05-17

### Added

- Added GitHub Actions release packaging for Linux amd64, Linux arm64, and macOS arm64 archives.
- Added SHA-256 checksum files for release package assets.
- Added README install guidance for `go install`.
- Added explicit project credits in the README and CLI help output.

### Changed

- Updated the CLI-visible version to `0.3.2`.

## [v0.3.1] - 2026-05-17

### Added

- Added GitHub Actions CI for formatting, `go vet`, and `go test ./...`.
- Added real CI and Go Reference badges to the README.

### Changed

- Added focused Go doc comments for exported internal package types and functions.

## [v0.3.0] - 2026-05-16

### Added

- Added `copy <key> [--ttl=30s]` to copy secrets to the clipboard without printing them.
- Added `export --output <file>` to write shell-safe exports directly to a `0600` file.
- Added best-effort core dump disabling on supported Unix-like systems.
- Added tests for safe export file output and clipboard clear behavior.

### Changed

- `export` prints a plaintext warning to stderr when writing directly to an interactive terminal.
- Updated security and user documentation for clipboard, export, and runtime memory exposure limits.

## [v0.2.2] - 2026-05-16

### Added

- Added per-key sync metadata for main/shared vault updates and delete markers.
- Added tests for sync metadata conflict decisions.

### Changed

- Token sync now skips older shared-vault values when main-vault metadata shows a newer local update.
- Updated token sync docs and backlog score for the stronger sync policy.

## [v0.2.1] - 2026-05-16

### Added

- Added `audit_log` config support so audit logging can be disabled.
- Added `vault doctor` freshness warnings for stale recovery snapshots and shared token vaults newer than the main vault.
- Added tests for exact shell-safe export/import round trips, audit-log redaction, disabled audit logging, and doctor freshness output.

### Changed

- Reduced audit-log metadata leakage by no longer logging key names or token identifiers by default.
- Improved import parsing for shell-safe export output with apostrophes and embedded newlines.

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
