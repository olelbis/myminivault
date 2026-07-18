# Changelog

## [Unreleased]

### Added

- Added a standalone Go `tools/reference-decryptor` for the documented `MYMV` v2 main-vault format.
- Added a Python reference decryptor for the same fixture and format.
- Added a base64 compatibility fixture for the reference decryptor.
- Added a ready-to-share focused crypto review request and GitHub issue template.

### Changed

- Updated file-format and crypto-review documentation to include the reference decryptor and fixture.

## [v0.12.18] - 2026-07-18

### Added

- Added `vault sync-tokens --dry-run` to preview staged token writes without modifying runtime files.
- Added internal sync preview tests and CLI smoke coverage.

### Changed

- Dry-run output now lists import/update keys, delete keys, skipped conflicts, and legacy metadata decisions.
- Dry-run skips automatic token import and avoids saving `vault.db`, `shared-token-vault.json`, or `rollback-state.json`.
- Updated README, user manual, token sync policy, man page, backlog, and changelog.

## [v0.12.17] - 2026-07-18

### Added

- Added encrypted main-vault rollback metadata with a stable `vault_id` and monotonic `revision`.
- Added local `rollback-state.json` trusted state to remember the highest accepted main-vault revision.
- Added `doctor` and `inspect-runtime` reporting for rollback state.
- Added unit coverage for rollback metadata initialization, high-water revision handling, rollback warnings, vault ID mismatch warnings, and symlink rejection.

### Changed

- Mutating password-based saves now increment vault revision metadata and update rollback state after the encrypted vault save succeeds.
- Loading an older valid vault now emits a warning when its encrypted revision is below the trusted local high-water mark.
- Updated rollback, security, recovery, runtime, and development documentation for the initial warn-mode rollback detection behavior.

## [v0.12.16] - 2026-07-18

### Added

- Added exclusive-create helpers for sensitive runtime files.
- Added regression coverage for pre-existing main-vault transaction markers, main-vault temp files, recovery temp files, and shared-token-vault temp files.

### Changed

- Main vault transaction markers now fail if a pre-existing marker is present instead of truncating it.
- Main vault, recovery snapshot, and shared-token-vault temp files now fail if a pre-existing temp path is present instead of reusing it.
- Updated runtime security notes and backlog status for file-replacement race hardening.

## [v0.12.15] - 2026-07-17

### Added

- Added optional compact-token input via `vault use-token --token-file <path>` and `vault use-token --token-fd <fd>`.
- Added CLI smoke coverage for file-backed and file-descriptor token input.

### Changed

- Updated token usage documentation to recommend stdin, protected token files, or inherited file descriptors over direct process arguments.

## [v0.12.14] - 2026-07-17

### Added

- Added an SPDX 2.3 JSON SBOM generator based on `go list -m -json all`.
- Release packages now upload per-target `.spdx.json` SBOM assets and include them in per-target SHA-256 manifests.

### Changed

- Pinned GitHub Actions workflow dependencies to immutable commit SHAs while retaining version comments for maintenance.
- Release artifact attestations now include generated SBOM assets.

## [v0.12.13] - 2026-07-17

### Added

- Added bounded container KDF loading policy for MYMV v2 metadata before deriving keys.
- Added tests for metadata-selected scrypt parameters, unsupported KDF rejection, and excessive scrypt parameter rejection.
- Added parent-directory sync after atomic runtime-file renames and legacy runtime migration moves.

### Changed

- Main vault, shared-token vault, and recovery decrypt paths now use allowed MYMV v2 scrypt metadata when present, while legacy and MYMV v1 files keep the runtime fallback config.
- Main vault, recovery snapshot, shared-token vault, transaction marker, backup restore, and legacy migration writes now sync parent directories where supported for stronger crash consistency.

## [v0.12.12] - 2026-07-16

### Added

- Added OS-specific no-follow opens for checked sensitive runtime file opens on Unix-like systems.
- Added fallback checked opens for non-Unix platforms.
- Added regression coverage for checked writes refusing symlink targets without modifying the symlink target.

### Changed

- Updated security notes and backlog to mark no-follow runtime opens as implemented for checked runtime helpers, while keeping broader file-replacement race and crash-consistency work tracked.

## [v0.12.11] - 2026-07-15

### Added

- Added portable symlink rejection for sensitive runtime paths before startup permission hardening, legacy migration, and critical runtime writes.
- Added `doctor` failures for symlinked sensitive runtime files.
- Added tests for runtime-home, main vault, recovery snapshot, token key, shared token vault, and doctor symlink handling.

### Changed

- Updated runtime security documentation and backlog to distinguish current symlink rejection from future OS-specific no-follow open hardening.

## [v0.12.10] - 2026-07-15

### Added

- Added `vault use-token --stdin` so compact tokens can be read from standard input instead of process arguments.
- Added CLI smoke coverage for stdin-based token use.

### Changed

- Updated help, README, user manual, security notes, man page, backlog, and development docs to document stdin token input and keep version examples current.

## [v0.12.9] - 2026-07-13

### Added

- Added `vault set <key> --stdin` so secret values can be read from standard input instead of process arguments.
- Added CLI smoke coverage for stdin-based secret writes.

### Changed

- Updated help, manual, man page, security notes, README, and backlog to document stdin secret input and the remaining process-argument risk for compact tokens.

## [v0.12.8] - 2026-07-12

### Fixed

- Made the CLI-visible version injectable at release build time with `-X main.vaultVersion=<version>`.
- Updated release packaging to inject the Git tag version into Linux and macOS binaries.
- Changed local development builds to report `vdev` instead of a stale release number.
- Added regression coverage so `vault help` uses the injected version value.
- Updated release documentation and version references for the new version-injection workflow.

## [v0.12.7] - 2026-07-12

### Fixed

- Printed long recovery keys and compact tokens on a single plain line for safer copy/paste.
- Kept the boxed display only for short values that fit without wrapping.
- Updated CLI smoke tests for the single-line token output.

## [v0.12.6] - 2026-07-12

### Fixed

- Added a main-vault transaction marker to detect interrupted saves.
- Restored a valid `vault.db.bak` only when an interrupted-save marker proves recovery is appropriate.
- Cleaned interrupted first-run temp state so a cancelled initial save can start cleanly.
- Reported a clear interrupted-save error when no valid backup can be restored.
- Documented the temporary `vault.db.transaction` runtime marker.

## [v0.12.5] - 2026-07-11

### Changed

- Made CLI failures return a non-zero process status through a single top-level error boundary.
- Strengthened shared token-vault atomic saves with close-error handling and a restrictive previous-version backup.
- Sanitized control characters from audit action names.
- Updated the backlog assessment and immediate priorities after the severe review.
- Updated the CLI-visible version to `0.12.5`.

### Fixed

- Prevented an unreadable or malformed existing token master key from being silently replaced and invalidating tokens.
- Added regression coverage for token-key preservation, token-vault backups, audit sanitization, and CLI failure exit codes.
- Kept token JSON failures machine-readable while returning a non-zero process status.

All notable project changes are recorded here. Application releases use Git tags such as `v0.3.0`, and release package builds inject the tag-derived CLI-visible version with `-X main.vaultVersion=<version>`.

## [v0.12.3] - 2026-07-11

### Changed

- Added `refresh-recovery` to rewrite the recovery snapshot from the current vault after validating the recovery key.
- Added byte-slice recovery-key APIs and best-effort wiping for recovery and token encryption keys.
- Added an aggregate release `SHA256SUMS` manifest to the package workflow.
- Updated the CLI-visible version to `0.12.3`.

### Fixed

- Fixed the aggregate release `SHA256SUMS` workflow job to pass the repository explicitly when running without a checkout.

## [v0.12.1] - 2026-07-11

### Changed

- Added byte-slice storage APIs for master-password load/save paths and wiped the CLI bridge's local password byte copies after use.
- Updated the CLI-visible version to `0.12.1`.

## [v0.12.0] - 2026-07-10

### Changed

- New recovery snapshots now use a dedicated random recovery salt instead of reusing the main vault salt.
- Kept legacy shared-salt recovery snapshots readable and documented the automatic rewrite path.
- Added a non-mutating `vault doctor` note for compatible legacy recovery snapshots that still share the main vault salt.
- Updated the CLI-visible version to `0.12.0`.

## [v0.11.1] - 2026-07-08

### Changed

- Simplified main vault payload parsing by consolidating extended and legacy JSON decoding in `internal/storage`.
- Added focused storage tests for extended payloads, legacy map payloads, missing data maps, and invalid JSON.
- Updated coverage baselines to `42.6%` full repository and `86.0%` internal packages.
- Updated the CLI-visible version to `0.11.1`.

## [v0.11.0] - 2026-07-02

### Added

- Added lock acquisition timeout coverage so a busy vault lock returns a readable error instead of waiting indefinitely.

### Changed

- Split the token CLI implementation into focused key-storage, token-execution, and token-management files under `cmd/vault`.
- Changed top-level vault locking to use a bounded wait before reporting that another vault command may still be running.
- Updated coverage baselines to `42.5%` full repository and `85.9%` internal packages.
- Updated the CLI-visible version to `0.11.0`.

## [v0.10.0] - 2026-06-02

### Added

- Added `internal/health` for reusable non-decrypting runtime health metadata checks.
- Added focused tests for runtime metadata compatibility checks.

### Changed

- Moved recovery metadata compatibility logic out of `cmd/vault` doctor orchestration.
- Updated development documentation for the new internal health package.
- Updated coverage baselines to `42.2%` full repository and `86.0%` internal packages.
- Updated the CLI-visible version to `0.10.0`.

## [v0.9.0] - 2026-06-01

### Added

- Added explicit legacy sync-decision accounting when token/shared-vault imports fall back because per-key metadata is missing.
- Added tests for legacy token sync fallback decisions and clearer token sync freshness warnings.
- Added practical token sync policy examples for token writes, newer main values, newer shared values, legacy metadata fallback, and doctor warnings.

### Changed

- Made token sync freshness warnings more actionable by showing how far `shared-token-vault.json` is ahead of `vault.db`.
- Updated README and user manual guidance for staged token writes and `vault sync-tokens`.
- Updated coverage baselines to `41.9%` full repository and `85.7%` internal packages.
- Updated the CLI-visible version to `0.9.0`.

## [v0.8.0] - 2026-06-01

### Added

- Added a dedicated recovery compatibility check to `vault doctor` for non-decrypting recovery container kind, version, and crypto-parameter metadata.
- Added a recovery relationship summary to `vault inspect-runtime`.
- Added focused tests for stale recovery snapshots, incompatible recovery containers, config metadata drift, and recovery inspection output.

### Changed

- Made recovery freshness warnings more actionable by showing how far the recovery snapshot lags behind the main vault.
- Updated recovery, security, user, developer, man-page, and backlog documentation.
- Updated coverage baselines to `41.3%` full repository and `85.6%` internal packages.
- Updated the CLI-visible version to `0.8.0`.

## [v0.7.0] - 2026-06-01

### Added

- Added startup hardening for existing runtime file permissions: normal commands now tighten sensitive runtime files to `0600` when possible.
- Added tests for startup permission tightening and critical runtime path failures.

### Changed

- Kept `doctor` and `inspect-runtime` non-mutating so they report current permissions without auto-fixing them.
- Updated runtime documentation for startup permission hardening.
- Updated the CLI-visible version to `0.7.0`.

## [v0.6.0] - 2026-06-01

### Changed

- Required explicit `--show` for plaintext `get` and `search` terminal output.
- Required explicit `--stdout` for plaintext export to stdout; `export --output <file>` remains the safer file-based export path.
- Required explicit `--show` or `--json` for token `get` and token `search` plaintext access.
- Updated documentation and screenshots to show the safer plaintext-output policy.
- Updated the CLI-visible version to `0.6.0`.

## [v0.5.0] - 2026-06-01

### Changed

- Updated newly saved encrypted runtime files to `MYMV v2` containers with non-sensitive crypto metadata for algorithm, KDF, scrypt parameters, salt size, nonce size, and payload layout.
- Authenticated the `MYMV v2` header, metadata, and salt with AES-GCM AAD for main vault, recovery snapshot, and shared token vault files.
- Kept existing `MYMV v1` and legacy salt-plus-ciphertext files readable.
- Updated the CLI-visible version to `0.5.0`.

## [v0.4.12] - 2026-05-31

### Fixed

- Persisted token-vault imports even when the triggering master-password command is read-only.
- Reworked main vault atomic saves so the existing primary vault remains in place if temporary writes or backup rotation fail.
- Changed token usage accounting so failed or unauthorized token commands do not consume `max-uses`.
- Made `use-token --json` failures return a non-zero process status while keeping stdout machine-readable.
- Preserved literal `--json` values for token `set` commands unless `--json` is used as the final output flag.
- Forced restrictive `0600` permissions after rewriting token key, token registry, export, and recovery files.

### Changed

- Updated the coverage baselines to `38.9%` full repository and `86.6%` internal packages.
- Updated the CLI-visible version to `0.4.12`.

## [v0.4.11] - 2026-05-31

### Added

- Added machine-readable JSON output for `use-token` commands with `--json`, including `get`, `set`, `list`, `search`, and JSON error payloads.
- Added third-party integration documentation with subprocess examples for Python, Go, and Java.
- Added CLI smoke coverage for token JSON success and error paths.

### Changed

- Documented the Linux token key storage policy: file-backed by design for now, with Secret Service detection kept informational.
- Updated the coverage baselines to `38.3%` full repository and `86.6%` internal packages.
- Updated the CLI-visible version to `0.4.11`.

## [v0.4.10] - 2026-05-29

### Changed

- Strengthened Linux Secret Service detection to require both a DBus session and the `secret-tool` command before reporting the backend as available.
- Kept Linux token key storage on the file fallback until Secret Service storage is implemented and tested across desktop/headless environments.
- Updated documentation, backlog, and CLI-visible version to `0.4.10`.

## [v0.4.9] - 2026-05-24

### Added

- Added macOS Keychain storage support for token master-key material when `token_key_storage` is `auto` or `keychain`.
- Added migration from an existing macOS `vault-token.key` file into macOS Keychain on first token use.

### Changed

- Updated `vault doctor`, user documentation, and security documentation to describe macOS Keychain behavior and the file fallback.
- Updated the CLI-visible version to `0.4.9`.

## [v0.4.8] - 2026-05-24

### Added

- Added focused follow-up coverage for all internal packages that were below the `80.0%` package-level target: clipboard, container, lock, paths, recovery, and storage.
- Added tests for clipboard backend command wrappers, container kind/header errors, lock open failures, runtime path errors, recovery invalid JSON/finalize errors, and storage invalid JSON/container-kind/atomic backup error paths.

### Changed

- Raised the local coverage baselines to `37.0%` full repository and `86.7%` internal packages.
- Updated the CLI-visible version to `0.4.8`.

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
