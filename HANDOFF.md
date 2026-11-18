# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- Claude findings 1–8 and grouped Dependabot updates are merged (PRs #5, #17–20). The critical token/shared-vault follow-up is merged in [PR #21](https://github.com/olelbis/myminivault/pull/21) on 2026-11-18 (`0dca085`), with all CI/security checks successful. Its local/remote branch was removed after CodeQL completed; local `main` is aligned with `origin/main`. No release is prepared.
- All five reported cases were reproduced against baseline `4ad5efb` using fake secrets in `/tmp/myminivault-critical-*`: unrelated main-vault exposure, usage reset, restore reimport, key/vault mismatch, and tombstone bypass. Reads also reproduced implicit replacement-key creation. Regression tests cover the fixes and the create/use/import/cleanup/revoke/restore/recovery/rotation lifecycle.
- Shared snapshots now contain active read scopes and authorized pending writes, not the full main vault. Write-only grants do not copy existing values. Counters merge monotonically before cleanup/rebuild, imports require unchanged known write grants, and tombstones precede legacy fallback. Successful saves remove obsolete token backups. A durable `.reconcile` marker blocks stale token use after interrupted writes; authenticated `sync-tokens` repairs it. Migration moves the barrier first, preserves conflicting runtime bundles, and handles canonical directory aliases; permission checks/inventory include all artifacts.
- Upgrade action: run `vault sync-tokens` with the master password to initialize scoped shared state. Existing v3 strings remain usable subject to their grant/expiry/count. Restore and password recovery revoke historical grants. Rotation requires the master password and preserves pending writes first. Recovery preserves readable token state separately in a private archive encrypted with the new password. Restore similarly archives state if the current main cannot be opened; ordinary commands refuse to initialize over orphaned token state. An unreadable token snapshot stops reset before replacement.
- Keychain lifecycle is covered through an injected macOS store (read-only lookup, explicit migration, missing keys, successful/failed rotation). No live personal Keychain access or OS ACL verification is claimed. The shared root key still exposes all retained read scopes and pending writes; per-token cryptographic isolation requires a separate design. See [token policy](docs/token-sync-policy.md).
- Validation on 2026-11-17 with Go 1.27.3 (macOS arm64): focused lifecycle/tombstone/Keychain/interruption tests, the full Go suite, full race/coverage run (all 35 CLI smoke scenarios), final focused race checks, `go vet ./...`, Staticcheck v0.8.2, gofmt, documentation links, and `git diff --check` passed. Internal coverage is 85.8% (1,247/1,453 statements), above the 80% floor; see [coverage notes](docs/coverage.md).
- Workflow: each task branch ends in a PR. The user follows remote CI and handles merge unless explicitly delegated. Current preferred toolchain is Go 1.27.3; module minimum is 1.27.0. Preserve historical coverage and release records.

## Next Task And Instruction

SR-1–SR-3 are merged in [PR #22](https://github.com/olelbis/myminivault/pull/22) on 2026-11-18 (`190c422`). CI and Security Scanning completed successfully, including CodeQL analysis/upload. After the user authorized cleanup, local `main` was fast-forwarded and the local/remote `token-key-security` branch removed. No release is prepared. Native Security.framework writes remove root bytes from process arguments while retaining the Base64 item format; the macOS release build now enables CGO. Read/delete compatibility still uses `security`. Canonical absolute accounts isolate runtime directories; read-only lookup falls back to the original legacy path spelling, and authenticated creation copies/verifies that key without deleting a potentially shared legacy item. File roots now use exclusive random staging, file sync, atomic rename, and directory sync. See [review and implementation record](docs/token-security-review-2026-11-18.md) and [token policy](docs/token-sync-policy.md).

Validation on 2026-11-18 with Go 1.27.3 (macOS arm64): full race suite including all 35 CLI smoke tests, final focused migration/Keychain regressions, final internal race/coverage run (85.4%, 1,275/1,493 statements), `go vet`, Staticcheck v0.8.2, native macOS build, Linux non-CGO cross-build, Darwin non-CGO backend tests, gofmt, documentation links, and `git diff --check` passed. No live Keychain access occurred. Logs/profiles are under `/tmp/myminivault-sr-*`; see `docs/coverage.md`. Remote CI and Security Scanning passed for PR #22.

Next: review the merged native backend and validate native Keychain ACL/prompt behavior in an explicitly isolated disposable Keychain under a dedicated macOS test account. No personal Keychain items may be accessed. Existing tests inject a store and compile the native backend; they do not establish live OS access behavior. The current backend uses the default Keychain search context, so prepare an explicit isolation harness before any live run. Keep per-token cryptographic format implementation as a separate design decision. Existing shared legacy roots remain shared until each migrated runtime is rotated.

Relevant files: `internal/keychain/save_darwin.go`, `internal/keychain/keychain.go`, `cmd/vault/token_key_cli.go`, `cmd/vault/token_key_identity_test.go`, `internal/token/key_atomic.go`, its failure tests, and `.github/workflows/release-packages.yml`. Preserve the review documents and implementation. Required checks after further code changes: focused regressions, full suite, race checks, `go vet`, internal coverage >=80%, gofmt, and `git diff --check`.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, BACKLOG.md, and docs/token-security-review-2026-11-18.md; review the SR-1–SR-3 fixes and prepare isolated native Keychain validation. Never access personal Keychain items. Do not commit, push, merge, or release without authorization.

## Sources Of Truth

- Release version: `VERSION`; release history: `CHANGELOG.md`.
- Go requirements: `go.mod`; CI and packaging: `.github/workflows/`.
- Usage: `README.md`, `docs/user-manual.md`.
- Build/tests/releases: `docs/development.md`.
- Security reports: `SECURITY.md`; threat model: `docs/security.md`.
- Contribution process: `CONTRIBUTING.md`.

## Useful Checks

```bash
git status --short --branch
go version
go test ./path/to/affected/package
git diff --check
```

For behavior changes, follow the broader verification rules in `AGENTS.md`.
Keep this file short; update current work at meaningful handoffs rather than
copying the backlog, changelog, test logs, or entire conversation here.
