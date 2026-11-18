# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- Claude findings 1–8 and grouped Dependabot updates are merged (PRs #5, #17–20). The current task is the critical token/shared-vault follow-up on `token-shared-vault-lifecycle`; commit, push, and PR creation were authorized on 2026-11-18. The user follows remote CI and handles merge; no merge or release is authorized for this task.
- All five reported cases were reproduced against baseline `4ad5efb` using fake secrets in `/tmp/myminivault-critical-*`: unrelated main-vault exposure, usage reset, restore reimport, key/vault mismatch, and tombstone bypass. Reads also reproduced implicit replacement-key creation. Regression tests cover the fixes and the create/use/import/cleanup/revoke/restore/recovery/rotation lifecycle.
- Shared snapshots now contain active read scopes and authorized pending writes, not the full main vault. Write-only grants do not copy existing values. Counters merge monotonically before cleanup/rebuild, imports require unchanged known write grants, and tombstones precede legacy fallback. Successful saves remove obsolete token backups. A durable `.reconcile` marker blocks stale token use after interrupted writes; authenticated `sync-tokens` repairs it. Migration moves the barrier first, preserves conflicting runtime bundles, and handles canonical directory aliases; permission checks/inventory include all artifacts.
- Upgrade action: run `vault sync-tokens` with the master password to initialize scoped shared state. Existing v3 strings remain usable subject to their grant/expiry/count. Restore and password recovery revoke historical grants. Rotation requires the master password and preserves pending writes first. Recovery preserves readable token state separately in a private archive encrypted with the new password. Restore similarly archives state if the current main cannot be opened; ordinary commands refuse to initialize over orphaned token state. An unreadable token snapshot stops reset before replacement.
- Keychain lifecycle is covered through an injected macOS store (read-only lookup, explicit migration, missing keys, successful/failed rotation). No live personal Keychain access or OS ACL verification is claimed. The shared root key still exposes all retained read scopes and pending writes; per-token cryptographic isolation requires a separate design. See [token policy](docs/token-sync-policy.md).
- Validation on 2026-11-17 with Go 1.27.3 (macOS arm64): focused lifecycle/tombstone/Keychain/interruption tests, the full Go suite, full race/coverage run (all 35 CLI smoke scenarios), final focused race checks, `go vet ./...`, Staticcheck v0.8.2, gofmt, documentation links, and `git diff --check` passed. Internal coverage is 85.8% (1,247/1,453 statements), above the 80% floor; see [coverage notes](docs/coverage.md).
- Workflow: each task branch ends in a PR. The user follows remote CI and handles merge unless explicitly delegated. Current preferred toolchain is Go 1.27.3; module minimum is 1.27.0. Preserve historical coverage and release records.

## Next Task And Instruction

After this fix is reviewed and merged, prioritize independent review of the hardened token lifecycle, an isolated macOS Keychain validation plan, and a decision on per-token encryption/key distribution before release. Keep issue #1 and its scope aligned; postpone headerless legacy-reader expansion until these security boundaries are reviewed.

Scope: review the scoped projection, dirty-write authorization, monotonic counters, failure barriers, restore/recovery and rotation semantics. Examine `internal/token/state.go`, `internal/sync/*`, `cmd/vault/token_lifecycle.go`, `cmd/vault/critical_token_lifecycle_test.go`, `cmd/vault/token_key_lifecycle_test.go`, `docs/security.md`, and `docs/token-sync-policy.md`. Reuse isolated fake-secret fixtures; never read personal vaults or Keychain items. If changes are authorized, run focused tests, the full suite, race tests, `go vet`, internal coverage (at least 80%), and `git diff --check`.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and BACKLOG.md; independently review the hardened token lifecycle and propose the Keychain validation/per-token isolation plan. Do not commit, push, merge, or release without authorization.

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
