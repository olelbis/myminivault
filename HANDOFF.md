# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- The Go and Python reference readers cover existing MYMV v2 main, HKDF recovery/shared-token, and MYMV v1 main fixtures. Keep public [review issue #1](https://github.com/olelbis/myminivault/issues/1) aligned with merged reader coverage. It had no reviewer comments as of 2026-11-16.
- Claude's review findings 1–5 are in the baseline. Findings 6–8 are implemented on `review-findings-6-8`: v3 compact tokens use a dedicated HKDF signing subkey; six-field and v2 tokens require revocation/reissue and are rejected before key/vault access; KDF metadata handling shares the validated crypto policy; unused recovery/config/scrypt compatibility entry points are removed. Encrypted container compatibility remains covered. Commit, push, and PR creation are authorized. The user handles remote CI and PR merge; merge and release are not authorized.
- A separate reviewer report describes a critical shared-token-vault exposure and three reproduced token lifecycle bugs (usage counters, restore reimport, key regeneration), plus one unconfirmed deleted-key resurrection path. The report is ordered in `BACKLOG.md` immediately after findings 6–8. The macOS Keychain path was not tested by the reviewer; no fix or independent reproduction is claimed here.
- The CI efficiency follow-up limits duplicate PR-branch runs, skips documentation-only changes, cancels superseded PR runs, runs race tests on Linux, and groups future Dependabot version updates into Go modules, CodeQL Actions, and other Actions. The ten Dependabot PRs opened before grouping remain separate and require their own triage; do not assume they were consolidated automatically.
- Workflow rule: every task branch ends in a PR. The user normally handles CI and merge, unless explicitly delegated; the agent prepares authorized commits/pushes and performs authorized cleanup after merge. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Validation on 2026-11-17 with Go 1.27.3 (macOS arm64): focused tests, `go test ./...`, full race/coverage suite, `go vet ./...`, and `git diff --check` passed. Internal coverage is 85.9% (floor: 80%); see the [coverage report](docs/coverage.md) for scope and historical measurements. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task after the findings 6–8 PR is merged: investigate and fix the critical token/shared-vault report ordered first in `BACKLOG.md`. This task has not started; defer issue #1 monitoring and the headerless legacy fixture until the report is triaged.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and BACKLOG.md; investigate and fix the critical token/shared-vault review. Reproduce with fake secrets in an isolated /tmp/myminivault-* runtime, then address shared-vault scope, usage counters, restore/reimport, key regeneration, and the unconfirmed deleted-key resurrection path. Assess macOS Keychain separately. Relevant files: internal/token/*, internal/sync/*, internal/storage/*, internal/health/*, cmd/vault/token*, cmd/vault/restore*, docs/security.md, and docs/token-sync-policy.md. Run focused tests, the full Go suite, race tests, go vet, internal coverage (at least 80%), and git diff --check. Do not commit, push, merge, or release without authorization.

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
