# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- The Go and Python reference readers cover existing MYMV v2 main, HKDF recovery/shared-token, and MYMV v1 main fixtures. Keep public [review issue #1](https://github.com/olelbis/myminivault/issues/1) aligned with merged reader coverage. It had no reviewer comments as of 2026-11-16.
- Claude's review findings 1–5 are addressed in PR #5: aligned KDF write/read bounds, 32-byte AES-256 write keys, main-vault HKDF rejection, Windows code cleanup, and race/fuzz/Dependabot CI. Deprecated recovery/token KDF containers remain readable under the documented migration policy. Findings 6–8 are deferred to the next task.
- A separate reviewer report describes a critical shared-token-vault exposure and three reproduced token lifecycle bugs (usage counters, restore reimport, key regeneration), plus one unconfirmed deleted-key resurrection path. The report is ordered in `BACKLOG.md` immediately after findings 6–8. The macOS Keychain path was not tested by the reviewer; no fix or independent reproduction is claimed here.
- Workflow rule: every task branch ends in a PR. The user normally handles CI and merge, unless explicitly delegated; the agent prepares authorized commits/pushes and performs authorized cleanup after merge. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task after this intermediate PR is merged: resolve Claude review findings 6–8 as a focused follow-up, including signing-key separation, duplicate KDF helper cleanup, and the six-field token sunset. Immediately afterward, investigate the critical token/shared-vault report in `BACKLOG.md`; defer issue #1 monitoring and the headerless legacy fixture until that review is triaged.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and the ordered backlog. After the intermediate review PR is merged, address Claude findings 6–8: derive a dedicated token signing subkey, remove duplicate KDF metadata helpers and unused recovery/config aliases, and retire six-field compact tokens with documented reissue behavior. Keep the reported critical token/shared-vault lifecycle review as the next priority afterward; do not start it in this task. Relevant files: internal/token/*, internal/storage/*, internal/crypto/*, internal/recovery/*, internal/config/*, docs/security.md, docs/token-sync-policy.md, and docs/crypto-review-scope.md. Run focused tests, the full Go suite, `go test -race ./...`, `go vet ./...`, and `git diff --check`. Do not commit, push, merge, or release without authorization.

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
