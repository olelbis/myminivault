# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- The Go and Python reference readers cover existing MYMV v2 main, HKDF recovery/shared-token, and MYMV v1 main fixtures. PR #3 was merged; keep public [review issue #1](https://github.com/olelbis/myminivault/issues/1) aligned with merged reader coverage. It had no reviewer comments as of 2026-11-16.
- Workflow rule: every task branch ends in a PR. The user handles CI and merge; the agent prepares authorized commits/pushes and performs cleanup after merge confirmation. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task: triage any new findings in public review issue #1 first. If none appear, extend independent format reading to the existing headerless legacy main-vault fixture as the next bounded compatibility check in `BACKLOG.md`.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and the ordered backlog. Check public review issue #1 for new findings and triage them first. If there are none, extend the independent Go and Python readers to the existing headerless legacy main-vault fixture with explicit fallback scrypt parameters. Relevant files: tools/reference-decryptor/*, tools/reference-decryptor-python/*, internal/storage/testdata/compat/*, and the review/format docs. Run reader tests, the full Go suite for behavior changes, `go vet ./...`, and `git diff --check`. Do not commit, push, merge, or release without authorization.

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
