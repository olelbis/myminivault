# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- The focused security-review documents and [public review issue #1](https://github.com/olelbis/myminivault/issues/1) now agree on KDF write profiles and reference-reader coverage. The issue remains open with no reviewer comments as of 2026-11-16.
- Workflow rule: every task branch ends in a PR. The user handles CI and merge; the agent prepares authorized commits/pushes and performs cleanup after merge confirmation. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task: triage any new findings in public review issue #1 first. If none appear, evaluate independent reader coverage for the existing HKDF recovery and shared-token fixtures, starting with recovery, as the next focused review follow-up in `BACKLOG.md`.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and the ordered backlog. Check public review issue #1 for new findings and triage them first. If there are none, inspect the Go/Python reference readers and the existing HKDF recovery and shared-token fixtures, then propose a narrow independent-reader extension, starting with recovery. Do not modify code, commit, push, publish, or release without authorization.

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
