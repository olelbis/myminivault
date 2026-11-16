# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- The focused security-review documents were corrected for KDF write profiles, reference-reader coverage, and the current staticcheck CI job. Agent instructions now ask the user to close a completed task chat before unrelated work.
- Workflow rule: every task branch ends in a PR. The user handles CI and merge; the agent prepares authorized commits/pushes and performs cleanup after merge confirmation. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task: review the ordered backlog and propose the next priority after these documentation changes are handled.

> Project: myminivault. Working directory: <absolute path to the myminivault checkout; resolve before starting>. Read AGENTS.md, HANDOFF.md, and the ordered backlog. Check the local changes in docs/crypto-review-scope.md, docs/review-request.md, and SECURITY.md, including link/content review and `git diff --check`, then propose the next priority. Do not modify code, commit, push, publish, or release without authorization.

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
