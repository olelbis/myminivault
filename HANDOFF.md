# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- Go 1.27.3 alignment and contributor/agent instructions were merged and pushed to `main` as `f7c2e25`; the task branch was cleaned up.
- Workflow rule: every task branch ends in a PR. The user handles CI and merge; the agent prepares authorized commits/pushes and performs cleanup after merge confirmation. See `AGENTS.md`.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task: review the focused external security-review material for consistency with current code.

> Read AGENTS.md and HANDOFF.md. Review docs/crypto-review-scope.md, docs/review-request.md, SECURITY.md, and the referenced crypto/container code for factual inconsistencies or missing review boundaries. Report concrete findings with file references. Do not modify code, publish external messages, commit, push, or release without authorization.

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
