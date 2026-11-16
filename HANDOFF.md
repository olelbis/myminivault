# Project Handoff

Read this file and `AGENTS.md` when starting a new session. Open other documents
only as needed; Git history and `CHANGELOG.md` contain completed work.

## Current Work

- Go 1.27.3 alignment and contributor/agent instructions are implemented on `go-1.27.3-alignment`. Check Git state and remote CI before merging; no new release is required for this task.
- The preferred toolchain, CI/security/release workflows, README badge, and development guide select Go 1.27.3; the module minimum remains Go 1.27.0.
- Latest validation: [coverage report](docs/coverage.md), including date, toolchain, and scope. Do not rerun the full suite merely to rediscover these results.

## Next Task And Instruction

Recommended next task: close the toolchain alignment branch after checking remote CI.

> Read AGENTS.md and HANDOFF.md. Check CI and Security Scanning for go-1.27.3-alignment and report any failures. If checks pass, propose merging into main and cleaning up the branch after CodeQL uploads finish. Update this handoff when closing. Do not merge or publish a release without authorization.

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
