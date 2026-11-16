# Contributing

myminivault is an experimental, unaudited local CLI vault. Focused bug reports,
tests, documentation corrections, and security reviews are welcome.

## Before Starting

- Read the [README](README.md) for supported behavior and platform limits.
- Use [HANDOFF.md](HANDOFF.md) for current work and [BACKLOG.md](BACKLOG.md#roadmap-overview) for priorities.
- Check existing issues before proposing a larger feature or format change.
- Report exploitable vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.
- Never attach real vaults, secret values, passwords, recovery keys, or tokens to reports or pull requests.

## Development

Use the Go toolchain declared in `go.mod`; workflow pins describe CI validation.
Keep changes small and use a descriptive task branch. Follow existing package
boundaries and add English comments where a security invariant needs explanation.

For a Go behavior change, format modified files and run:

```bash
go test ./...
go vet ./...
git diff --check
```

Add focused regression tests for bugs. For documentation-only changes, review
examples and links and run `git diff --check`; the full Go suite is unnecessary.
Use fake data and an isolated `MYMINIVAULT_HOME` for manual testing.

See the [development guide](docs/development.md) for smoke tests, independent
reference readers, analyzer commands, packaging, and release procedures.
[Coverage notes](docs/coverage.md) explain the enforced internal 80% floor and
why CLI subprocess tests are separate from statement coverage.

## Pull Requests

Explain the problem, resulting behavior, and verification performed. Call out
changes to file formats, recovery, synchronization, or compatibility explicitly.
Update affected documentation and add a concise changelog entry when useful for
users. Keep unrelated formatting and refactors out of the change.

Releases are grouped by the maintainer. A contribution does not need its own
version bump or release tag. Wait for branch CodeQL uploads to finish before
deleting remote branches after merging.
