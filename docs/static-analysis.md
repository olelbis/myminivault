# Static Analysis Triage

myminivault uses automated analysis as a guardrail, not as a substitute for a
security audit. Findings should be reviewed with the local-vault threat model in
mind and should either be fixed, documented as accepted, or tracked as follow-up
work.

## Current CI Gates

The normal CI and security workflows currently run:

- `gofmt` formatting checks
- `go vet ./...`
- `go test ./...`
- repository and internal-package coverage reporting
- `staticcheck ./...`
- CodeQL for Go
- `govulncheck ./...`

These checks must stay green before changes are merged.

## Local Gosec Triage

`gosec` is useful for security review, but it is not a CI gate yet because it
currently reports several findings that need context:

- user-selected import/export/reference-decryptor paths are expected CLI input,
  not web request paths; path traversal findings must still be reviewed when the
  target is a sensitive runtime file
- subprocess findings are expected for narrow OS integration helpers such as
  clipboard commands and macOS Keychain access; command names and arguments must
  remain fixed or constrained
- cleanup errors from best-effort temp-file removal may be intentionally ignored,
  but the primary write, fsync, rename, and directory-sync errors must not be
  ignored
- numeric conversions from parsed metadata must be bounded before conversion or
  explicitly annotated when a validator already proves the bound

Run it locally with:

```sh
GOBIN=/tmp/myminivault-tools go install github.com/securego/gosec/v2/cmd/gosec@latest
/tmp/myminivault-tools/gosec ./...
```

## Current Gosec Baseline

The latest local triage run reduced the default `gosec ./...` result from 67
findings to 51 findings. The remaining findings are intentionally not used as a
gate yet: they are mostly user-selected CLI paths, runtime-file paths already
covered by myminivault-specific path checks in higher-level callers, and
best-effort cleanup errors around temp files after primary failures.

Before enabling `gosec` in CI, either eliminate these categories or add narrow
rule-specific suppressions with comments that explain the exact accepted risk.

## Suppression Policy

Use `// #nosec` only when all of the following are true:

- the finding was manually reviewed
- the code path is covered by an explicit validation or a narrow documented
  trust boundary
- the comment names the rule, for example `G115`, and explains the accepted
  condition in one sentence
- suppressing the finding is less confusing than restructuring the code

Prefer fixing the code over suppressing the warning when the fix makes the code
clearer for a human reviewer.

## Release Policy

Static-analysis-only changes do not require an immediate user-facing release
unless they change CLI behavior, encrypted format behavior, packaging, or a
security-sensitive runtime guarantee. They should still be listed in the
changelog under `Unreleased`.
