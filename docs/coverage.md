# Coverage Notes

GitHub Actions publishes a `coverage-report` artifact on every CI run. The artifact contains:

- `coverage.out`: Go coverage profile
- `coverage.txt`: function-level coverage report from `go tool cover -func`
- `internal-coverage.out`: Go coverage profile for `./internal/...`
- `internal-coverage.txt`: function-level internal package coverage report

Local baseline measured on 2026-10-24 with Go `1.27.3` (macOS arm64), selected explicitly with `GOTOOLCHAIN=go1.27.3`:

| Scope | Statement coverage |
| --- | --- |
| Full repository | 53.0% |
| Internal packages | 86.3% |
| CLI package (`cmd/vault`) | 29.4% |

These values are unchanged from the 2026-10-20 measurement with Go `1.27.2`. Both coverage runs used `-count=1` to bypass cached test results:

```bash
GOTOOLCHAIN=go1.27.3 go test -count=1 -covermode=atomic -coverprofile=/tmp/myminivault-go1273-full.out ./...
GOTOOLCHAIN=go1.27.3 go tool cover -func=/tmp/myminivault-go1273-full.out
GOTOOLCHAIN=go1.27.3 go test -count=1 -covermode=atomic -coverprofile=/tmp/myminivault-go1273-internal.out ./internal/...
GOTOOLCHAIN=go1.27.3 go tool cover -func=/tmp/myminivault-go1273-internal.out
```

The README badge is a manually maintained snapshot of internal package coverage; the CI artifact contains the measurement for each run. CLI smoke tests execute a separately compiled, uninstrumented `vault` binary, so they check behavior without contributing statement coverage to `cmd/vault`.

CI enforces an internal package coverage floor of `80.0%`. Full repository coverage remains informational because subprocess-based CLI smoke tests protect real behavior without raising statement coverage in `cmd/vault`.

As command-independent logic moves into `internal/...` packages, `cmd/vault` should become thinner while internal package coverage remains the main quality signal.
