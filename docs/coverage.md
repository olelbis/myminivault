# Coverage Notes

GitHub Actions publishes a `coverage-report` artifact on every CI run. The artifact contains:

- `coverage.out`: Go coverage profile
- `coverage.txt`: function-level coverage report from `go tool cover -func`
- `internal-coverage.out`: Go coverage profile for `./internal/...`
- `internal-coverage.txt`: function-level internal package coverage report

Local baseline measured on 2026-10-20 with Go `1.27.2` (macOS arm64):

| Scope | Statement coverage |
| --- | --- |
| Full repository | 53.0% |
| Internal packages | 86.3% |
| CLI package (`cmd/vault`) | 29.4% |

The README badge is a manually maintained snapshot of internal package coverage; the CI artifact contains the measurement for each run. CLI smoke tests execute a separately compiled, uninstrumented `vault` binary, so they check behavior without contributing statement coverage to `cmd/vault`.

CI enforces an internal package coverage floor of `80.0%`. Full repository coverage remains informational because subprocess-based CLI smoke tests protect real behavior without raising statement coverage in `cmd/vault`.

As command-independent logic moves into `internal/...` packages, `cmd/vault` should become thinner while internal package coverage remains the main quality signal.
