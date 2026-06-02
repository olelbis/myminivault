# Coverage Notes

GitHub Actions publishes a `coverage-report` artifact on every CI run. The artifact contains:

- `coverage.out`: Go coverage profile
- `coverage.txt`: function-level coverage report from `go tool cover -func`
- `internal-coverage.out`: Go coverage profile for `./internal/...`
- `internal-coverage.txt`: function-level internal package coverage report

Current local baseline:

| Scope | Statement coverage |
| --- | --- |
| Full repository | 42.2% |
| Internal packages | 86.0% |

The README badge tracks internal package coverage because the project has many CLI smoke tests that execute the compiled `vault` binary as a subprocess. Those smoke tests are valuable behavior checks, but subprocess execution does not contribute much statement coverage to the parent `cmd/vault` test process.

CI enforces an internal package coverage floor of `80.0%`. Full repository coverage remains informational because subprocess-based CLI smoke tests protect real behavior without raising statement coverage in `cmd/vault`.

As command-independent logic moves into `internal/...` packages, `cmd/vault` should become thinner while internal package coverage remains the main quality signal.
