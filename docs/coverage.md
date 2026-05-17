# Coverage Notes

GitHub Actions publishes a `coverage-report` artifact on every CI run. The artifact contains:

- `coverage.out`: Go coverage profile
- `coverage.txt`: function-level coverage report from `go tool cover -func`

Current local baseline:

| Scope | Statement coverage |
| --- | --- |
| Full repository | 34.1% |
| Internal packages | 81.2% |

The README badge tracks internal package coverage because the project has many CLI smoke tests that execute the compiled `vault` binary as a subprocess. Those smoke tests are valuable behavior checks, but subprocess execution does not contribute much statement coverage to the parent `cmd/vault` test process.

Treat coverage as an informational signal, not a release gate yet. As command-independent logic moves into `internal/...` packages, `cmd/vault` should become thinner while internal package coverage becomes the main quality signal.
