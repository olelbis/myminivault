# Token Lifecycle Security Review — 2026-11-18

Reviewed baseline: `6afc0b0499ef51b2de26f4f8d54e82779d2ba270` (after PR #21).
This is a focused source review with isolated reproductions, not an external audit.
No production code, personal runtime, or live Keychain items were changed or read.

## Findings

### SR-1 / P1: Keychain writes expose the token root in subprocess arguments

Location: `internal/keychain/keychain.go`, `Store.SaveTokenKey`, lines 115–116.
Creation, migration, and rotation pass the Base64-encoded 32-byte token root as
`security add-generic-password ... -w <encoded-key> -U`. Base64 is reversible.
An observer able to capture these process arguments can obtain the root without
reading a Keychain item. With a copied shared snapshot, that root decrypts all
retained read scopes and pending writes and derives its token signing key.
It does not reveal the main password or values absent from the snapshot.

Confirmed with an injected command runner: decoding the `-w` argument recovers
the exact fake root. No live cross-user process capture was performed; actual
argument visibility depends on OS permissions and monitoring configuration.
This is actionable even though same-user process inspection is a documented
non-goal: the CLI introduces the exposure during otherwise protected key input,
and capture through process monitoring need not imply full same-user compromise.

Proposed fix: use a reviewed Keychain API path that passes secret bytes in memory,
with no secret in argv, environment, or diagnostic output. Test create, lookup,
update, denial, missing item, locked backend, and failure without silent fallback.
Validate ACL and prompt behavior separately on an isolated macOS account.

### SR-2 / P2: Relative runtime homes collide in the Keychain namespace

Locations: `cmd/vault/config_cli.go`, `initializeRuntimePaths`, lines 76–81;
`internal/paths/paths.go`, `RuntimeHome`; `cmd/vault/token_key_cli.go` store calls.
`MYMINIVAULT_HOME=runtime` remains relative. From two different working directories,
the two distinct on-disk vaults both use account `runtime/vault-token.key` under
the same Keychain service. They silently share one root. Rotation in one runtime
replaces the other's root, making the other's token snapshot unreadable. Its
ordinary password commands then abort during shared-state reconciliation; pending
writes require the original key to recover. This does not expose either main
password or demonstrate access to unrelated password-encrypted main data.

Confirmed in a temporary checkout with a fake Keychain map: create two separate
runtime directories, create both snapshots, replace A's root, and observe B's
snapshot authentication fail. No live Keychain was accessed.

Proposed fix: define stable absolute runtime identity before choosing the account;
handle directory aliases deliberately. Preserve access to legacy relative and
aliased accounts through an authenticated, explicit migration that checks key
consistency and conflicts before moving or deleting anything. Simply changing
the account string would strand existing installations. Add two-runtime and
migration regressions, including separate rotations and pending writes.

### SR-3 / P2: File-backed root persistence lacks a durable atomic commit

Locations: `internal/token/token.go`, `SaveMasterKey`, lines 61–65;
`internal/paths/paths.go`, `WriteFileChecked`, lines 98–108.
The key is written with `O_TRUNC`, closed, and chmodded, with no key-file `Sync`
and no atomic replacement. In contrast, shared snapshots and reconciliation
markers are synchronized. A successful creation or rotation therefore does not
establish that the key bytes are durable before subsequent token state becomes
durable and the barrier is cleared. After sudden host failure, a lost or damaged
key can strand a successfully saved snapshot, including pending token writes.
Directory synchronization alone is not a substitute for synchronizing file data.

Evidence is source inspection, not a power-loss reproduction. Rotation already
saves pending writes to main and revokes grants before replacing the root; this
finding does not claim that successful rotation alone loses those main values.

Proposed fix: exclusive checked staging at mode 0600, complete write, file sync,
checked atomic replacement, and parent-directory sync before success. Define
interrupted-stage recovery and failure behavior. Test injected failures and the
first-key-create → token-write → restart lifecycle, without real secrets.

## Lifecycle Review Results And Limits

Inspected scoped projections, unchanged-grant write authorization, monotonic
usage merge, tombstone precedence, token success ordering, reconciliation barriers,
restore/recovery archives, rotation, and read-only key lookup. No additional
confirmed scope bypass or grant resurrection was found in those reviewed paths.
Passing tests do not establish completeness or OS-level security guarantees.

The shared root still decrypts the union of retained scopes and pending writes.
Per-token capability keys must be independent random values, with separate read
snapshots and write queues. A root available to every token holder would defeat
that isolation. Define read and write capabilities, owner key custody, authenticated
grant identity, counters, replay policy, expiry, revocation, crash recovery, and
upgrade behavior before implementation. A copied bearer and ciphertext remain
readable offline after revocation; offline max-use enforcement needs an explicit
trusted-state assumption. OS account compromise remains outside current guarantees.

`docs/security.md` still describes file-to-Keychain migration on first token use;
current code migrates only during explicit token creation. Correct that wording
with the implementation follow-up.

## Verification

Go 1.27.3, macOS arm64, 2026-11-18. Isolated tracked-source copy under
`/tmp/myminivault-security-review-_mmbzvz6`, fake secrets and fake Keychain runner.
Existing critical lifecycle, scope/import, migration, and Keychain tests passed
with `-race -count=1` across `internal/token`, `internal/sync`, `internal/keychain`,
and `cmd/vault` using a targeted test-name filter. Both added review reproductions
passed under the race detector. Reproduction tests exist only in the temporary
copy (`cmd/vault/security_review_repro_test.go`); they assert that the defects
occur and must be inverted into regressions during fixes. Logs: `validation.log`
and `repro.log` in that directory. Temporary artifacts are not durable project
fixtures. No full-suite run or new coverage measurement was needed for this
review; historical coverage remains unchanged.

## Recommended Follow-Up

Fix SR-1 through SR-3 before release, starting with root handling and runtime
identity. Keep per-token format implementation as a subsequent reviewed design.
For live Keychain validation, use a dedicated macOS test account and disposable
Keychain with fake material; avoid modifying the personal login Keychain or its
search list. Explicitly target only the disposable Keychain, then test locked,
unlocked, denied, missing, concurrent, and interrupted operations and cleanup.
The current backend lacks an explicit Keychain selector; a harness must provide
that isolation before any live run. Do not use the current unqualified backend
against personal Keychain state. Verify ACLs and prompts without assuming that
the presence of the `security` executable means the store is unlocked or usable.

After authorized fixes, run focused regressions, the full suite, race checks,
`go vet`, internal coverage (at least 80%), gofmt, and `git diff --check`.
No commit, push, PR, issue update, merge, tag, or release is authorized by this review.

## Implementation Follow-Up — 2026-11-18

The original findings above describe baseline `6afc0b0` and are retained as review
history. Fixes on `token-key-security` address all three:

- SR-1: `save_darwin.go` uses SecItemUpdate/SecItemAdd with an in-memory Base64
  buffer. No secret enters subprocess argv. Read/delete compatibility retains
  `security`; native writes require CGO, enabled for macOS release builds.
  Non-CGO writes fail explicitly. Native OS ACLs/prompts remain unverified.
- SR-2: canonical absolute accounts, read-only fallback to the original legacy
  spelling, authenticated migration with snapshot validation and saved-key
  readback, and canonical-only rotation. Legacy items remain for other runtimes.
  Regressions cover distinct relative homes, parent aliases, retained ciphertext,
  migration failure, wrong keys, conflicts, readback mismatch, and rotation.
- SR-3: random exclusive 0600 staging, file sync, atomic rename, parent sync;
  failed pre-rename operations preserve the old key. Directory-sync failures
  return errors even if the new complete key is visible. Interrupted staging
  is never adopted on restart. Failure-injection regressions cover these phases.

Existing runtime spelling must be retained for first legacy lookup/migration.
Legacy root copies initially contain the same key; rotate migrated runtimes to
separate them. Native access validation requires an isolated harness first;
no live Keychain items have been read or written in this task.

Follow-up validation: Go 1.27.3 on macOS arm64, full `go test -race -count=1
-covermode=atomic -coverprofile=/tmp/myminivault-sr-coverage.out ./...` passed,
including all 35 CLI smoke tests (414.672 seconds for the smoke package).
Final focused migration/native-boundary tests and internal race coverage passed:
85.4% (1,275/1,493 statements). `go vet`, Staticcheck v0.8.2, Darwin native build,
Linux non-CGO cross-build, Darwin non-CGO fallback tests, gofmt, documentation
links, and diff checks passed. See `docs/coverage.md` for the final profile.
No real Keychain, power-loss, remote CI, packaging install, or release test is
claimed. The user subsequently authorized commit, push, and PR creation. CI review and merge remain with the user; cleanup requires a separate post-merge go-ahead. No release is authorized.


## Merge And Closure

PR #22 merged on 2026-11-18 as `190c422`. CI and Security Scanning completed
successfully, including CodeQL analysis/upload. The user authorized post-merge
cleanup; local main was fast-forwarded and the task branch removed locally and
remotely. Live isolated Keychain validation remains the next task. No release
was prepared or published.
