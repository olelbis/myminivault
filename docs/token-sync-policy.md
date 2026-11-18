# Token And Shared Vault Sync Policy

## Summary

The password-protected main vault is the source of token grants. The shared
vault contains the union of active **read** scopes, plus authorized token
writes awaiting import. A write-only grant does not copy existing values into
the mirror. Scopes and read/write permissions are CLI checks, not separate
cryptographic compartments for each token.

Master-password commands reconcile pending writes and monotonic usage counts
before rebuilding the mirror. The main copy becomes durable before shared
state is discarded. This is local synchronization, without a merge base or
distributed conflict resolution.

## Runtime Files

All paths resolve under the active runtime home (`MYMINIVAULT_HOME` or
`~/.myminivault/`):

- `vault.db`: master-password-encrypted main vault and token grants.
- `shared-token-vault.json`: token-key-encrypted scoped values, grants, usage,
  update/deletion metadata, and pending-write markers.
- `vault-token.key`: the token master key for the file backend.
- `vault-tokens.json`: grant-to-path metadata, without bearer tokens or values.
- `shared-token-vault.json.reconcile`: a non-secret durable interruption marker.

The token master key derives distinct HKDF-SHA256 encryption and signing
subkeys. Encryption uses `myminivault:shared-token-vault` with a per-file salt;
v3 HMAC-SHA256 signing uses `myminivault:compact-token-signing:v3` with empty
salt. Six-field and v2 tokens remain retired and require revocation/reissue.

A `.bak` exists only during atomic replacement. Successful saves remove it;
cleanup also removes obsolete `.tmp` files. On an interrupted rename, an
authenticated master command can reconcile the backup, or initial staging
file, before rebuilding. An unreadable snapshot or key error aborts the
operation instead of generating a replacement key or overwriting the state.
Copied snapshots outside the runtime directory cannot be removed by the CLI.

Legacy migration moves a reconciliation marker before token/main state. It
preserves interrupted bundles instead of mixing them into an occupied runtime,
and recognizes directory aliases as the same context. Inventory and permission
checks include the marker, backup, and staging snapshot. Authenticated rebuilds
remove stale staging only after the main copy is durable.

Scoping and unlinking old snapshots do not guarantee physical erasure or undo
previously copied file-key/full-mirror pairs. After an actual compromise,
rotate exposed secret values as well as the token key.

## Upgrade Existing Token State

Run `vault sync-tokens` with the master password after upgrading. It reconciles
old counters and authorized writes, removes unrelated mirrored values and
metadata, and writes `token_state_version: 1`. Token commands require this
scoped state; existing v3 bearer strings remain valid subject to their grants,
expiry, and usage. Legacy containers remain readable through the documented
container migration policy.

Legacy full mirrors have no dirty-key markers. Their one-time import is
limited to unchanged write grants known to both main and shared vaults. New
state imports only keys explicitly marked in `sync.pending_writes`.

## Current Flow

### Master-Password Commands

1. Decrypt the main vault and check rollback policy.
2. Authenticate shared state using the existing token key; check vault identity.
3. Import only authorized pending writes and merge usage with `max(main, shared)`
   for existing, unchanged grants. Never add grants from the shared vault.
4. Create a durable reconciliation marker. Clean expired/exhausted grants and
   persist imported data/counters before executing the requested command.
5. Save command changes, rebuild the scoped mirror, update registry metadata,
   and remove the marker after successful completion.

Read commands also persist imported changes. When no active grants remain,
after pending writes/counters are saved, the shared file and obsolete snapshots
are removed. No token key is created by ordinary reads, diagnostics, or sync.
A new key is created only through explicit token creation or authenticated
regeneration. Token creation can migrate an existing file key to Keychain;
read-only compatibility lookup does not migrate it.

### Token Commands

Token `get`, `list`, and `search` read the scoped mirror. Token `set` marks its
key as pending and saves it with the usage increment before returning success.
Unauthorized or failed operations do not return secret values.

A final-use write must survive until a master can save it. Therefore exhausted
grant counters and authorized pending values may remain in shared state until
reconciliation, even with no usable grants. Other values outside active read
scopes are dropped on the next successful token save or master reconciliation.
Expiry does not erase bytes from an idle filesystem automatically.

## `sync-tokens`

`vault sync-tokens` reconciles data and usage and refreshes the scoped state.
`vault sync-tokens --dry-run` previews authorized data changes and counter
updates without saving vaults, changing keys, cleaning grants, or removing an
interruption marker. Use the normal command to complete a pending reconciliation.

JSON token `set` responses retain `sync_required: true` and
`sync_command: "vault sync-tokens"` until the owner imports the staged write.

## Conflict Policy

Only authorized dirty values participate in current-state import. The newer
per-key update wins when both sides have timestamps. A main deletion tombstone
blocks missing or older/equal shared timestamps before legacy fallback is
considered. A genuinely newer authorized write may intentionally recreate a
key. Unknown grants, modified claims, and read-only grants cannot import writes.

## Interrupted Operations

The reconciliation marker blocks token validation until authenticated repair.
This covers interruption between saving a master revocation/delete and updating
the shared mirror, or failure while saving token usage. `doctor` reports the
marker as a failure. Run `vault sync-tokens` with the master password after
resolving reported filesystem/key errors. Do not delete the marker merely to
bypass the check: it protects against stale token grants and data.

## Restore, Recovery, And Key Rotation

`restore` first preserves pending writes and usage in the pre-restore main-vault
backup, then clears shared state and restores a freshly encrypted candidate
with all token grants removed. If the current main copy is missing or cannot
be opened with the backup password, readable token state is preserved in a
private `.myminivault-restore-tokens-*` archive encrypted with that password.
Ordinary commands refuse to initialize a new vault over orphaned token state.
A subsequent import cannot undo the restore; restoring a backup cannot
reactivate its bearer tokens.

`regenerate-token-key` now requires the master password and confirmation. It
persists pending writes, revokes grants, removes shared snapshots, and replaces
the key. An error leaves token use blocked until authenticated reconciliation;
it does not report successful rotation with an unreadable shared vault.
After a key-store write failure, retry regeneration once the backend is fixed;
`sync-tokens` can repair state consistency but does not replace the token key.

Password recovery also revokes snapshot-era grants. Before replacement it
preserves readable shared state separately in a private
`.myminivault-recovery-tokens-*` directory, encrypted with the **new** password.
This archive is not automatically imported into the recovered snapshot. To
inspect it, restore it in an isolated runtime with the new password; keep it
protected like other vault backups. If shared state cannot be read, recovery
stops before replacing the main vault so the original state is preserved.

## Keychain And Remaining Boundaries

With file-backed storage, copying the token key and shared snapshot exposes
all retained read scopes and pending writes. It does not provide the main
password or unrelated main-vault values. Separate per-token encryption keys
were evaluated: they require a different capability/key-distribution and
pending-write format and are deferred to a dedicated design review. The current
shared key provides no cryptographic isolation between token holders who can
obtain that key. Deriving per-token keys from the same exposed root would not
change this boundary. A candidate stronger design places an independent random
capability key in each bearer token, keeps owner copies inside the password-
protected main vault, and separates encrypted snapshots and write queues by
grant. Its format, revocation, backup, and crash-recovery semantics need review
before implementation.

macOS Keychain can remove the adjacent key-file exposure after migration, but
an authorized local process can still request the shared key. Lifecycle tests
use an injected macOS store for lookup, migration, rotation, missing items, and
write failures; no live personal Keychain access or end-to-end OS ACL test is
claimed. `doctor` authenticates token ciphertext with a read-only provider,
wipes the plaintext buffer, and neither decodes nor prints its secret values.
`inspect-runtime` remains a non-decrypting inventory.
