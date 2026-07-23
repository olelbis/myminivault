# myminivault User Manual

`myminivault` is a local command-line vault for key/value secrets. It is intended as a personal, local tool.

> Experimental personal project. Not audited. Do not rely on it as a production password manager.

Read the [Security Model](security.md) before using real secrets. Recovery behavior is documented in [Recovery Policy](recovery-policy.md), and token synchronization behavior is documented in [Token Sync Policy](token-sync-policy.md).

## Before You Use It

Keep these rules in mind:

- use a strong, unique master password
- keep runtime files out of Git, shared folders, and chat uploads
- treat `vault.db.recovery` plus its recovery key like access to the recovered vault snapshot
- treat `vault-token.key` as critical token-system material
- prefer `copy` for one-off use; treat `export --output` as a persistent plaintext artifact
- rotate exposed secrets rather than relying only on file deletion

## Common Workflows

| Goal | Command |
| --- | --- |
| Add or update a real secret | `printf '%s' "$SECRET" \| vault set KEY --stdin` |
| Add or update a demo value | `vault set KEY value` |
| Print one secret intentionally | `vault get KEY --show` |
| Copy one secret without terminal output | `vault copy KEY --ttl=30s` |
| Export secrets to a restrictive plaintext file | `vault export --output secrets.env` |
| Import shell-style secrets | `vault import secrets.env` |
| Check local file health | `vault doctor` |
| Preview format migration | `vault migrate --dry-run` |
| Create recovery access | `vault setup-recovery` |
| Refresh recovery snapshot | `vault refresh-recovery` |
| Test recovery access | `vault test-recovery` |
| Create scoped temporary access | `vault create-token --keys="API_*" --duration="2h"` |
| Import staged token writes | `vault sync-tokens` |

## Build And Run

Install the latest tagged release with Go:

```bash
go install github.com/olelbis/myminivault/cmd/vault@latest
```

GitHub Releases also provide `.tar.gz`, `.deb`, `.rpm`, macOS `.pkg`, and SPDX JSON SBOM assets. Release workflow assets include SHA-256 checksum manifests and GitHub artifact attestations.

Prefer the macOS `.pkg` release asset on macOS. The `.tar.gz` binary is unsigned and not notarized, so Gatekeeper may block it when downloaded from a browser.

For local testing of an unsigned `.tar.gz` binary, make it executable first:

```bash
chmod +x ./vault
./vault help
```

Only as an explicit local exception, if Gatekeeper blocks that unsigned binary and you trust the downloaded release asset you verified, remove quarantine from that one file:

```bash
xattr -dr com.apple.quarantine ./vault
./vault help
```

Build the CLI from the repository root:

```bash
go build -o bin/vault ./cmd/vault
```

Local builds show `vdev` in help output. Official release packages inject the release version from the Git tag.

Show help:

```bash
./bin/vault help
```

## Password Model

Most commands ask for the master password. If the vault does not exist yet, entering a new password creates it. Use the same password for later commands.

```bash
printf '%s' "$API_KEY_VALUE" | ./bin/vault set API_KEY --stdin
```

The master password is never stored directly. It derives the encryption key used to open `vault.db`.

## Basic Workflows

### Set A Secret

Prefer stdin when the value should not appear directly in process arguments or shell history:

```bash
printf '%s' "$API_KEY_VALUE" | ./bin/vault set API_KEY --stdin
```

For demos or low-risk test values, the positional form remains available:

```bash
./bin/vault set API_KEY secret-value
```

`set --stdin` reads the remaining standard input after the master password prompt. One trailing newline is removed so `echo secret | vault set KEY --stdin` stores `secret`, while embedded newlines are preserved.

Keys must:

- not be empty
- be at most 255 characters
- not contain spaces, quotes, backslashes, `=`, `:`, `;`, or `,`

### Get A Secret

```bash
./bin/vault get API_KEY --show
```

`get --show` prints plaintext to the terminal by explicit request. Use `copy` when terminal scrollback is a concern.

Values passed directly to `vault set KEY value` and compact tokens passed directly to `vault use-token <token>` are process arguments. They may be visible to process inspection, shell history, wrappers, monitoring, or crash diagnostics depending on the platform. Prefer `vault set KEY --stdin` for real secrets and `vault use-token --stdin ...`, `vault use-token --token-file ...`, or `vault use-token --token-fd ...` for compact tokens. Avoid recording commands containing secrets or compact tokens in persistent scripts or shared shell sessions.

### Delete A Secret

```bash
./bin/vault delete API_KEY
```

Deletes a key from the main vault and mirrors the updated main vault to the shared token vault when token runtime files exist.

### List Keys

```bash
./bin/vault list
```

Lists key names only. Values are not printed.

### Search Keys

```bash
./bin/vault search API --show
```

Searches keys by case-insensitive substring and prints matching key/value pairs only with `--show`.

Search prints values for matching keys. Avoid it on recorded or shared terminals.

### Clear Vault

```bash
./bin/vault clear
```

Deletes all entries after confirmation.

### Stats

```bash
./bin/vault stats
```

Shows vault metadata, recovery status, token summary, access count, and timestamps.

## Import And Export

### Export

```bash
./bin/vault export --output secrets.env
```

`export --output` writes entries as shell-safe `export KEY='value'` lines. Export uses POSIX single-quote escaping, so values containing quotes, `$`, backticks, backslashes, and newlines are printed without triggering shell expansion.

Export files are plaintext secrets. They may be copied by backups, Time Machine, cloud-sync folders, editors, indexing tools, or other local processes. The command asks for confirmation before writing. For controlled automation only, use:

```bash
./bin/vault export --output secrets.env --yes
```

Plaintext stdout export is still available for controlled automation, but it must be requested explicitly:

```bash
./bin/vault export --stdout
```

The output file is written with `0600` permissions. Delete export files when they are no longer needed and rotate any exposed secrets.

### Import

```bash
./bin/vault import secrets.env
```

Imports lines in either format:

```text
API_KEY=secret-value
export API_KEY="secret-value"
```

Blank lines and lines starting with `#` are ignored.

## Clipboard Copy

```bash
./bin/vault copy API_KEY
./bin/vault copy API_KEY --ttl=30s
```

Copies a single secret to the system clipboard without printing it to the terminal. The CLI warns that other local apps or clipboard managers may read clipboard contents.

By default, the command waits for the TTL and clears the clipboard if it still contains the copied secret. Use `--ttl=0` to skip automatic clearing.

Clipboard copy avoids terminal scrollback, but it is not a hard security boundary. Clipboard managers, remote desktop tools, malware, or other local apps may still observe clipboard contents.

## Backup

Create a timestamped backup of `vault.db`:

```bash
./bin/vault backup
```

The backup filename looks like:

```text
vault.db.2026-05-15_22-30-00.bak
```

The normal save path also keeps `vault.db.bak` as the previous version of the vault. The loader uses `vault.db.bak` only when `vault.db` is missing, not as a fallback for wrong passwords.

## Local Health Check

```bash
./bin/vault doctor
```

Checks local runtime health without asking for the master password. It reports config validity, runtime file permissions, timestamped backup presence, lock-file presence, recovery freshness and compatibility, token files, and log file status.

Sensitive runtime files should normally be readable only by the local user. Startup rejects symlinked sensitive runtime paths and tightens file permissions when possible. `vault doctor` warns when files such as `vault.db`, backups, recovery snapshots, token files, or logs are group/world-readable, and reports symlinked sensitive files as failures. It also warns when `vault.db.recovery` appears older than the main vault, has an unexpected container kind, or was written with crypto parameters that differ from the current config.

## Runtime Inspection

```bash
./bin/vault inspect-runtime
```

Lists the active runtime home, whether it came from `MYMINIVAULT_HOME` or the default `~/.myminivault/`, active runtime files, a recovery/main-vault relationship summary, and legacy current-directory runtime files. It shows path, modified time, size, mode, and encrypted container format details where available, but it does not decrypt vaults or print secrets.

Example:

```bash
MYMINIVAULT_HOME=/tmp/myminivault-demo ./bin/vault inspect-runtime
```

Use this when:

- you changed `MYMINIVAULT_HOME` and want to confirm which vault context is active
- you upgraded from an older version and want to check whether legacy files remain in the current directory
- `vault` looks empty and you suspect you are pointing at a different runtime home
- `vault doctor` reports recovery freshness or compatibility warnings
- you want to review file permissions without unlocking the vault

## Migration Preview

```bash
./bin/vault migrate --dry-run
```

Previews encrypted runtime file format migration without asking for the master password and without modifying files. It inspects active main vault, backup, recovery, and shared token vault files, reports whether each file is missing, legacy, `MYMV v1`, or current `MYMV v2`, and shows which files would be rewritten by a future real migration command.

The real mutating `vault migrate` command is not implemented yet. Current saves already rewrite readable older files as `MYMV v2` after normal authenticated save operations.

## Password Recovery

For the exact snapshot, divergence, verifier, and rotation policy, see [Recovery Policy](recovery-policy.md).

### Setup Recovery

```bash
./bin/vault setup-recovery
```

Generates a high-entropy recovery key and asks you to retype it to confirm that you saved it. The key is a grouped base32 string derived from 32 secure random bytes.

Setup writes a recovery-encrypted snapshot to `vault.db.recovery`.

The recovery key alone is not enough to recover the vault, and `vault.db.recovery` alone is not enough. Together, they are enough to recover the secrets present in that recovery snapshot.

### Test Recovery

```bash
./bin/vault test-recovery
```

Checks whether a recovery key matches the configured recovery data.

### Refresh Recovery Snapshot

```bash
./bin/vault refresh-recovery
```

Asks for the recovery key, validates it, and rewrites `vault.db.recovery` from the current main vault without changing the recovery key or master password. Use this after important vault changes when recovery is part of your operational plan.

### Recover Master Password

```bash
./bin/vault recover
```

Uses the recovery key to decrypt the recovery vault copy and set a new master password.

Recovery can recover only the snapshot stored in `vault.db.recovery`. If the main vault and recovery snapshot diverge, recovery behavior follows the recovery snapshot. Keys added after the latest recovery snapshot may be missing after recovery, and keys deleted after the latest recovery snapshot may reappear.

### Rotate Recovery

There is no dedicated `rotate-recovery` command yet. To replace the recovery key, run:

```bash
./bin/vault setup-recovery
```

Confirm replacement when prompted, save the new key securely, then run:

```bash
./bin/vault test-recovery
```

Older backups may still contain recovery snapshots encrypted for older recovery keys. Rotate or remove historical backup files according to your own security needs.

### Change Master Password

```bash
./bin/vault change-password
```

Prompts for the current master password first, then asks for the new password and confirmation.

## Token System

The token system creates temporary signed tokens that can access only matching keys and only with selected permissions.

Token access uses:

- a compact signed token string
- token expiration time
- max-use limits
- key pattern restrictions
- read/write permissions
- encrypted shared token vault

### Create Token

```bash
./bin/vault create-token --keys="API_*" --duration="2h" --permissions="read" --max-uses=20
```

| Option | Required | Description |
| --- | --- | --- |
| `--keys=<pattern>` | Yes | Key pattern. `*` is supported as a wildcard |
| `--duration=<duration>` | Yes | Go duration such as `30m`, `2h`, `24h` |
| `--permissions=read,write` | No | Defaults to `read` |
| `--max-uses=N` | No | Defaults to `100` |

Token duration and max uses must be greater than zero. Maximum token duration is 24 hours. Token key patterns cannot contain `:` because compact tokens use colon-delimited signed payloads.

### Use Token

Read a key:

```bash
./bin/vault use-token <token> get API_KEY --show
printf '%s' "$MYMV_TOKEN" | ./bin/vault use-token --stdin get API_KEY --show
./bin/vault use-token --token-file /run/secrets/myminivault-token get API_KEY --show
./bin/vault use-token --token-fd 3 get API_KEY --show
```

Write a key:

```bash
./bin/vault use-token <token> set API_KEY new-value
```

List accessible keys:

```bash
./bin/vault use-token <token> list
```

Search accessible keys:

```bash
./bin/vault use-token <token> search API --show
```

Machine-readable token output for third-party programs:

```bash
./bin/vault use-token <token> get API_KEY --json
printf '%s' "$MYMV_TOKEN" | ./bin/vault use-token --stdin get API_KEY --json
./bin/vault use-token --token-file /run/secrets/myminivault-token get API_KEY --json
./bin/vault use-token <token> list --json
./bin/vault use-token <token> search API --json
```

Example success payload:

```json
{"key":"API_KEY","value":"secret"}
```

Example error payload:

```json
{"error":"token has expired"}
```

When `--json` is used, token command errors are printed as JSON and the process exits non-zero, so subprocess callers can parse stdout and still rely on exit status. Successful authorized token commands consume one token use; failed validation, permission, or key-pattern checks do not. The compact token is still a bearer secret: pass it through a secret store, protected file, inherited file descriptor, or environment variable, avoid committing it, and prefer `use-token --stdin`, `use-token --token-file`, or `use-token --token-fd` so the token is not placed directly in the command line.

Python:

```python
import json
import os
import subprocess

payload = subprocess.check_output(
    ["vault", "use-token", "--stdin", "get", "API_KEY", "--json"],
    input=os.environ["MYMV_TOKEN"],
    text=True,
)
secret = json.loads(payload)["value"]
```

Go:

```go
cmd := exec.Command("vault", "use-token", "--stdin", "get", "API_KEY", "--json")
cmd.Stdin = strings.NewReader(os.Getenv("MYMV_TOKEN"))
out, err := cmd.Output()
if err != nil {
    panic(err)
}
var payload struct {
    Key   string `json:"key"`
    Value string `json:"value"`
}
if err := json.Unmarshal(out, &payload); err != nil {
    panic(err)
}
secret := payload.Value
```

Java:

```java
Process p = new ProcessBuilder("vault", "use-token", "--stdin", "get", "API_KEY", "--json").start();
p.getOutputStream().write(System.getenv("MYMV_TOKEN").getBytes(java.nio.charset.StandardCharsets.UTF_8));
p.getOutputStream().close();
String payload = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
if (p.waitFor() != 0) {
    throw new IllegalStateException(payload);
}
```

### Manage Tokens

```bash
./bin/vault list-tokens
./bin/vault token-info <token-id>
./bin/vault revoke-token <token-id>
./bin/vault cleanup-tokens
```

Regenerate the token master key:

```bash
./bin/vault regenerate-token-key
```

This invalidates all existing tokens.

If `vault-token.key` is exposed, run `regenerate-token-key` and treat existing tokens and shared-token-vault state as compromised.

## Main And Shared Vault Synchronization

The CLI keeps a main vault and a shared token vault:

- `vault.db` is the main password-protected vault
- `shared-token-vault.json` is an encrypted shared vault used for token commands

Commands that mutate the main vault, such as `set`, `delete`, `clear`, and `import`, mirror the main vault back to the shared token vault after saving only when token runtime files already exist or token data is configured.

Token write operations save immediately to the shared token vault. Master-password commands import token-side changes from the shared vault before running, and you can also import them explicitly with:

```bash
./bin/vault sync-tokens
```

To preview staged token changes before saving them into `vault.db`:

```bash
./bin/vault sync-tokens --dry-run
```

The dry run lists keys that would be imported or updated, keys that would be deleted, conflicts that would be skipped, and decisions that depend on legacy sync metadata. It does not save `vault.db`, `shared-token-vault.json`, or `rollback-state.json`.

Sync policy:

- `vault.db` is the master-password source of truth after a master command saves
- token writes are staged in `shared-token-vault.json`
- master commands import staged token writes before they execute
- ordinary password commands do not create token runtime files until token features are used
- master mutations mirror the full main vault back to the shared vault after saving once token runtime files exist, so deletes remain deleted
- conflict handling uses per-key sync timestamps when both vaults have metadata; legacy vaults without metadata fall back to simple import behavior
- when `vault doctor` reports that `shared-token-vault.json` is newer than `vault.db`, run `sync-tokens` to persist staged token writes into the main vault

## Locking And Concurrent CLI Usage

Vault commands use `.myminivault.lock` to serialize separate CLI processes while they access runtime vault files. This reduces cross-process write races around `vault.db`, token files, and the shared token vault.

If another `vault` process keeps the lock busy, a command waits for a bounded time and then exits with a readable timeout message instead of waiting indefinitely.

The lock is advisory. It coordinates cooperating `vault` processes, but it does not stop unrelated programs from editing or deleting files.

## Security Audit

```bash
./bin/vault security-audit
```

Reports recovery status, token status, vault key count, access count, vault version, last access time, and runtime file presence.

## Configuration

Show current config:

```bash
./bin/vault config
```

Default values:

| Setting | Default |
| --- | --- |
| `scrypt_n` | `32768` |
| `scrypt_r` | `8` |
| `scrypt_p` | `1` |
| `key_size` | `32` |
| `max_backups` | `5` |
| `audit_log` | `true` |
| `token_key_storage` | `auto` |

The program loads `vault-config.json` from the runtime directory.

The scrypt settings are retained as the compatibility fallback for deprecated
legacy files. Newly written `MYMV v2` runtime files use the authenticated
Argon2id metadata stored in the container header.

Config validation:

- `scrypt_n` must be a power of two between `32768` and `1048576`
- `scrypt_r` must be between `1` and `16`
- `scrypt_p` must be between `1` and `8`
- `key_size` must be `16`, `24`, or `32`
- `max_backups` must be between `1` and `100`
- `token_key_storage` must be `auto`, `file`, or `keychain`

Manual timestamped backups keep only the newest `max_backups` files.

If `vault-config.json` is malformed or unsafe, the CLI stops with a config error.

`token_key_storage` controls where token master-key material is stored:

- `auto` prefers macOS Keychain when available and uses the `vault-token.key` file fallback elsewhere, including Linux
- `file` explicitly keeps the current `vault-token.key` runtime file behavior
- `keychain` requires an implemented OS keychain backend and fails clearly when unavailable

On first token use, `auto` can migrate an existing macOS `vault-token.key` into macOS Keychain and then remove the old file. On Linux, token key storage is file-based by design for now. `vault doctor` checks for both a DBus session and `secret-tool` before reporting Secret Service as available, but Linux still uses the file fallback. Other OS stores remain future work.

Audit logging is enabled by default but intentionally avoids key names and token identifiers. To disable audit logging:

```json
{
  "audit_log": false
}
```

## Runtime Files

By default, runtime files live in:

```text
~/.myminivault/
```

Set `MYMINIVAULT_HOME=/path/to/dir` to use a separate runtime directory. This is useful for tests, disposable demos, or intentionally isolated vaults.

### Runtime Home Override

`MYMINIVAULT_HOME` controls the complete runtime home. Every runtime file is resolved relative to that directory:

- main vault
- recovery snapshot
- backups
- token master key
- shared token vault
- token registry
- audit log
- config file
- lock file

Temporary isolated vault:

```bash
MYMINIVAULT_HOME=/tmp/myminivault-demo vault set API_KEY hello
MYMINIVAULT_HOME=/tmp/myminivault-demo vault list
```

Persistent alternate vault:

```bash
export MYMINIVAULT_HOME="$HOME/.myminivault-work"
vault set WORK_API_KEY hello
```

Important behavior:

- if `MYMINIVAULT_HOME` is not set, the default is `~/.myminivault/`
- the runtime directory is created with owner-only `0700` permissions
- changing `MYMINIVAULT_HOME` changes which vault the CLI sees
- `vault config` prints the active `runtime_home`
- `vault inspect-runtime` prints active and legacy runtime files without decrypting vault data
- legacy runtime files in the current working directory are migrated only if the target file is missing
- normal commands tighten existing runtime file permissions to `0600` when possible
- sensitive temp and transaction files fail on pre-existing paths instead of reusing them
- `vault doctor` and `vault inspect-runtime` report permissions without changing them
- do not use a Git repo, shared folder, or cloud-sync folder unless you understand the exposure and conflict risks

| File | Purpose |
| --- | --- |
| `vault.db` | Main encrypted vault |
| `vault.db.bak` | Backup of previous main vault version |
| `vault.db.transaction` | Temporary marker used to detect and recover interrupted main-vault saves |
| `vault.db.recovery` | Recovery-encrypted vault copy |
| `vault-token.key` | Local token master key when file-backed token key storage is used |
| `shared-token-vault.json` | Encrypted shared vault used by token access |
| `shared-token-vault.json.bak` | Previous encrypted shared vault retained during atomic replacement |
| `vault-tokens.json` | Token registry metadata |
| `rollback-state.json` | Local trusted high-water revision used for rollback warnings |
| `vault.log` | Audit log |
| `vault-config.json` | Optional config override |
| `.myminivault.lock` | Inter-process lock file |

Current encrypted runtime files include a small cleartext `MYMV v2` container header with the container format version, file kind, and non-sensitive crypto metadata. New saves use Argon2id metadata. This helps `vault doctor` and `vault inspect-runtime` identify file format information without decrypting secrets. The v2 cleartext context is authenticated with AES-GCM AAD, so header or metadata tampering makes decryption fail. Mutating password-based saves also keep encrypted vault rollback metadata and update `rollback-state.json`; if a later command sees an older valid vault revision, it warns instead of silently lowering trusted local state. scrypt-based `MYMV v2`, older `MYMV v1`, and salt-plus-ciphertext files remain readable but are deprecated and are upgraded to the current Argon2id-based profile when rewritten.

These files are ignored by Git because they may contain encrypted secrets, keys, logs, or local runtime state.

If older runtime files are found in the current working directory and the runtime directory does not already contain matching files, the CLI migrates them into `~/.myminivault/` on startup. Symlinked legacy runtime files are skipped instead of being followed.

## Troubleshooting

### Wrong Password

If `vault.db` exists and the password is wrong, the CLI rejects access. It does not silently fall back to `vault.db.bak`.

### Missing Runtime Files

If no vault exists, the first password-protected write creates one. Token runtime files are created only when token features are used.

### Token Changes Not Visible

Run:

```bash
./bin/vault sync-tokens
```

Master-password commands also import staged token writes before running.

### Recovery Key Does Not Work

Check whether recovery was configured and whether `vault.db.recovery` exists. Recovery can recover only the recovery-encrypted snapshot.
