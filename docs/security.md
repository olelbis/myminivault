# myminivault Security Model And Threat Model

`myminivault` is an experimental personal project. It has not been independently audited and should not be treated as a production password manager.

This document defines the current security goals, assumptions, trust boundaries, known limitations, and residual risks. The purpose is to keep future development honest about what the tool protects, what it only mitigates, and what it explicitly does not defend against.

## Scope

This model covers the local CLI, local runtime files, recovery workflow, token workflow, import/export behavior, clipboard behavior, coverage/release checks, and release artifacts.

It does not cover hosted infrastructure, remote synchronization services, browser extensions, mobile clients, multi-user deployments, or enterprise administration because those features do not exist in the project.

## Security Goals

`myminivault` aims to:

- keep vault values encrypted at rest in local runtime files
- derive encryption keys from a master password using scrypt
- authenticate encrypted payloads with AES-GCM
- support recovery without storing the master password
- support temporary token access with key-pattern, permission, expiry, and max-use limits
- reduce local write races with an inter-process lock file
- keep runtime vault files out of Git by default
- avoid printing plaintext where a safer workflow exists, such as `copy` or `export --output`
- document operational risks clearly before claiming stronger guarantees
- keep security-sensitive behavior covered by automated tests where practical

## Non-Goals

`myminivault` does not currently aim to provide:

- enterprise password manager guarantees
- audited cryptographic design
- protection from malware or a compromised local user account
- protection from an attacker who can run arbitrary code as the same OS user
- remote sync security
- multi-user access control
- hardware-backed key storage
- strong memory-hardening against local process inspection
- protection from secrets copied into shell history, terminal scrollback, logs, screenshots, remote desktop tools, or clipboard managers
- guaranteed recovery from every backup or historical vault state

## Protected Assets

Treat these as sensitive:

- master password
- vault contents
- recovery key
- token master key in `vault-token.key`
- compact token strings printed by `create-token`
- `vault.db`
- `vault.db.bak`
- `vault.db.recovery`
- `shared-token-vault.json`
- `vault-tokens.json`
- backup files such as `vault.db.<timestamp>.bak`
- `vault.log` if command timing or action metadata reveals context
- exported shell snippets and files created by `vault export --output`
- clipboard contents after `vault copy`

## Attacker Model

The primary attacker considered by the current design can read or copy project runtime files after trusted commands have run.

This includes cases such as:

- accidental Git staging of runtime files
- backup leakage
- copied project folders
- overly broad local filesystem permissions
- another local user reading world-readable files

The project has only partial or best-effort mitigations for:

- an attacker who can modify runtime files between trusted command runs
- an attacker who can observe terminal input or output
- an attacker who can read shell history or terminal scrollback
- an attacker who can steal a compact token before it expires
- an attacker who can copy encrypted vault files and attempt offline password guessing

The project does not defend against:

- malware running as the same OS user
- debuggers, memory dump tools, or process inspection by the same user
- a compromised terminal emulator, shell, OS account, or machine
- a malicious or replaced binary/source tree that the user later runs
- a compromised Go toolchain or dependency supply chain
- a user intentionally exporting or pasting secrets into unsafe locations

## Trust Boundaries

### Build And Source Boundary

The source tree and executable are trusted inputs. Changing the source code does not make an already encrypted `vault.db` decryptable by itself, because decryption still requires the master password, a valid recovery path, or secrets already available at runtime.

A modified executable becomes dangerous when a user runs it and provides credentials. It could capture the master password, write derived keys to disk, print decrypted secrets, weaken command checks, or exfiltrate plaintext after a successful decrypt. This is treated as a supply-chain or local-code-execution compromise, not as a supported threat the vault can defend against.

### Local Process Boundary

The CLI process is trusted while it runs. Plaintext secrets, passwords, derived keys, and decrypted vault data may exist in process memory during command execution.

The CLI disables core dumps on supported Unix-like systems as a best-effort mitigation, but this is not a sandbox and not a defense against same-user process inspection.

### Runtime File Boundary

Runtime files are local files under `~/.myminivault/` by default. Encrypted vault files are designed to tolerate file copying better than plaintext files, but copied files still enable offline password guessing and may contain historical secrets.

File permissions are an important local mitigation, not a complete security boundary.

Newly saved encrypted runtime files include a small cleartext `MYMV` container header with a container format version and file kind. This supports safer inspection and future migrations without decrypting secrets. The header reveals that a file is a myminivault encrypted container and whether it is a main, recovery, or shared-token vault file; it does not reveal key names, values, recovery metadata, token contents, or encrypted vault metadata.

### Terminal Boundary

Anything printed to the terminal can be captured by terminal scrollback, shell wrappers, logs, screen recording, remote desktop software, or clipboard copy.

`get` and plain `export` intentionally print plaintext. Prefer `copy` for one secret and `export --output <file>` for export artifacts when terminal exposure matters.

### Clipboard Boundary

`copy` avoids terminal output, but the clipboard is shared local OS state. Clipboard managers, local apps, remote desktop tools, and malware may read it.

`copy` clears the clipboard after a TTL when supported and only if the clipboard still contains the copied secret. This is a best-effort cleanup, not a hard guarantee.

### Main Vault And Shared Token Vault Boundary

`vault.db` is the main password-protected vault. `shared-token-vault.json` is the encrypted vault used by token commands.

Token writes are staged in the shared token vault, then imported by master-password commands. Master mutations mirror the main vault back to the shared token vault when token runtime files exist.

This is a local convenience model, not distributed synchronization. Per-key timestamps reduce overwrite surprises when metadata is available, but there is no full merge-base or multi-device conflict model.

### Release Boundary

GitHub Releases publish source tags, binary archives, and installable packages. Release checksums help detect accidental corruption or mismatched downloads. Release workflow artifacts also receive GitHub artifact attestations, which provide signed build provenance for assets produced by GitHub Actions.

The project does not currently require manually signed commits or tags, and release packages are not notarized or signed with platform-specific installer certificates.

## Runtime Files

Runtime files are stored under `~/.myminivault/` by default. `MYMINIVAULT_HOME` can override this location for tests, automation, or intentionally isolated vaults. The runtime directory is created with `0700` permissions, and sensitive files are written with restrictive file modes where the platform supports them.

Security notes for `MYMINIVAULT_HOME`:

- it changes the active vault context, so a different value may look like an empty or different vault
- it should point to a local directory controlled by the current user
- avoid Git repositories, shared folders, cloud-sync folders, network mounts, or world-readable paths unless that exposure is intentional
- the CLI creates the runtime directory with `0700`, but parent directory permissions and external sync tools remain outside the CLI's control
- legacy cwd migration does not overwrite existing runtime-home files, which avoids accidental replacement but may leave old files behind for manual review

| File | Sensitivity | Primary Risk | Current Mitigation |
| --- | --- | --- | --- |
| `vault.db` | High | Offline password guessing, copied encrypted secrets | AES-GCM encryption, scrypt, restrictive writes |
| `vault.db.bak` | High | Historical encrypted secrets | Same encrypted format, restrictive writes |
| `vault.db.recovery` | High | Recovery-encrypted snapshot exposure | High-entropy recovery key, restrictive writes |
| `vault-token.key` | Critical | Token system compromise | Restrictive writes, `regenerate-token-key`, macOS Keychain support with file fallback |
| `shared-token-vault.json` | High | Token-access vault exposure | Encrypted shared vault, token master key |
| `vault-tokens.json` | Medium | Token registry metadata leakage | Restrictive writes |
| `vault.log` | Medium | Operational metadata leakage | Redacted key/token identifiers, optional logging |
| `vault-config.json` | Low/Medium | Unsafe runtime configuration | Validation on load |
| `.myminivault.lock` | Low | Write coordination confusion | Advisory lock only |

Runtime files should stay out of Git and should normally be readable only by the local user. Legacy runtime files in the current working directory are migrated into the runtime directory when possible, unless the target file already exists.

Legacy encrypted files without a `MYMV` header remain readable as salt-plus-ciphertext files. Once a legacy main, recovery, or shared token vault is saved again, the rewritten file uses the current headered container format.

`token_key_storage` can be set to `auto`, `file`, or `keychain`. On macOS, `auto` prefers macOS Keychain for token master-key material when the `security` tool is available, and can migrate an existing `vault-token.key` into Keychain on first token use. `file` keeps the portable restrictive-file behavior. `keychain` requires an implemented OS backend and fails clearly when unavailable instead of silently writing `vault-token.key`. On Linux, readiness detection requires both a DBus session and `secret-tool`, but Secret Service storage remains future work and the file fallback remains the supported behavior.

The macOS backend stores the token master key under the `myminivault` service and uses the runtime token-key path as the Keychain account, so separate `MYMINIVAULT_HOME` directories do not intentionally share the same token key. The implementation shells out to the macOS `security` tool, so it improves at-rest storage but is not a complete mitigation against same-user process inspection while a token command is running.

## Data Flows

### Password-Protected Vault Commands

1. The user provides a master password.
2. The CLI derives a key from the password and vault salt.
3. The CLI decrypts and authenticates `vault.db`.
4. The command reads or mutates vault data.
5. Mutating commands save atomically and keep a `.bak` copy.
6. If token runtime exists, relevant changes may be mirrored to the shared token vault.

Primary risks:

- weak passwords enable offline guessing if encrypted files are copied
- plaintext exists in process memory during execution
- `get` prints plaintext by design
- interrupted or concurrent writes can corrupt data without proper locking

Current mitigations:

- scrypt key derivation
- AES-GCM authenticated encryption
- checksum verification around serialized vault payloads
- atomic writes with file sync and backup behavior
- inter-process lock file
- safer alternatives such as `copy` and `export --output`

### Recovery Flow

1. `setup-recovery` creates a high-entropy recovery key.
2. A recovery-encrypted vault snapshot is written to `vault.db.recovery`.
3. `recover` uses the recovery key to decrypt that snapshot and reset access.

Primary risks:

- recovery follows the recovery snapshot, not necessarily the latest main vault
- anyone with both recovery key and recovery file can attempt recovery
- recovery file plus recovery key is effectively equivalent to the master password for that recovery snapshot
- historical backups may contain older recovery state

Current mitigations:

- recovery key uses 32 random bytes encoded as grouped base32
- recovery file is written atomically with restrictive permissions
- verifier metadata confirms that the recovery key belongs to the snapshot
- recovery behavior is documented in [Recovery Policy](recovery-policy.md)

### Token Flow

1. `create-token` creates a compact bearer token with scope, expiry, permissions, and max-use limits.
2. Token metadata and shared vault data are stored in encrypted token runtime files.
3. `use-token` validates the token and applies allowed read/write operations.
4. Usage count is persisted after validation.
5. Master-password commands import staged token writes according to the token sync policy.

Primary risks:

- a compact token is a bearer credential while valid
- `vault-token.key` compromise undermines token security
- shared token vault sync is local best-effort, not distributed merge
- token writes may surprise users if they expect fully separate vaults

Current mitigations:

- token expiry and max-use limits
- HMAC token signatures
- key-pattern and permission checks
- encrypted shared token vault
- usage-count persistence
- revocation support
- documented sync behavior in [Token Sync Policy](token-sync-policy.md)

### Export And Clipboard Flow

`export` creates shell-friendly plaintext. `export --output <file>` writes that plaintext to a restrictive file. `copy` writes one secret to the system clipboard and clears it after a TTL when supported.

Primary risks:

- terminal scrollback and shell capture
- plaintext export files
- clipboard managers and local apps
- accidental sharing of copied/exported values

Current mitigations:

- interactive plaintext export warning
- `export --output` writes with restrictive permissions
- `copy` avoids terminal output
- clipboard warning and TTL-based best-effort clearing

## Key Threats And Residual Risk

| Threat | Current Posture |
| --- | --- |
| Copied encrypted vault file | Mitigated by scrypt and AES-GCM, but weak passwords remain risky |
| Copied plaintext export | Not mitigated after export; rotate exposed secrets |
| Stolen compact token | Limited by expiry, max uses, scope, and revocation |
| Stolen `vault-token.key` | Serious; regenerate token key and treat tokens as compromised |
| Stolen recovery key and recovery file | Critical for that recovery snapshot; replace recovery setup and rotate sensitive secrets |
| Malicious modified executable | Out of scope once the user runs it with credentials |
| Same-user malware | Out of scope |
| Process memory inspection | Mostly out of scope; core dump disabling is best-effort only |
| Terminal capture | Out of scope once plaintext is printed |
| Clipboard capture | Partially mitigated by TTL clearing, but not prevented |
| Runtime file tampering | Partially mitigated by authenticated encryption and checksums |
| Supply-chain compromise | Partially mitigated by CI, checksums, and GitHub artifact attestations; still not a full external audit or platform signing process |

## Operational Guidance

- Use a strong, unique master password.
- Keep runtime files out of Git and cloud-shared folders unless you understand the risk.
- Prefer `copy` over `get` when terminal exposure matters.
- Prefer `export --output <file>` over plain terminal export when an export artifact is needed.
- Treat export files as plaintext secrets.
- Disable audit logging with `"audit_log": false` if command metadata is too sensitive for your environment.
- Run `vault doctor` periodically in active vault directories.
- Run `vault inspect-runtime` when runtime-home confusion, legacy files, or `MYMINIVAULT_HOME` overrides are suspected.
- Rotate tokens quickly if a compact token may have been exposed.
- Regenerate the token master key if `vault-token.key` may have been exposed.
- Do not describe the tool as production secure without external review.

## Incident Response

If `vault.db` or a backup is copied:

- assume offline password guessing is possible
- change weak or reused master passwords
- rotate high-value secrets if exposure risk is meaningful

If the master password is exposed:

- change the master password
- rotate stored secrets as appropriate
- treat old backups as still protected by the old risk profile

If `vault-token.key` is exposed:

- run `regenerate-token-key`
- treat existing compact tokens and shared token vault state as compromised
- recreate needed tokens

If a compact token is exposed:

- revoke the token when possible
- rotate affected secrets if the token allowed reads and may have been used
- do not rely only on expiry unless the risk is acceptable

If the recovery key is exposed:

- replace recovery setup
- rotate sensitive secrets if the recovery file may also have been exposed
- review backups for older recovery snapshots

If both the recovery key and `vault.db.recovery` are exposed:

- treat the recovery snapshot as compromised
- assume an attacker can recover the secrets present in that snapshot
- replace recovery setup after regaining control
- rotate secrets that may have existed in the exposed snapshot

If exported plaintext or clipboard contents are exposed:

- rotate affected secrets
- delete plaintext export artifacts where possible
- review shell history, logs, and shared files

## Future Security Work

Recommended next steps:

- keep coverage reporting focused on security-sensitive behavior as the code evolves
- keep expanding `vault doctor` and `vault inspect-runtime` checks as runtime behavior grows
- keep hardening token sync if it moves beyond local-file workflows
- decide whether revision counters, merge-base metadata, or fuller delete tombstones are needed
- consider log rotation or retention controls if logs become more detailed
- consider macOS Keychain or another OS key store for protecting `vault-token.key`
- consider signed tags, signed release checksums, SBOMs, or platform-specific package signing later in the release process
- avoid claiming production security without an external audit
