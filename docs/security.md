# myminivault Security Model

`myminivault` is an experimental personal project. It has not been independently audited and should not be treated as a production password manager.

This document explains the intended security boundaries, sensitive assets, assumptions, and known limitations so future development can be explicit instead of relying on "it is encrypted" as a complete answer.

## Goals

`myminivault` aims to:

- keep vault values encrypted at rest in local runtime files
- derive encryption keys from a master password using scrypt
- authenticate encrypted payloads with AES-GCM
- support a recovery workflow without storing the master password
- support temporary token access with key-pattern and permission limits
- reduce local write races with an inter-process lock file
- keep runtime vault files out of Git by default

## Non-Goals

`myminivault` does not currently aim to provide:

- enterprise password manager guarantees
- audited cryptographic design
- protection from malware or a compromised local user account
- remote sync security
- multi-user access control
- hardware-backed key storage
- memory-hardening against local process inspection
- protection from secrets copied into shell history, terminal scrollback, logs, or clipboard tools

## Sensitive Assets

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
- `vault.log` if key names or token IDs reveal context
- exported shell snippets

## Attacker Assumptions

The current model mostly considers an attacker who can read or copy files from the working directory after commands have run.

The project does not currently defend well against:

- an attacker who can run code as the same OS user
- an attacker who can observe terminal input/output
- an attacker who can read shell history
- an attacker who can inspect process memory
- an attacker who can replace the binary or source code
- an attacker who can modify runtime files between trusted command runs

## Runtime Files

| File | Sensitivity | Notes |
| --- | --- | --- |
| `vault.db` | High | Main encrypted vault |
| `vault.db.bak` | High | Previous encrypted vault version |
| `vault.db.recovery` | High | Recovery-encrypted vault snapshot |
| `vault-token.key` | Critical | Local token master key; compromise invalidates token security assumptions |
| `shared-token-vault.json` | High | Encrypted shared token vault |
| `vault-tokens.json` | Medium | Token registry metadata |
| `vault.log` | Medium | May reveal token IDs, actions, or key names |
| `vault-config.json` | Low/Medium | Can affect scrypt and backup behavior |
| `.myminivault.lock` | Low | Coordination file, not a security boundary |

Runtime files should stay out of Git and should normally be readable only by the local user.

## File Permissions

Current code writes some sensitive files with restrictive permissions, but a complete file-permission audit is still a backlog item.

Expected direction:

- `vault.db`, `.bak`, `.recovery`, token key, shared token vault, registry, and logs should not be world-readable
- backup files should receive the same care as `vault.db`
- `vault-token.key` should be treated as especially sensitive
- future `vault doctor` checks should warn about unsafe permissions

## Master Password

The master password is used to derive an encryption key through scrypt. It is not intentionally stored.

Risks:

- weak master passwords are still weak
- terminal input may be exposed by a compromised terminal or OS user
- process memory is not hardened
- shell scripts that pipe passwords can leak through history, process inspection, or logs

## Recovery Key

Recovery uses a high-entropy recovery key and a recovery-encrypted snapshot stored in `vault.db.recovery`.

Important limitations:

- recovery can recover only the snapshot stored in `vault.db.recovery`
- if the main vault and recovery snapshot diverge, recovery follows the recovery snapshot
- anyone with the recovery key and recovery file can attempt recovery
- losing the recovery key means recovery is not available
- replacing or rotating recovery should be documented carefully before relying on it operationally

## Token System

Tokens provide temporary access with:

- key-pattern restrictions
- read/write permissions
- expiration time
- max-use limits
- HMAC signatures
- encrypted shared token vault storage

Important limitations:

- a compact token string is a bearer credential while valid
- a stolen token can be used until it expires, is revoked, or reaches max uses
- `vault-token.key` is critical for token security
- token writes go through `shared-token-vault.json`
- conflict handling is currently last-writer-wins at the vault-key level

## Main And Shared Vault Boundary

`vault.db` is the main password-protected vault. `shared-token-vault.json` is the encrypted vault used by token commands.

Current behavior:

- token writes are staged in `shared-token-vault.json`
- master-password commands import token-side changes before running
- master mutations mirror the main vault back to the shared token vault after saving when token runtime exists
- deletes remain authoritative because mirroring replaces shared vault data with main vault data

This is a powerful but complex model. Future work should decide whether automatic import remains the right default or whether token writes should require explicit `sync-tokens`.

## Backups And Export

Backups are encrypted but still sensitive because they may contain old secrets.

Export output is intentionally shell-friendly, but exported values are plaintext once printed. Be careful with:

- terminal scrollback
- shell history
- copied output
- logs
- redirected files

## Logging

`vault.log` can reveal operational metadata such as token IDs, actions, and key names. Key names may be sensitive even when values are encrypted.

Future review should decide:

- whether token IDs should be truncated further
- whether key names should be logged
- whether logs should be optional, rotated, or permission-checked

## Locking

`.myminivault.lock` serializes local CLI processes and helps avoid write races. It is not an access-control mechanism and should not be treated as a security boundary.

## If A Runtime File Is Compromised

Suggested response:

- If `vault.db` or a backup is copied, rotate secrets if the master password may be weak or exposed.
- If the master password is exposed, change the master password and rotate secrets as appropriate.
- If `vault-token.key` is exposed, run `regenerate-token-key` and treat existing tokens as compromised.
- If a compact token is exposed, revoke the token or wait for expiration only if the risk is acceptable.
- If the recovery key is exposed, replace recovery setup and rotate secrets as appropriate.
- If exported plaintext is exposed, rotate affected secrets.

## Future Security Work

Planned or recommended:

- add `vault doctor` checks for runtime file permissions and stale locks
- add more unit tests around tampered ciphertext, checksum failure, and token forgery
- decide token sync conflict policy
- decide whether delete tombstones or per-key revisions are needed
- document recovery key rotation
- review logging behavior
- avoid claiming production security without an external audit
