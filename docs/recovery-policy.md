# Recovery Policy

This document describes the current recovery behavior and the operational policy around `vault.db.recovery`.

## Summary

Recovery is snapshot-based.

`vault recover` does not reconstruct the latest possible vault state from every runtime file. It decrypts the recovery-encrypted snapshot stored in `vault.db.recovery`, then saves that recovered snapshot with a new master password.

## Runtime Files

Recovery files are resolved inside the active runtime home. By default this is `~/.myminivault/`; set `MYMINIVAULT_HOME=/path/to/dir` to use an isolated runtime home.

Recovery uses:

- `vault.db`: main master-password encrypted vault
- `vault.db.recovery`: recovery-key encrypted vault snapshot
- `vault.db.bak`: previous main vault version used only when the primary main vault is missing

`vault.db.recovery` is a sensitive secret-bearing file. Anyone with both the recovery key and `vault.db.recovery` can attempt recovery.

Treat `vault.db.recovery` plus the matching recovery key as equivalent to the master password for that recovery snapshot. The recovery key alone is not enough, and the recovery file alone is not enough, but together they can recover the secrets stored in that snapshot. See [Security Model](security.md#recovery-flow) for the threat-model summary and incident response guidance.

## Snapshot Behavior

`vault.db.recovery` is updated only when the application can save a vault while the recovery key is available in memory.

That currently happens when:

- `setup-recovery` creates the first recovery key and saves the vault
- `recover` decrypts the recovery snapshot, updates recovery metadata, and saves the vault with the new master password
- a command saves the vault while the current process has the recovery key set

Most normal master-password commands do not ask for the recovery key. They can update `vault.db` without updating `vault.db.recovery`.

## Divergence Policy

If `vault.db` and `vault.db.recovery` diverge, recovery follows `vault.db.recovery`.

This means:

- keys added after the last recovery snapshot may be absent after recovery
- keys deleted after the last recovery snapshot may reappear after recovery
- token metadata and recovery use counters follow the recovered snapshot
- recovery should be tested after setup and after important vault changes if it is part of the user's operational plan

This is intentional for now because the application does not store the recovery key or ask for it on every save.

## Verifier Policy

The recovery verifier is an embedded SHA-256 hash of the recovery key inside the encrypted vault payload.

Current role:

- verify that the provided recovery key belongs to the decrypted recovery snapshot
- avoid accepting a decrypted payload that does not contain matching recovery metadata

Current limitations:

- the verifier is not a separate password-authenticated key exchange
- the verifier strength depends on the recovery key entropy
- the recovery key must remain secret

The current recovery key is generated from 32 secure random bytes and encoded as grouped base32, so verifier hardening is not urgent for local personal use. A future security-focused release may replace or supplement this verifier with versioned metadata if the threat model becomes stricter.

## Rotation And Replacement

To rotate recovery today:

1. Run `vault setup-recovery`.
2. Confirm replacement when prompted.
3. Save the new recovery key securely.
4. Run `vault test-recovery` with the new key.
5. Consider deleting older backups that contain older recovery snapshots if those older recovery keys should no longer work.

Important caveat: older backup files may still contain snapshots encrypted for older recovery keys. Rotating the current recovery setup does not rewrite historical backup files.

After rotating recovery, review old backups and exported copies of `vault.db.recovery`. Keeping old recovery snapshots is sometimes useful for disaster recovery, but each retained snapshot extends the period during which an old recovery key may matter.

## Deferred Decisions

Future improvements to consider:

- a dedicated `rotate-recovery` command with clearer output
- a `refresh-recovery` command that asks for the recovery key and rewrites `vault.db.recovery` without changing the master password
- a `vault doctor` warning when recovery is configured but the recovery snapshot appears older than the main vault
- versioned recovery metadata for future verifier migrations
- clearer backup cleanup guidance after recovery rotation
