# Windows security lifecycle

## Devices and revocation

The Devices & keys screen derives first-seen, last-seen, and highest sequence data from the authenticated immutable operation log. The current Windows device is identified by its DPAPI-protected device ID. Friendly names and revocation cut-offs are stored in separate DPAPI-protected security state.

Revocation records the highest sequence already accepted from a device. Historical operations at or below that cut-off remain authoritative; a new operation above it is rejected before insertion or materialized-state rebuild. Revoking the current device is blocked.

Revocation cannot erase secrets already copied to another machine. Revoke that machine's fine-grained GitHub token in GitHub settings, remove its local vault where possible, and reset important websites' 2FA secrets.

## Key epochs

Epoch rotation persists `PendingEpoch`, verifies the active database, creates a separate database and DPAPI root-key envelope, restores the complete state and sync history, reopens and compares sensitive records, creates and verifies Recovery-A/B, and only then atomically activates the new pointer. Every earlier failure leaves the previous database, key, and pointer active. Previous encrypted files remain for rollback.

If GitHub sync is configured, uploads are paused until a replacement remote generation is verified.

## Permanent purge

Normal Remove remains Archive. Advanced purge requires an archived account, fresh Windows user verification, exact typed confirmation `PURGE`, no related unresolved conflict, and a recovery password.

`PurgePending` is persisted before work begins. A separate database/key epoch is built without the account, its secret versions, history, or old operation history. Recovery-A/B is recreated and verified before activation.

Purge cannot guarantee physical erasure. Old devices, Git history, disabled repositories, old recovery files, filesystem snapshots, and external backups may retain encrypted copies. Replace the GitHub remote generation, retire old recovery media where appropriate, and reset or revoke the website's 2FA secret.

## Current boundary

Device friendly names and revocation cut-offs are local protected policy. Each Windows installation must receive the revocation policy through an administrator-controlled recovery/configuration workflow; Phase 6 does not add a cross-device administrative signing protocol.
