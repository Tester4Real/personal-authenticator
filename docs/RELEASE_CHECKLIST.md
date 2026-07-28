# Windows v2 manual release checklist

Use a clean Windows 10 2004+ or Windows 11 VM for final qualification.

## Build provenance

- [ ] Confirm the approved branch is clean.
- [ ] Run Release build, all tests, formatting, vulnerability audit, and sensitive-data scans.
- [ ] Review third-party notices and code-sign outside the repository.

## Local vault and migration

- [ ] Test Upgrade, Continue v1, Cancel, interruption, verification, and rollback with synthetic v1 fixtures.
- [ ] Confirm `vault.pav` remains byte-for-byte unchanged until activation.
- [ ] Test clean local-only installation while monitoring that no HTTP client or network endpoint is created.
- [ ] Test archive, restore, duplicate import, candidate activation, history, and sensitive URI/QR reveal.
- [ ] Corrupt the database, pointer, DPAPI key, and Windows profile independently.

## Recovery and lifecycle

- [ ] Interrupt Recovery-A and Recovery-B at every checkpoint.
- [ ] Restore on a clean Windows profile without the original GitHub account.
- [ ] Rename and revoke a second Windows device; preserve history and reject new sequences.
- [ ] Interrupt every key-rotation checkpoint; confirm the previous epoch remains active.
- [ ] Test purge confirmation, reauthentication, conflict blocking, clean epoch, and warnings.

## Synchronisation

- [ ] Synchronise two clean Windows installations after offline edits and conflicts.
- [ ] Test token loss, repository deletion/rename/transfer/recreation/public visibility, rollback, and corruption.
- [ ] Exercise Remote Repair and verified replacement without deleting the old repository.
- [ ] Run the opt-in live test only with a temporary private repository and environment token, then delete both.

## Deployment

- [ ] Test Narrator, keyboard, high contrast, scaling, clipboard clearing, and sensitive-screen behavior.
- [ ] Smoke-test the self-contained x64 publish on a clean machine.
- [ ] Record the signed artifact hash and archive the qualification report.
