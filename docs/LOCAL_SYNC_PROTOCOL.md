# Windows v2 local sync protocol

Phase 4 adds an optional, encrypted local-folder backend for synchronising multiple Windows installations. It is local-first: every vault mutation commits to encrypted SQLite and its transactional outbox before any folder access. The application remains fully usable when sync is unconfigured, unavailable, or interrupted. This phase contains no GitHub client, HTTP client, token, or device-pairing protocol.

## Local operation log

SQLite schema version 4 stores an immutable operation log. Database triggers reject updates and deletes from `sync_operations`. Each encrypted operation contains:

- a random operation ID;
- a persistent, DPAPI-protected Windows device ID;
- a strictly increasing per-device sequence;
- a Lamport logical clock;
- zero or more causal parent operation IDs;
- an account ID, operation kind, and field address;
- a bounded, kind-specific encrypted payload.

Account creation, individual metadata fields, archive state, secret additions, active-secret choice, history, duplicate decisions, purge, and conflict resolution use distinct operation kinds/field addresses. Local operation payloads are encrypted with the v2 vault root key. The row retains only bounded routing metadata and a SHA-256 integrity hash outside that ciphertext.

An upgrade from a Phase 3 database creates schema 4 transactionally. Before the first sync/rebuild, existing materialised records are emitted as baseline operations without changing their IDs or values. This lets the operation log become authoritative without requiring current local-only users to configure sync.

## Transactional outbox

The materialised local change, immutable operation, causal-parent rows, device sequence, Lamport clock, and outbox row commit in one SQLite transaction. Folder upload runs afterward.

An outbox row is removed only after the immutable object has been atomically written, reopened, byte-compared, decrypted, authenticated, and checked against its operation ID. An interruption before acknowledgement leaves the operation queued. A retry of an already uploaded identical object is idempotent; an existing ID with different bytes is a hard collision.

## Folder format and encryption

The folder contains:

```text
PersonalAuthenticator.sync
objects\<first-two-operation-ID-hex>\<operation-ID>.pao
quarantine\<original-name>.<timestamp>.<random>.bad
```

`PersonalAuthenticator.sync` contains repository/generation IDs, bounded Argon2id parameters, a random salt, a nonce, and an AES-256-GCM password verifier. Production KDF parameters are 64 MiB, three iterations, and parallelism two. The derived 256-bit sync key and selected folder configuration are stored locally with DPAPI `CurrentUser`; the password is not stored.

Every `.pao` contains an authenticated fixed header (format version, repository ID, generation ID, operation ID, nonce, and ciphertext length), AES-256-GCM ciphertext, and tag. The associated data binds the header. Plaintext account fields, setup URIs, and secrets never enter the shared folder.

Readers validate paths and identifiers before opening, check file length before allocation, cap an operation at 128 KiB and an object collection at 100,000 files, reject trailing data/unknown required payload flags, and strictly validate the payload against its declared operation kind. Malformed, wrongly placed, unauthenticated, or cross-repository objects are moved to `quarantine` and are never applied. No compression is accepted, so compressed-data bombs are impossible in this format.

## Deterministic application

Operations are replayed in `(Lamport clock, device ID, device sequence, operation ID)` order. Causal parents must already be applied. An operation with a missing parent remains pending and is retried when more objects arrive.

Application is idempotent by operation ID and `(device ID, sequence)`. Re-receiving identical bytes is harmless. Reusing either identity for different content is rejected. Materialised SQLite records are rebuilt from the verified operation set when remote objects are applied; this makes operation order and snapshots independent. Snapshots remain disposable caches.

Automatic merges:

| Concurrent changes | Result |
| --- | --- |
| Different accounts | Both apply |
| Different metadata fields | Both apply |
| Identical account/secret import | Deterministic canonical IDs and aliases |
| Archive plus unrelated metadata | Both apply |

Conflicts:

| Concurrent changes | Result |
| --- | --- |
| Same metadata field, different values | Metadata conflict |
| Different secrets added to one account | Secret conflict; every version remains a candidate |
| Different active-secret choices | Active-secret conflict; every version remains |
| Restore versus purge | Conflict is recorded before purge can remove materialised data |
| Incompatible duplicate decisions | Duplicate-decision conflict |

Secret conflicts support **Keep version A**, **Keep version B**, **Keep both**, and **Separate accounts**. Metadata/restore/purge/duplicate conflicts support deterministic A/B selection. A resolution is itself an immutable causal operation and is committed/outboxed before its local materialised effect is applied.

## Recovery and failure behaviour

- Folder unavailability, cancellation, write interruption, disk-full, or denied access leaves the encrypted local vault usable and its outbox queued.
- Invalid remote objects are quarantined rather than uploaded or applied.
- Local vault integrity failures stop before reading/uploading the outbox.
- The folder is neither the primary database nor the only recovery path.
- Phase 3 Recovery-A/B bundles contain materialised vault records, not the Phase 4 operation log or folder configuration. Restoring one therefore starts a new local sync history after explicit reconfiguration; it must not be used to overwrite an existing shared generation without a future repository-replacement workflow.

## Phase 4 boundaries

The backend assumes a trusted filesystem transport for availability, but not for confidentiality or integrity. Anyone controlling that folder can delete, replay, reorder, withhold, or corrupt ciphertext. Authentication, collision checks, causal gaps, and deterministic replay prevent silent application of modified data, but Phase 4 does not yet implement remote rollback detection, snapshots, compaction, device revocation, key rotation, repository replacement, or effective purge across old devices/history. Those are later-phase concerns.

GitHub synchronisation is intentionally absent. No GitHub token is requested, stored, or used.
