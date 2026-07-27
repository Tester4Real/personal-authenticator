# Recovery-A / Recovery-B format

## Purpose

Recovery bundles are optional, password-encrypted snapshots of the complete Windows v2 vault. They are independent of the local DPAPI root key and independent of the older portable `.pab` backup format.

The application alternates:

- `PersonalAuthenticator-Recovery-A.par`
- `PersonalAuthenticator-Recovery-B.par`

It never considers a newly written slot valid until a complete second-pass decrypt and record verification succeeds.

## Cryptographic envelope

All multibyte integers are little-endian.

| Field | Size | Validation |
| --- | ---: | --- |
| Magic `PAVREC03` | 8 bytes | Exact match |
| Format version | 2 bytes | Currently `1` |
| Slot | 1 byte | `0` for A, `1` for B |
| Reserved | 1 byte | Must be zero |
| Argon2id memory | 4 bytes | 8–256 MiB; production 64 MiB |
| Argon2id iterations | 4 bytes | 1–10; production 3 |
| Argon2id parallelism | 4 bytes | 1–16; production 2 |
| Salt | 16 bytes | Random per bundle |
| AES-GCM nonce | 12 bytes | Random per bundle |
| Ciphertext length | 4 bytes | Positive, exact file-length match, bounded to 128 MiB |
| Ciphertext | variable | Complete binary vault payload |
| AES-GCM tag | 16 bytes | Authentication required before parsing |

The 56-byte fixed header is AES-GCM associated data. The derived key is 256 bits. Passwords must contain 12–1024 characters. Password bytes, derived keys, decrypted payloads, and temporary serialization buffers are cleared on a best-effort basis.

## Encrypted payload

The binary payload records the format version, creation time, monotonic vault change sequence, and bounded collections of every account, active/candidate/retired secret version, and encrypted history relationship.

Lengths and counts are checked before allocation. UTF-8 decoding is strict. Duplicate identifiers, missing relationships, invalid active-secret references, malformed fields, trailing bytes, and oversized collections reject the complete bundle.

## Rotation and interruption

The inactive slot is written to a unique same-directory temporary file, flushed to disk, decrypted, and fully checked. It is then atomically moved or replaced into the inactive slot and checked again. Only after that check does the DPAPI-protected health record advance.

An interruption while writing A leaves B unchanged. An interruption while writing B leaves A unchanged. A replaced generation is retained with a unique `.previous-*` filename rather than pre-deleted.

## Health and restore

Recovery health records the last fully verified slot, absolute file path, UTC verification time, and included vault sequence. The UI reports the exact number of later committed changes and warns at 20 changes, 30 days, a missing bundle, corrupt health state, or local sequence rollback.

Restore decrypts and validates the selected bundle before creating a unique replacement SQLite database and unique DPAPI-protected root-key file. It adds encrypted recovery-history records, reopens the replacement, verifies SQLite integrity and every authenticated record, and compares all fields. Only then is the active selector atomically updated. The previous selector is retained by the atomic pointer store. The old database and root-key file are never overwritten or automatically deleted.
