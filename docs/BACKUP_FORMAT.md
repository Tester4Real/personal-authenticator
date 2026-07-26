# Portable backup format

## Scope

This document specifies the implemented Personal Authenticator portable backup envelope written by `PasswordBackupService`.

Portable backups are independent of Windows DPAPI and are intended to survive reinstallation or movement to another Windows user when the password is known. They are not the same format as `%LOCALAPPDATA%\PersonalAuthenticator\vault.pav`.

- File extension: `.pab` by UI convention
- Magic: ASCII `PABKUP01`
- Current envelope version: `1`
- Current encrypted payload version: `1`

## Byte order and integer types

All multi-byte integers in the binary envelope are little-endian:

- `formatVersion` is an unsigned 16-bit integer.
- `iterations` and `ciphertextLength` are signed 32-bit integers whose accepted values are constrained during import.

The fixed binary prefix is 24 bytes. Version 1 then carries a fixed 16-byte salt and 12-byte nonce, producing a 52-byte authenticated header.

## Version-1 binary layout

| Offset (hex) | Offset (decimal) | Size | Type | Version-1 value or meaning |
| ---: | ---: | ---: | --- | --- |
| `0x00` | 0 | 8 | bytes | ASCII magic `PABKUP01` |
| `0x08` | 8 | 2 | `UInt16 LE` | Format version: `1` |
| `0x0A` | 10 | 1 | byte | KDF identifier: `1` = PBKDF2-HMAC-SHA-512 |
| `0x0B` | 11 | 1 | byte | Reserved; exporter writes `0` |
| `0x0C` | 12 | 4 | `Int32 LE` | PBKDF2 iteration count; exporter writes `600000` |
| `0x10` | 16 | 1 | byte | Salt length: `16` |
| `0x11` | 17 | 1 | byte | Nonce length: `12` |
| `0x12` | 18 | 1 | byte | Authentication-tag length: `16` |
| `0x13` | 19 | 1 | byte | Reserved; exporter writes `0` |
| `0x14` | 20 | 4 | `Int32 LE` | Ciphertext length `N` |
| `0x18` | 24 | 16 | bytes | Random PBKDF2 salt |
| `0x28` | 40 | 12 | bytes | Random AES-GCM nonce |
| `0x34` | 52 | `N` | bytes | AES-GCM ciphertext |
| `0x34 + N` | `52 + N` | 16 | bytes | AES-GCM authentication tag |

Total file length is:

```text
52-byte authenticated header + N-byte ciphertext + 16-byte tag
= 68 + N bytes
```

The importer currently requires the salt, nonce, and tag lengths to equal 16, 12, and 16 respectively. It does not currently reject non-zero reserved bytes, but those bytes are included in authenticated additional data and therefore cannot be modified without invalidating the tag.

## Password encoding and key derivation

Input password rules:

- Minimum length: 12 .NET `char` values (UTF-16 code units)
- Maximum length: 1,024 .NET `char` values
- No composition rule is applied; users must choose a long, unique password

Derivation:

```text
passwordBytes = UTF8(password)
key = PBKDF2-HMAC-SHA-512(
    passwordBytes,
    salt,
    iterations,
    outputLength = 32 bytes)
```

The version-1 exporter always writes 600,000 iterations. The importer accepts an authenticated-header iteration value from 100,000 through 5,000,000 inclusive. Values outside that range are rejected before derivation.

The password is never used directly as an encryption key and is not stored in the envelope. The service clears its mutable password copies and derived key best effort. The original UI string and runtime/OS copies cannot be guaranteed to be cleared.

## Encryption and authentication

Version 1 uses AES-256-GCM:

- Key: 32 bytes from PBKDF2
- Nonce: 12 random bytes from `RandomNumberGenerator.GetBytes`
- Tag: 16 bytes
- Plaintext: compact UTF-8 JSON payload
- Authenticated additional data: every byte of the 52-byte header, offsets `0` through `51`

Conceptually:

```text
(ciphertext, tag) = AES-256-GCM.Encrypt(
    key,
    nonce,
    plaintextJson,
    associatedData = header[0..52])
```

This authenticates the magic, version, KDF identifier, reserved fields, iteration count, component lengths, ciphertext length, salt, and nonce. The tag also authenticates the encrypted payload. Ciphertext length equals plaintext length for GCM.

There is no unauthenticated account metadata outside the ciphertext.

## Encrypted JSON payload

After successful AES-GCM authentication, the plaintext is compact UTF-8 JSON with camel-case property names:

```json
{
  "formatVersion": 1,
  "accounts": [
    {
      "id": "00000000-0000-0000-0000-000000000001",
      "issuer": "Example",
      "accountName": "user@example.invalid",
      "secretBytes": "<base64-encoded secret bytes>",
      "algorithm": 0,
      "digits": 6,
      "period": 30,
      "favourite": false,
      "sortOrder": 0,
      "createdAtUtc": "2026-01-01T00:00:00+00:00",
      "updatedAtUtc": "2026-01-01T00:00:00+00:00"
    }
  ]
}
```

The shown identifier and metadata are illustrative; the secret placeholder is not a usable credential.

Algorithm values follow the current enum serialization:

| JSON number | Algorithm |
| ---: | --- |
| `0` | SHA-1 |
| `1` | SHA-256 |
| `2` | SHA-512 |

`secretBytes` is standard JSON Base64 representation of the raw secret byte array. This JSON must exist only in process memory before encryption or after authenticated decryption. It must never be written as plaintext.

## Export procedure

1. Validate password length.
2. If the path exists, require the caller to have explicitly set `overwriteExisting`; otherwise reject the export without changing the file.
3. Serialize the version-1 payload to a byte array.
4. Generate a new 16-byte salt and 12-byte nonce with the OS CSPRNG.
5. Encode the password as UTF-8, then on a thread-pool worker check cancellation and derive a 32-byte key with 600,000 PBKDF2-HMAC-SHA-512 iterations.
6. Check cancellation, construct the 52-byte header, and encrypt the JSON with AES-256-GCM using the complete header as additional authenticated data.
7. Check cancellation, then concatenate header, ciphertext, and tag.
8. Write through a same-directory temporary file and flush managed and OS buffers.
9. Move the temporary file when no destination exists, or atomically replace the existing destination when overwrite permission was supplied. Portable export does not retain a `.previous` copy.
10. Clear owned plaintext, password, key, ciphertext, tag, salt, nonce, and envelope buffers best effort.

The UI uses the Windows save picker for overwrite confirmation and passes
explicit permission to the service. It does not pre-delete the selected file.
Cancellation or a failure before atomic replacement preserves the existing
backup. A race that creates a destination after an unconfirmed export begins is
detected at the atomic-file boundary and reported as an existing-file error.

## Import validation

Import applies these checks in order:

1. The path must exist.
2. File length must be at least the 24-byte fixed prefix and no more than 64 MiB.
3. The entire file is read into memory.
4. Magic must equal `PABKUP01`.
5. Format version must equal `1`; other versions are rejected.
6. KDF identifier must equal `1`.
7. Iterations must be between 100,000 and 5,000,000.
8. Salt, nonce, and tag lengths must equal 16, 12, and 16.
9. Ciphertext length must not be negative.
10. A 64-bit calculation computes the 52-byte header and expected total length without overflowing a 32-bit declaration.
11. Expected total length must equal the file length exactly; trailing bytes and truncation are rejected.
12. The key is derived from the supplied password and stored salt/iterations.
13. AES-GCM verifies the complete header and ciphertext before plaintext is accepted.
14. JSON is parsed off the UI thread and must remain within a maximum nesting depth of 16.
15. Payload version must equal `1`, and the accounts collection must exist.
16. Each account must have an ID, non-empty issuer/account name, and secret bytes; domain construction then applies display, secret-length, digit, and period constraints.

Wrong passwords and authenticated modifications to the header, ciphertext, or tag fail at AES-GCM and return the same safe message:

```text
The backup password is incorrect or the backup was modified.
```

This intentionally avoids providing an oracle that distinguishes those two cases. Structurally malformed envelopes return specific non-sensitive format errors.

All imported account objects are disposed if conversion fails partway. The caller disposes an imported collection if the subsequent vault import fails.

## Duplicate behavior after decryption

Backup decryption does not itself merge records. `VaultService.ImportAsync` applies:

- **Merge (`Merge`):** retain current accounts and skip each imported likely match.
- **Merge and replace matches (`MergeReplaceDuplicates`):** retain unmatched current accounts and replace matching records at their existing positions.
- **Merge and keep duplicates (`MergeAddDuplicates`):** retain current accounts and append every imported record, including likely matches.
- **Replace current vault exactly (`Replace`):** stage an empty vault and append every imported record without duplicate filtering, preserving intentional duplicates in the backup.

The likely-duplicate comparison includes normalized issuer, normalized account
name, algorithm, digits, period, and secret bytes. The UI selection applies to
the complete import; version 1 has no per-account conflict report. All modes use
the vault service's clone-and-commit transaction, so a save failure retains the
previous live set and leaves the imported collection owned by the caller.

## Failure and resource behavior

- File reads and writes accept cancellation tokens.
- KDF, AES-GCM, and JSON-deserialization CPU work runs through `Task.Run`, away from the WinUI thread.
- Cancellation is checked before/after PBKDF2 and around AES/JSON work. The PBKDF2 call itself is synchronous and cannot be interrupted mid-derivation; the current UI has no progress/cancel control.
- The importer reads the complete envelope and allocates plaintext equal to the declared ciphertext length only after exact length validation.
- The 64 MiB limit bounds primary file and plaintext allocations, although concurrent working buffers can consume several times the file size.
- Atomic export uses ciphertext-only temporary data.
- Serialization populates its DTO collection inside a `try/finally`; secret copies already created are cleared even if account enumeration or JSON serialization fails. Deserialization likewise clears DTO secret arrays and disposes partially constructed domain accounts on failure.
- Portable backup destination ACLs are inherited from the user-selected directory; the application does not apply the local vault's custom ACL.

## Versioning and migration strategy

Current behavior is deliberately conservative: any envelope version other than `1`, any KDF identifier other than `1`, or any payload version other than `1` is rejected. There is no migration implementation yet.

A future reader should:

1. Dispatch on the envelope version before interpreting version-specific fields.
2. Preserve the version-1 parser unchanged for backward compatibility.
3. Define new KDF or cipher identifiers explicitly; never reinterpret identifier `1`.
4. Authenticate every decryption-affecting field.
5. Validate resource bounds before allocating or deriving a key.
6. Authenticate/decrypt fully before parsing or migrating payload data.
7. Migrate into current domain objects in memory, validate, then save through the DPAPI vault.
8. Export only the newest format while continuing to import supported older formats.
9. Never overwrite the source backup during migration; create a fresh backup with a fresh salt and nonce.
10. Add golden-file, wrong-password, truncation, header-tamper, ciphertext-tamper, tag-tamper, and cross-version tests.

If a memory-hard KDF is added later, it requires a new KDF identifier and explicit memory/parallelism fields in a new envelope version. Changing the meaning of the existing iteration field would break compatibility and must not be done.

## Test coverage

The currently observed tests cover:

- Export/import round trip
- No known plaintext account metadata or secret bytes in the exported envelope
- Wrong password
- Modified ciphertext
- Modified authentication tag
- Modified authenticated header
- Truncation
- Unsupported format version
- Different salt and nonce on repeated exports
- Existing-file rejection without overwrite permission
- Atomic confirmed overwrite without pre-delete
- Cancellation preserving an existing destination
- Oversized declared ciphertext length rejection
- All four whole-import duplicate policies and transactional save-failure behavior

Before freezing version 1 for production, add stable golden test vectors generated from fixed test-only inputs and validate cross-machine restore from a clean Windows installation.
