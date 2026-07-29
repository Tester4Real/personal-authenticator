# GitHub sync protocol v1

This document freezes the byte-level contract shared by Personal Authenticator
clients. GitHub is only a transport for the immutable operation log. The local
encrypted vault remains authoritative for local commits, and network failure
must never roll back local state.

The canonical conformance data is under `protocol-fixtures/v1/`. It is synthetic
test data, contains no production credential or OTP seed, and is consumed
byte-for-byte by the Windows test suite. A second implementation is not
interoperable until it consumes the same files without rewriting them.

## Primitive encodings

- All binary integers are little-endian and signed unless their type is
  explicitly unsigned.
- A GUID is the 16 bytes returned by .NET `Guid.ToByteArray()` or
  `Guid.TryWriteBytes()`. Java/Kotlin UUID network byte order is not compatible.
- GUID ordering is .NET `Guid.CompareTo`, not lexicographic comparison of Java
  UUID bytes or the canonical GUID string.
- A timestamp is a signed 64-bit .NET UTC tick count: 100-nanosecond intervals
  since `0001-01-01T00:00:00Z`. It is not Unix time.
- Binary strings and blobs are a signed 32-bit byte length followed by exactly
  that many bytes. Text is strict UTF-8 without a terminator.
- Boolean values are one byte and only `0x00` and `0x01` are valid.

The fixture manifest pins GUID bytes and ordering, tick values, and all hashes.

## Repository layout

The configured private repository uses a dedicated branch and path:

```text
<path>/descriptor.json
<path>/objects/<first-two-lowercase-N-format-id-chars>/<operation-id-N>.pao
<path>/snapshots/<random-id>.pas
<path>/heads/<public-device-id>.pah
```

Paths and filenames contain no issuer, account name, email address, device
display name, setup URI, secret, or OTP. Operations are authoritative.
Snapshots and heads are disposable indexes and cannot replace operation-log
rebuild.

## Descriptor

`descriptor.json` is UTF-8 JSON serialized with these PascalCase properties in
this order:

1. `ProtocolVersion` — integer, currently `1`.
2. `RequiredFeatures` — array, currently
   `["immutable-operations-v1"]`.
3. `RepositoryId` — the numeric GitHub repository ID as a signed 64-bit value.
4. `VaultId` — canonical GUID text.
5. `RemoteGeneration` — canonical GUID text.
6. `Salt` — Base64, exactly 16 decoded bytes.
7. `Nonce` — Base64, exactly 12 decoded bytes.
8. `VerifierCiphertext` — Base64, exactly 32 decoded bytes.
9. `VerifierTag` — Base64, exactly 16 decoded bytes.

Unknown JSON properties are optional and ignored. An unknown entry in
`RequiredFeatures`, an unknown protocol version, or an unknown required binary
flag puts the client into read-only compatibility mode and blocks uploads.

The shared 32-byte sync key is:

```text
Argon2id(
  password = strict UTF-8 existing sync password,
  salt = descriptor Salt,
  memory = 65536 KiB,
  iterations = 3,
  parallelism = 2,
  output = 32 bytes
)
```

Existing descriptors accept passwords containing 4 through 1,024 UTF-16 code
units. Android v1 only opens an existing descriptor and must never create,
replace, or reset a missing descriptor.

The 32-byte verifier plaintext is:

```text
SHA-256(
  RepositoryId:int64-le ||
  VaultId:dotnet-guid-bytes ||
  RemoteGeneration:dotnet-guid-bytes
)
```

It is encrypted with AES-256-GCM using the derived sync key, descriptor `Nonce`,
no AAD, and a 16-byte tag. Authentication failure is a wrong password or a
modified descriptor; it must not mutate local or remote state.

## Immutable object envelope

Every `.pao` file is:

| Offset | Size | Type | Value |
| ---: | ---: | --- | --- |
| 0 | 8 | ASCII | `PAVGHO01` |
| 8 | 2 | uint16-le | envelope version `1` |
| 10 | 2 | uint16-le | required flags, currently `0` |
| 12 | 8 | int64-le | numeric repository ID |
| 20 | 16 | .NET GUID bytes | vault ID |
| 36 | 16 | .NET GUID bytes | remote generation |
| 52 | 16 | .NET GUID bytes | object/operation ID |
| 68 | 12 | bytes | deterministic nonce |
| 80 | 4 | int32-le | plaintext byte length |
| 84 | length | bytes | AES-GCM ciphertext |
| 84 + length | 16 | bytes | AES-GCM tag |

The complete 84-byte header is AES-GCM AAD. The nonce is the first 12 bytes of:

```text
HMAC-SHA-256(
  key = sync key,
  data =
    RepositoryId:int64-le ||
    VaultId:dotnet-guid-bytes ||
    RemoteGeneration:dotnet-guid-bytes ||
    ObjectId:dotnet-guid-bytes
)
```

The plaintext length must be between 64 and 131,072 bytes and the file length
must be exactly `84 + plaintext length + 16`. The decrypted operation ID must
equal the header object ID. A repeated object ID with different bytes is a hard
collision. Immutable object bytes are stable and may be compared after an
ambiguous upload response.

## Operation binary format

An operation is serialized in this exact sequence:

| Field | Encoding |
| --- | --- |
| format version | int32-le, currently `1` |
| operation ID | .NET GUID bytes |
| device ID | .NET GUID bytes |
| device sequence | int64-le, greater than zero |
| Lamport clock | int64-le, greater than zero |
| occurred at UTC | int64-le .NET ticks |
| account ID present | strict one-byte Boolean |
| account ID | .NET GUID bytes when present; all v1 operations require it |
| operation kind | int32-le |
| field key | length-prefixed strict UTF-8 |
| causal-parent count | int32-le, 0 through 64 |
| causal parents | .NET GUID bytes sorted by .NET `Guid.CompareTo` |
| payload flags | int32-le |
| payload fields | present fields in the order below |

Payload flag bits and field order are:

| Bit | Hex | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | `0x001` | text | length-prefixed UTF-8 |
| 1 | `0x002` | Boolean | strict one-byte Boolean |
| 2 | `0x004` | integer | int32-le |
| 3 | `0x008` | date | int64-le .NET UTC ticks |
| 4 | `0x010` | GUID | .NET GUID bytes |
| 5 | `0x020` | secondary GUID | .NET GUID bytes |
| 6 | `0x040` | account | length-prefixed account JSON |
| 7 | `0x080` | secret version | length-prefixed secret-version JSON |
| 8 | `0x100` | history entry | length-prefixed history JSON |
| 9 | `0x200` | conflict ID | .NET GUID bytes |
| 10 | `0x400` | conflict resolution | int32-le enum |

Any flag outside `0x7ff` is an unknown required feature. Text is limited to
16 KiB, account JSON to 16 KiB, secret-version JSON to 32 KiB, history JSON to
8 KiB, and the complete operation to 128 KiB. Trailing bytes are invalid.

Operation kinds are frozen as:

| Value | Kind | Required field key | Required payload |
| ---: | --- | --- | --- |
| 0 | `AccountAdded` | `account` | account and active secret version |
| 1 | `IssuerChanged` | `issuer` | nonblank text |
| 2 | `AccountNameChanged` | `account-name` | nonblank text |
| 3 | `FavouriteChanged` | `favourite` | Boolean |
| 4 | `SortOrderChanged` | `sort-order` | nonnegative integer |
| 5 | `ArchiveChanged` | `archive` | optional date; null means restore |
| 6 | `SecretAdded` | `secret-set` | secret version |
| 7 | `ActiveSecretChanged` | `active-secret` | nonempty GUID |
| 8 | `HistoryAdded` | `history:<history-id-N>` | history entry |
| 9 | `DuplicateDecision` | `duplicate-decision` | history entry |
| 10 | `Purged` | `archive` | none |
| 11 | `ConflictResolved` | `resolution:<conflict-id-N>` | conflict ID and resolution |

Android must parse and preserve all 12 kinds but must never originate kind 10.

## Nested record JSON

Nested records use UTF-8, camelCase property names, numeric enum values, compact
JSON, and schema version `1`. Property order is part of the v1 fixture bytes.

Account fields:

```text
schemaVersion, id, issuer, accountName, activeSecretVersionId, favourite,
sortOrder, createdAtUtc, updatedAtUtc, archivedAtUtc
```

Secret-version fields:

```text
schemaVersion, id, accountId, secretBytes, algorithm, digits, period,
provisioningUri, provisioningUriOrigin, state, createdAtUtc, retiredAtUtc
```

History fields:

```text
schemaVersion, id, accountId, action, occurredAtUtc, secretVersionId,
previousSecretVersionId, relatedAccountId, actorDeviceId
```

Secret bytes are Base64 in JSON. `DateTimeOffset` values are UTC ISO-8601 JSON
strings. Consumers must retain semantically unknown optional JSON properties
when a future required feature says preservation is necessary; v1 itself
ignores unknown optional properties.

## Semantic hashes, conflicts, and application order

`SyncSemanticHasher` hashes the operation kind, field key, and normalized
payload with SHA-256. Integers and ticks are little-endian. Nullable strings use
`-1` length; nullable GUIDs use a one-byte presence marker followed by .NET GUID
bytes. Account issuer/name are trimmed and uppercased invariantly. Secret bytes
are hashed directly. The checked-in manifest pins one semantic hash for every
operation kind.

A conflict ID is the first 16 bytes, interpreted as a .NET GUID, of:

```text
SHA-256(
  MinGuid(operationA, operationB):dotnet-guid-bytes ||
  MaxGuid(operationA, operationB):dotnet-guid-bytes
)
```

where `MinGuid` and `MaxGuid` use .NET `Guid.CompareTo`.

Apply only operations whose causal parents are already applied. Repeatedly sort
ready operations by:

```text
(Lamport clock, .NET device-GUID order, device sequence,
 .NET operation-GUID order)
```

Operation IDs and `(device ID, device sequence)` pairs are immutable identities.
Reusing either identity with different original serialized bytes is invalid.
Original operation bytes must be retained and never reserialized during an
upgrade.

## Transport validation and failure handling

Before upload, verify the authenticated user, private/writeable repository,
canonical owner/name, numeric repository ID, descriptor vault/generation, and
required features. Download the complete immutable operation set before
enabling upload for a newly connected device.

Git tree traversal is complete-before-apply. A truncated recursive tree falls
back to bounded non-recursive traversal with strict components, depth 64, at
most 10,000 trees and 100,000 blobs. Responses are capped at 32 MiB. Invalid,
partial, stale-generation, rollback, collision, and unsupported-feature states
block upload and do not roll back local accounts. Retry is bounded, jittered,
and honors `Retry-After`.

Tokens and sync keys are protected separately at rest. The sync password is
never stored. The repository never receives SQLite files, plaintext account
JSON, setup URIs, generated OTPs, tokens, recovery passwords, or plaintext
secrets outside authenticated object ciphertext.
