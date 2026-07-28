# Optional GitHub sync protocol

GitHub sync is an optional transport for the Windows v2 immutable operation log. The encrypted SQLite vault remains the primary database, all mutations commit locally with their outbox entry before network activity, and the application remains fully usable without GitHub.

## Repository layout

The configured private repository uses a dedicated branch and path. Filenames are opaque and contain no issuer, account name, email address, device display name, setup URI, secret, or OTP:

```text
<path>/descriptor.json
<path>/objects/<id-prefix>/<operation-id>.pao
<path>/snapshots/<random-id>.pas
<path>/heads/<public-device-id>.pah
```

`descriptor.json` is non-secret bootstrap metadata: protocol and required features, numeric GitHub repository ID, vault ID, remote generation, Argon2id salt, and an encrypted password verifier. Operation, snapshot, and head objects use AES-256-GCM. Their authenticated header binds the repository ID, vault ID, generation, object ID, protocol version, and plaintext length. Immutable operation nonces are derived from the shared key and unique object identity, making a repeated upload byte-stable so collisions can be detected safely. Mutable heads receive a new object ID and nonce for every update.

The repository never receives `vault.pav`, SQLite files, plaintext account JSON, setup URIs, generated OTPs, tokens, recovery passwords, or plaintext secrets.

## Credentials and local configuration

The fine-grained token is entered only in the Windows UI and must grant Contents read/write access to the selected private repository. It is stored in a separate DPAPI `CurrentUser` protected file (`github-token.dat`). The DPAPI-protected `github-sync.dat` contains the repository identity, shared sync key, verified object hashes/sequences, health state, and settings. Tokens are absent from settings, vault records, recovery bundles, logs, diagnostics, tests, and source.

Recovery v2 includes only credential-free public sync metadata and the complete operation/sync state. Restoring it does not restore a token or shared key; reconnection is required. Legacy recovery bundles remain importable and the UI warns that they begin a new sync history.

## Synchronisation and failure handling

Manual sync, optional debounced change sync, and periodic background sync are serialized. Downloads are authenticated and applied idempotently; invalid encrypted objects are quarantined without plaintext. Uploads are verified by downloading the stored bytes. A lost upload response is recovered by reopening and comparing the immutable object. Failed work remains in the local outbox.

Before upload the coordinator verifies the authenticated user, private/writeable repository, canonical owner/name, numeric repository ID, descriptor vault/generation, and required protocol features. A public repository, recreated repository, wrong vault, unsupported feature, missing/changed known object, sequence regression, or non-descendant branch head stops uploads without rolling back local state. A private-repository 404 remains explicitly ambiguous.

Remote Repair re-uploads locally verified history and verifies unknown objects; it never deletes unknown remote files. Repository replacement keeps the old configuration active, uploads a new generation to an empty path, reopens it with a fresh client, verifies complete encrypted operation coverage, and only then activates the replacement. The previous configuration is retained as a disabled DPAPI-protected fallback; repositories are never automatically deleted.

## Bounds and limitations

Responses are capped at 32 MiB and JSON depth is capped. A truncated recursive tree falls back to non-recursive traversal with strict component/path validation, depth 64, at most 10,000 trees, and at most 100,000 blobs. The complete traversal is accumulated before application; exceeding a limit rejects the entire sync. Operations retain the bounds documented in `LOCAL_SYNC_PROTOCOL.md`. Retry uses bounded exponential backoff with jitter and honors `Retry-After`.

GitHub availability is not a recovery guarantee. Token expiration, repository loss, account loss, or service outages do not affect the local vault. Keep verified Recovery-A/Recovery-B bundles and provider recovery methods.
