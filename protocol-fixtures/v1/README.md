# Protocol v1 conformance fixtures

These files are deterministic, synthetic, test-only vectors for the Windows and
Android Personal Authenticator implementations. They deliberately include a
fake password and fake OTP seed bytes so that cryptographic outputs can be
reproduced byte-for-byte. None of the values may be used as a real credential.

`manifest.json` is the index and records:

- .NET GUID bytes, comparison order, and UTC tick values;
- Argon2id parameters/output and descriptor verifier input/output;
- descriptor property names and exact file hash;
- nested account, secret-version, and history JSON;
- all 12 operation kinds and the union of all 11 payload flags;
- semantic hashes, parent order, and complete object-header fields;
- deterministic merge ordering and conflict ID/output.

`operations/*.bin` contains original serialized operation bytes.
`objects/*.pao` contains complete encrypted GitHub object envelopes.
`records/*.json` and `descriptor.json` pin exact JSON bytes.

The Windows conformance test rebuilds the vectors independently, compares every
checked-in byte, round-trips every operation, and decrypts every `.pao` object.
Other clients must consume these same checked-in files without rewriting them.
