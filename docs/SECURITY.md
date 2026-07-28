# Security model

## Executive warning

Personal Authenticator reduces the risk of secrets being exposed in ordinary files, logs, backups, clipboard history, or accidental cloud services. It does not make a compromised Windows session safe.

Using TOTP on the same PC as the account login removes much of the independent-device separation of multi-factor authentication. Same-user malware, an administrator, or an attacker with control of an unlocked session may capture the password, current code, decrypted secret, screen, keystrokes, or clipboard. Use a separate device or phishing-resistant hardware-backed authentication for high-value accounts when possible.

Restore, Release build, 70 automated tests, formatting, x64/ARM64 self-contained
publishing, and published-x64 launch/responsiveness checks passed. The monitored
x64 process owned zero TCP or UDP endpoints. Clean-machine deployment, ARM64
execution, signing, and exhaustive manual security-workflow validation remain
release activities. Do not use the app as the only copy of production
authenticator credentials.

## Protected assets

| Asset | Sensitivity |
| --- | --- |
| TOTP seed bytes | Long-lived credential material; disclosure lets an attacker generate future codes |
| Current OTP | Short-lived bearer value that may complete a login |
| Account issuer/name | Potentially sensitive service and identity metadata |
| Portable-backup password | Unlocks every account in that backup |
| Derived backup key and decrypted JSON | Equivalent to access to the backup's account set |
| Windows DPAPI context | Determines whether the local vault can be decrypted |
| Provider recovery codes | Outside this application's storage, but essential for recovery |

Theme, automatic-lock interval, reveal behavior, and clipboard timing are not treated as secrets and are stored in plaintext settings.

## Threat model

### In scope

- Offline copying, loss, or theft of `vault.pav` without access to the original Windows user context
- Offline copying, loss, modification, truncation, or wrong-password use of a portable `.pab` backup
- Accidental plaintext persistence in the vault, backup, settings, temporary files, or structured application logs
- Accidental acceptance of malformed, ambiguous, oversized, non-TOTP, or multi-code QR input
- Casual shoulder exposure and unnecessary always-visible codes
- Clipboard persistence after a copy and accidentally clearing unrelated later clipboard content
- Race conditions between lock and clipboard clearing
- Failure to release owned in-memory secret buffers on lock/delete/error/exit
- Corrupt or unsupported local/portable envelope versions

### Out of scope

- Malware, injected code, debuggers, or screen/key/clipboard capture running as the same Windows user
- A compromised Windows kernel, administrator, firmware, hypervisor, or physical memory acquisition
- An attacker controlling the process while the vault is unlocked
- Weak backup passwords and sufficiently resourced offline password guessing
- Compromise of the identity provider, primary password, recovery channel, or provider-side TOTP implementation
- Phishing or real-time relay of a valid TOTP code
- Guaranteed clock correctness without an independent trusted time source
- Guaranteed deletion from SSD wear-leveling, paging, crash dumps, hibernation, runtime copies, or OS-managed buffers
- Availability attacks, including deleting or corrupting all local and backup copies

## Trust boundaries

### Windows user and DPAPI

The local vault relies on Windows DPAPI `CurrentUser`. The trust boundary is the current Windows profile and its OS-managed key material. A vault copied to another user or a reformatted Windows installation should fail to decrypt. Conversely, code running with the same user's authority may be able to invoke DPAPI too.

### UI and untrusted import data

Setup URIs, manual fields, QR images, clipboard images, backup files, and backup passwords cross from untrusted local input into the application. The parser, image decoder, envelope parser, authenticated decryption, and domain constructors validate them before account state changes.

### Disk

The local vault and portable backups cross a persistent-storage boundary. The local file contains only a versioned DPAPI envelope. The portable file exposes encryption parameters and lengths but keeps account metadata and secrets in AES-GCM ciphertext. Non-secret settings are plaintext.

### Clipboard

Windows clipboard contents are shared with other applications in the user session. A copied OTP leaves the process and cannot be considered confidential during the configured interval.

### Windows user verification

`UserConsentVerifier` is an OS presence prompt. It does not derive or unwrap the vault encryption key. It is a convenience gate layered before DPAPI decryption or a reveal/copy action.

## Local vault protection

The complete compact JSON account payload is encrypted, including issuer, account name, TOTP parameters, timestamps, and secret bytes. `DpapiVaultStore` uses:

- `ProtectedData.Protect`/`Unprotect`
- `DataProtectionScope.CurrentUser`
- Fixed optional entropy: SHA-256 of `Personal Authenticator DPAPI vault v1`
- Envelope magic `PAVLT001` and format version `1`
- A creation timestamp and protected-payload length
- SHA-256 of the DPAPI ciphertext as an early corruption check
- A 64 MiB maximum vault file size

The unkeyed SHA-256 is not a MAC and must not be described as an additional security boundary. DPAPI provides the actual confidentiality and integrity behavior.

Updates are written as ciphertext to a same-directory temporary file with write-through, flushed to disk, and atomically replaced. The prior encrypted vault is retained as `vault.pav.previous`; no plaintext previous copy exists. The final `vault.pav` ACL disables inheritance and grants full control only to the current user SID and Local System.

Account mutations are transactional at the service layer: the live set is
deep-cloned, only the owned clones are changed, and live state is replaced only
after encrypted persistence succeeds. A staging-clone, serialization, or save
failure disposes staging secrets, retains the preceding live set, enters
`Faulted`, hides it from normal UI actions, and can reload the last successful
disk state on the next unlock.

### DPAPI limitations

- DPAPI binds recovery to the Windows user/profile and its key material. A raw `vault.pav` is not a portable backup.
- Formatting Windows, deleting the user profile, domain/account changes, or losing DPAPI master keys may make the vault unrecoverable.
- Same-user malware can generally call DPAPI or read the process after unlock.
- An administrator or sufficiently privileged attacker may compromise the user/session.
- DPAPI at rest does not protect codes rendered on screen, copied to the clipboard, or held in an unlocked process.
- Fixed optional entropy is not a password and is not secret.
- File ACLs are defense in depth; an administrator can bypass or alter them.

Use a portable encrypted backup and separately retained provider recovery codes.

## Locking and in-memory handling

The vault state machine is `Uninitialised → Locked/Unlocked → Unlocking/Locking → Unlocked/Locked`, with `Faulted` on load/decrypt failure.

When locking:

1. Any pending clipboard timer is cancelled and the clipboard is immediately cleared only if the code and random ownership marker still match.
2. Every active `TotpAccount` is disposed.
3. Each account's owned `SensitiveBuffer` atomically releases and overwrites its byte array with `CryptographicOperations.ZeroMemory`.
4. The active account list and visible cards are cleared.

Temporary plaintext, password-byte, derived-key, ciphertext, tag, envelope, and QR pixel buffers are also overwritten in `finally` blocks where the implementation owns them.

### Managed-memory limitations

Zeroisation is best effort:

- Serialization, cryptographic libraries, WinRT, XAML, and the CLR may create copies outside application ownership.
- `PasswordBox.Password`, provisioning URI text, account labels, generated OTP strings, exception messages, and other .NET strings are immutable.
- The backup service clears its own password `char[]`/UTF-8 buffer, but it cannot clear the original UI string or all runtime copies.
- JIT optimization, garbage collection, paging, crash dumps, hibernation, and OS buffers are outside the application's guarantees.

Lock promptly, keep the OS patched, protect the Windows account, and avoid crash/memory dumps containing an unlocked process.

## Automatic lock behavior

The app can lock after configured inactivity, minimization, Windows session lock, or suspend. Explicit lock and application exit also clear active account objects. Inactivity is based on key-down and pointer-press events seen by the root UI; it is not proof the user is absent.

Automatic locking reduces unattended exposure but cannot retroactively hide values already observed or captured. An abrupt process or OS termination may bypass graceful cleanup, although the on-disk vault remains encrypted.

## Windows user verification limitations

When `UserConsentVerifier` is available, an interactive unlock asks Windows to verify the user. The optional reveal/copy setting uses the same service.

Important behavior:

- Verification is a user-presence gate, not the vault encryption key.
- If the device has no verifier, the user has not configured it, policy disables it, or the API is otherwise unavailable, `WindowsUserVerificationService` deliberately returns success and the app falls back to DPAPI rather than permanently locking out the user.
- That unavailable-verifier fallback currently proceeds without an explicit UI explanation.
- Cancellation or failed verification while the API is available leaves the vault locked or cancels reveal/copy.
- `RequireVerificationForCodes` gates the reveal and copy actions; it does not by itself hide cards that are already configured to display codes. Enable `HideCodesByDefault` as well when a prompt should precede on-screen reveal.
- The **Start unlocked** setting uses the same verification-gated unlock path as an explicit unlock. If no verifier is available, the documented fallback still permits the operation.
- Verification cannot defend against code already executing inside or controlling the process.

If mandatory fail-closed verification is required, this version does not provide that policy.

## Clipboard limitations

The service accepts only six- or eight-character ASCII-numeric codes. It requests:

- no clipboard history
- no clipboard roaming
- a configurable 5–300 second clear delay

Each copy includes a fresh random 16-byte value encoded into the custom format
`application/x-personal-authenticator-owner`. The delayed task has its own
cancellation source, independent of the UI command token. At expiry, it clears
only if both the current text and marker match. Before a newer copy, on lock,
and on normal exit, the timer is cancelled and that same conditional clear is
attempted immediately. This avoids erasing unrelated content, including the
same numeric text placed by a different owner.

Clipboard clearing is exposure reduction, not prevention:

- Any process with clipboard access can read the code before clearing.
- The marker is an ownership/race guard, not a secret or authorization boundary; another process that can read and reproduce it can defeat the distinction.
- Clipboard managers, remote-session software, accessibility tools, malware, or the OS may retain copies despite the requested flags.
- A crash or forced termination may prevent delayed clearing.
- Equality checking reveals the expected code to the service for the task lifetime; the code is an immutable string and cannot be reliably zeroed.

## QR import controls

QR decoding occurs locally through Windows image decoding and ZXing.Net. No image or payload is uploaded or intentionally saved.

Limits enforced by the decoder/parser:

- 20 MiB input limit for both seekable and non-seekable streams; non-seekable data is copied only into a bounded in-memory buffer
- Maximum 4,096 × 4,096 dimensions and 16,777,216 pixels
- Exactly one QR result
- Maximum 4,096-character payload
- PNG/JPEG picker allowlist in the UI
- Strict `otpauth://totp/...` parsing after decode

Windows image awaits resume without capturing the WinUI context, so the ZXing
CPU continuation runs off the UI thread. Cancellation is checked during
non-seekable buffering, by the Windows imaging tasks, and around QR recognition.
Decoded pixel bytes and the rented non-seekable copy buffer are cleared best
effort.

## Duplicate detection

Likely duplicates are compared with HMAC-SHA-256 over normalized issuer, account name, algorithm, digits, period, and secret bytes. The 32-byte HMAC key is random per process and cleared when the detector is disposed. Fingerprints are computed only in memory and are not persisted.

This avoids storing a stable raw-secret-derived lookup value. It is still a heuristic: changing display names prevents a match even when the TOTP secret is the same.

## Portable backup encryption

Version-1 `.pab` backups use:

- A fresh 16-byte cryptographically random salt
- PBKDF2-HMAC-SHA-512
- 600,000 iterations on export; import accepts 100,000–5,000,000
- UTF-8 encoding of a 12–1,024 UTF-16-code-unit password
- A 32-byte derived key
- A fresh 12-byte cryptographically random nonce
- AES-256-GCM
- A 16-byte authentication tag
- The entire 52-byte header as authenticated additional data
- A 64 MiB maximum file size

All account metadata and secrets are encrypted. Only magic/version, KDF parameters, lengths, salt, and nonce are exposed. Wrong passwords and authenticated tampering produce the same user-facing message. Structural errors are rejected before key derivation. Full details are in [BACKUP_FORMAT.md](BACKUP_FORMAT.md).

After authenticated decryption, the user selects one policy for the complete
import: merge/skip matches, merge/replace matches, merge/keep duplicates, or
replace the vault exactly while preserving intentional duplicates. The vault
service stages that import on owned clones and commits only after the encrypted
save succeeds. There is no per-account conflict report.

### Backup limitations

- Security against offline guessing depends on password strength; 600,000 PBKDF2 iterations cannot compensate for a weak or reused password.
- The KDF is CPU-hard, not memory-hard.
- KDF, AES, and decrypted-JSON CPU work is dispatched off the UI thread. Cancellation is checked around those operations, but PBKDF2 itself cannot be interrupted mid-derivation and there is no progress/cancel UI.
- Portable backup files do not receive a custom ACL because the user chooses their destination.
- Losing the password means the application cannot recover the backup.
- Export requires an explicit overwrite flag. The Windows save picker supplies that permission; a confirmed overwrite uses ciphertext-only temporary output and `File.Replace` without pre-deleting the existing backup.

Use a long, unique password stored in a reputable password manager, keep at least two protected copies, and test restore using non-production data before depending on the format.

## Logging policy

Production configuration has no logging provider registered by application code. Debug builds register the debugger logging provider at Information level.

Structured log templates contain only:

- fixed event text
- account counts
- exception type names
- vault I/O exception objects for developer diagnostics

They must not contain secrets, OTPs, provisioning URIs, QR payloads, backup passwords, derived keys, decrypted JSON, or clipboard text. `SensitiveDataPolicy` recognizes forbidden marker classes, and security regression tests exercise those markers. This is a narrow regression guard, not a general data-loss-prevention engine; new log statements require review.

The XAML startup diagnostic at `%LOCALAPPDATA%\PersonalAuthenticator\startup.log` records timestamp, exception type, HRESULT, and exception message. It executes before vault initialization and must remain restricted to startup/XAML details.

There is no application analytics, telemetry, remote logging, crash upload, HTTP client, GitHub client, or token handling. Optional Phase 4 local-folder synchronisation exchanges only authenticated ciphertext through a user-selected filesystem path; its protocol and limitations are documented in `LOCAL_SYNC_PROTOCOL.md`.

The published x64 process owned zero TCP and zero UDP endpoints during the
observed responsiveness run. That point-in-time process check supports, but
does not replace, the source-level no-network policy.

## Incident response and recovery

### Suspected account or PC compromise

1. From a separate known-clean device, use each provider's recovery process.
2. Revoke active sessions and rotate the primary password.
3. Disable and re-enrol TOTP so the old seed can no longer generate valid codes.
4. Replace recovery codes.
5. Treat every vault and portable backup present during the compromise as potentially copied.
6. Rebuild or remediate the PC before restoring newly issued credentials.

Deleting the local vault alone does not revoke a stolen TOTP seed.

### Lost or reformatted PC

Install a trusted build on the replacement Windows installation and restore a `.pab` using its password. The old `vault.pav` normally cannot cross the DPAPI boundary. If no portable backup exists, use each service's recovery codes/support process.

### Corrupt local vault

Stop modifying the application-data directory and preserve copies of `vault.pav` and `vault.pav.previous`. The application does not currently restore the previous file automatically. Prefer restoring a known-good portable backup; manual previous-file recovery should be attempted only on copies and under the same Windows user profile.

### Lost backup password

There is no recovery mechanism or password escrow. Use another valid backup, the still-accessible local vault, or provider recovery. If the local vault is still available, export a new backup with a new strong password.

### Rejected codes

Check Windows date, time, time zone, and synchronization status. The application can detect a local clock jump but cannot determine authoritative time without a trusted external source.

## Security review checklist

Before a release:

- Manually validate launch, lock, unlock, delete, clipboard, QR, export, restore, and recovery behavior from the release publish output.
- Re-run all 70 currently observed tests (34 Core and 36 Infrastructure/ViewModel) and add regression cases for every security fix.
- Verify restore, Release build, and formatting; regenerate both publishes and require the script's executable, legal-file, XBF, and PRI checks.
- Search source and artifacts for unintended real secrets, setup URIs, codes, passwords, decrypted JSON, and network clients.
- Test backup tamper/wrong-password/truncation behavior and repeated-export salt/nonce uniqueness.
- Validate that clipboard clearing remains conditional and that lock cancels pending work.
- Validate Windows user-verification available, cancelled, unavailable, and startup-unlock paths.
- Test DPAPI and portable restore from clean Windows profiles/machines.
- Review package licences and advisories, preserve `THIRD-PARTY-NOTICES.md`, and verify the Windows App SDK distribution terms documented in [DEPENDENCIES.md](DEPENDENCIES.md).
- Sign redistributed binaries or a future MSIX without committing private keys.

## Phase 6 lifecycle controls

Device revocation preserves accepted historical operations but rejects unseen sequences above the recorded cut-off. It cannot remotely erase copied secrets; revoke the device token and rotate important website secrets. Vault key rotation and purge use a separately written and verified database/key generation plus verified Recovery-A/B before atomic activation. Purge is not a physical-erasure guarantee because old devices, Git history, recovery media, and backups may retain encrypted copies. See [WINDOWS_SECURITY_LIFECYCLE.md](WINDOWS_SECURITY_LIFECYCLE.md) and [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
