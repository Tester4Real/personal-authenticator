# Personal Authenticator

Personal Authenticator is a Windows-only, fully local TOTP authenticator built with .NET 10 and WinUI 3. It imports standard `otpauth://totp/...` setup URIs, QR images, or manual account details; generates six- or eight-digit codes; and stores the complete sensitive vault under the current Windows user's DPAPI protection.

> [!WARNING]
> The published Release x64 application launched, rendered, and remained responsive on the development machine. Both x64 and ARM64 self-contained publish folders passed the repository's resource/legal-file checks. This is still security-sensitive software: re-run the release checklist on the release commit and keep provider recovery methods. Clean-machine deployment, ARM64 execution, MSIX, and signing validation remain outstanding.

## Features

- TOTP with SHA-1, SHA-256, or SHA-512, six or eight digits, and 15–300 second periods
- Strict provisioning-URI validation, including duplicate-parameter and issuer-mismatch rejection
- Local PNG/JPEG and clipboard QR decoding with size, dimension, payload, and multiple-code limits
- Search, favourites, display-name editing, ordering, explicit deletion confirmation, and duplicate handling
- A single one-second UI timer that only regenerates a code when its TOTP step changes
- DPAPI `CurrentUser` encryption for the local vault, transactional clone-and-commit mutations, atomic replacement, an encrypted previous copy, and a restricted final-file ACL
- Explicit lock, inactivity lock, minimise lock, Windows session-lock/suspend handling, and best-effort secret-buffer clearing
- Optional Windows user verification before unlock, reveal, or copy when the OS capability is available
- Clipboard history/roaming suppression, random per-copy ownership markers, delayed conditional clearing, and immediate conditional clearing on lock/exit
- Portable `.pab` backups using PBKDF2-HMAC-SHA-512 and AES-256-GCM
- Four whole-import restore policies: merge/skip, merge/replace matches, merge/keep duplicates, or exact replacement
- No application HTTP client, cloud sync, analytics, advertisements, telemetry, or crash upload

## Screenshot

![Verified Personal Authenticator main window](artifacts/manual-mainwindow-print.png)

This capture was taken from the live Release x64 development build.

## Security warning

Running an authenticator on the same PC used to sign in is convenient, but it weakens the separation normally provided by a second device. Malware or an attacker controlling the same Windows session may be able to observe both the primary login flow and the TOTP code. For high-value accounts, prefer a separate trusted authenticator or a phishing-resistant hardware-backed method where the service supports one.

DPAPI protects the vault at rest; it does not protect an unlocked process from same-user malware, an administrator, a debugger, screen capture, keylogging, or clipboard monitoring. Read [docs/SECURITY.md](docs/SECURITY.md) before relying on the application.

## Prerequisites

For development:

- Windows 10 version 2004/build 19041 or later, or Windows 11
- An x64 or ARM64 Windows machine matching the target being run
- .NET SDK `10.0.302`; `global.json` allows later 10.0 patch SDKs and rejects prerelease SDKs
- Network access for the initial NuGet restore
- PowerShell, Command Prompt, or another terminal capable of running the .NET CLI

The project targets `net10.0-windows10.0.19041.0`. The app project is configured as unpackaged and self-contained for both .NET and Windows App SDK deployment. Both architecture publish operations have succeeded, but deployment has not yet been exercised from a clean machine.

## Restore and build

From the repository root:

```powershell
dotnet restore .\PersonalAuthenticator.sln
dotnet build .\PersonalAuthenticator.sln --configuration Release
```

To build the Windows application for x64 explicitly:

```powershell
dotnet build .\src\PersonalAuthenticator.App\PersonalAuthenticator.App.csproj `
  --configuration Release `
  --runtime win-x64 `
  -p:Platform=x64
```

The final observed validation completed solution restore and Release build successfully. Re-run the commands in the current checkout before treating that result as current.

## Run

For an x64 development run:

```powershell
dotnet run --project .\src\PersonalAuthenticator.App\PersonalAuthenticator.App.csproj `
  --configuration Debug `
  --runtime win-x64 `
  -p:Platform=x64
```

Or run the executable emitted beneath:

```text
src\PersonalAuthenticator.App\bin\<Configuration>\net10.0-windows10.0.19041.0\<RID>\
```

The self-contained Release x64 publish output has launched, rendered, and
responded successfully. During the monitored run, the process owned zero TCP
or UDP endpoints. This is a point-in-time runtime check, not a substitute for
source review or host-level traffic monitoring.

If window construction fails, a safe startup diagnostic is written to:

```text
%LOCALAPPDATA%\PersonalAuthenticator\startup.log
```

The diagnostic contains startup/XAML error details only and is not written
during a normal launch.

## Test and format

Run all tests:

```powershell
dotnet test .\PersonalAuthenticator.sln --configuration Release
```

Run the two suites independently:

```powershell
dotnet test .\tests\PersonalAuthenticator.Core.Tests\PersonalAuthenticator.Core.Tests.csproj `
  --configuration Release

dotnet test .\tests\PersonalAuthenticator.Infrastructure.Tests\PersonalAuthenticator.Infrastructure.Tests.csproj `
  --configuration Release
```

Verify formatting:

```powershell
dotnet format .\PersonalAuthenticator.sln --verify-no-changes
```

The final observed test run passed 70 tests: 34 Core tests and 36 Infrastructure/ViewModel tests. These cover strict URI and percent-encoding parsing, secret-buffer disposal, duplicate fingerprints, transactional vault failure/reload paths, all four backup-import policies, RFC 6238 TOTP vectors, DPAPI persistence, portable-backup authentication/tamper/overwrite/length cases, bounded non-seekable QR input, clipboard ownership and cancellation, logging-policy markers, and ViewModel workflows.

`dotnet format .\PersonalAuthenticator.sln --verify-no-changes` also passed.

## Account import

The add-account dialog supports:

1. A standard `otpauth://totp/...` URI.
2. A local `.png`, `.jpg`, or `.jpeg` QR image.
3. A QR image currently on the Windows clipboard.
4. Manual issuer, account name, Base32 secret, algorithm, digits, and period entry.

A confirmation dialog shows the display information, parameters, and only a short masked secret suffix. The full secret is not intentionally displayed. Unknown URI parameters, HOTP URIs, malformed Base32, duplicate parameters, empty labels, and conflicting issuers are rejected.

## Local files

By default, application state is stored beneath:

```text
%LOCALAPPDATA%\PersonalAuthenticator\
```

| File | Contents | Protection |
| --- | --- | --- |
| `vault.pav` | Complete account payload, including secrets | DPAPI `CurrentUser`; versioned binary envelope; restricted final-file ACL |
| `vault.pav.previous` | Previous encrypted vault produced during atomic replacement | Still DPAPI ciphertext; retained for recovery, with no automatic restore UI |
| `settings.json` | Theme, lock, reveal, and clipboard preferences | Plaintext by design; must never contain account secrets |
| `startup.log` | Optional safe XAML-startup diagnostic | Created only after a startup failure; contains error type, HRESULT, and exception message before the vault is loaded |

A copied `vault.pav` normally cannot be restored after Windows is reinstalled or from a different Windows user profile. Use a password-encrypted portable backup for recovery.

## Portable backup and restore

### Export

1. Unlock the vault.
2. Open **Settings**.
3. Enter and confirm a backup password of at least 12 characters.
4. Select **Export encrypted backup** and confirm the destination in the Windows save picker.
5. Store the resulting `.pab` file somewhere separate from the PC.

The password is not stored and cannot be recovered. Each export uses a fresh 16-byte salt and 12-byte nonce. Account names and secrets are inside the authenticated ciphertext.

The Windows save picker supplies explicit overwrite permission. A confirmed
overwrite is written to a same-directory temporary file and atomically replaces
the destination; the application does not pre-delete the old backup.

### Restore

1. Install or build Personal Authenticator on the destination Windows installation.
2. Unlock the local vault.
3. Open **Settings**, enter the backup password, and choose one whole-import policy.
4. Select the `.pab` file and import it.

The policies are:

- **Merge and skip duplicates:** retain local accounts and ignore imported likely matches.
- **Merge and replace matching accounts:** retain unmatched local accounts and replace each likely match with the imported record.
- **Merge and keep duplicates:** append all imported records, including likely matches.
- **Replace current vault exactly:** discard the current set and preserve the backup's complete account list, including intentional duplicates.

The choice applies to the whole import; there is no per-account conflict report.

Keep provider recovery codes separately. Losing both the backup password and all provider recovery options can permanently lock you out. The exact format is documented in [docs/BACKUP_FORMAT.md](docs/BACKUP_FORMAT.md).

## Publish

The app project declares `win-x64` and `win-arm64`, `SelfContained=true`,
`WindowsAppSDKSelfContained=true`, and `PublishSingleFile=false`. Create clean
outputs for both architectures with:

```powershell
.\scripts\Publish.ps1
```

Or publish one architecture:

```powershell
.\scripts\Publish.ps1 -Architecture x64
.\scripts\Publish.ps1 -Architecture arm64
```

The architecture-specific publish profiles can also be invoked directly. See
[packaging/README.md](packaging/README.md) for those commands and the MSIX
assessment.

Output:

```text
artifacts\publish\win-x64\
artifacts\publish\win-arm64\
```

The final observed `Publish.ps1` run succeeded for both targets. For each
folder, the script verified the executable, a non-empty
`THIRD-PARTY-NOTICES.md`, `PersonalAuthenticator.App.pri`, `App.xbf`,
`MainWindow.xbf`, and both dialog XBF files. The x64 folder was then launched
successfully; ARM64 execution remains unverified.

Distribute each complete folder, including `THIRD-PARTY-NOTICES.md`, rather
than only the executable. The repository currently has no MSIX packaging
project and sets `WindowsPackageType=None`; therefore, no installer is
produced. Published executables are unsigned. Local development can use
unsigned output, but redistributed builds should be code-signed, and a future
MSIX must be signed with a certificate whose private key is never committed.

## Known limitations

- Automated hardening coverage and x64 launch/responsiveness checks passed, but every security workflow should still be repeated manually on the final release commit.
- Clean-machine self-contained deployment and ARM64 execution are unverified.
- No MSIX installer, update mechanism, or code-signing workflow is implemented.
- TOTP only: no HOTP, proprietary push approval, passkeys, provider login, or cloud sync.
- QR drag-and-drop is not implemented; supported paths are file picker and clipboard.
- The program does not synchronize time over a network. It only warns after detecting an unexpected local wall-clock jump.
- Windows user verification is a presence gate, not a cryptographic vault key. If unavailable or not configured, the implementation falls back to DPAPI and allows the operation.
- The unavailable-verifier fallback is currently silent. To require a prompt before on-screen reveal, enable both **Hide codes by default** and **Require verification for codes**; verification alone does not hide already-visible cards.
- **Start unlocked** uses the same Windows user-verification flow as an explicit unlock; when no verifier is available, the documented DPAPI fallback still applies.
- Backup restore offers four explicit whole-import policies but no per-account conflict report.
- Backup KDF, AES, JSON, and QR CPU continuations do not run on the UI thread and include cancellation checkpoints. PBKDF2 itself cannot be interrupted once a derivation call begins, and there is no progress/cancel UI.
- Managed-memory clearing is best effort; immutable strings and runtime/OS copies cannot be guaranteed to disappear immediately.
- Clipboard clearing only reduces exposure duration. Other software can read a copied code before it is conditionally cleared.
- A previous encrypted local vault is retained, but there is no automatic recovery UI for it.
- The direct aggregate Windows App SDK terms permit redistribution of binplaced self-contained files, but the resolved WinUI 2.3.2 servicing component carries conflicting “Engineering Preview” wording. Resolve that legal/licence caveat before external distribution.

## Further documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Portable backup format](docs/BACKUP_FORMAT.md)
- [Dependencies and licences](docs/DEPENDENCIES.md)
- [Third-party notices](THIRD-PARTY-NOTICES.md)
- [Changelog](CHANGELOG.md)
