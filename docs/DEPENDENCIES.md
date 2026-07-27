# Dependencies and licences

## Scope

Package versions are centralized in `Directory.Packages.props`, with central transitive pinning enabled. This document covers every NuGet package deliberately declared there and identifies where it is used.

Licence values below were checked against restored NuGet package metadata and
the package owners' official release/licence pages for the pinned versions.
They are not legal advice. Transitive packages are resolved by NuGet and can
change when direct versions change; generate the exact restored bill of
materials before each release:

```powershell
dotnet list .\PersonalAuthenticator.sln package --include-transitive
```

Keep `THIRD-PARTY-NOTICES.md` with every build and publish folder. Review the
exact resolved packages, licences, bundled notices, vulnerability advisories,
and upstream maintenance again whenever a version changes.

## Runtime and build dependencies

| Package | Version | Purpose / projects | Licence | Maintenance assessment | Selection rationale |
| --- | ---: | --- | --- | --- | --- |
| `CommunityToolkit.Mvvm` | `8.4.2` | Observable ViewModels and generated property notification in App/tests | MIT | Microsoft/community-maintained toolkit; pinned and widely used in Windows/.NET apps | Removes repetitive `INotifyPropertyChanged` code while keeping ViewModels framework-light and testable |
| `Konscious.Security.Cryptography.Argon2` | `1.3.1` | Argon2id key derivation for verified Recovery-A/Recovery-B bundles in Infrastructure | MIT | Focused managed implementation; pinned, bounded parameters, and covered by authentication/tamper/rotation tests; monitor upstream and advisories | Supplies the memory-hard Argon2id construction without implementing a password KDF in application code |
| `Microsoft.Extensions.DependencyInjection` | `10.0.10` | Constructor-injection composition root in App | MIT | Microsoft-maintained .NET 10 line | Small standard container; avoids a custom service locator or larger third-party container |
| `Microsoft.Extensions.Logging` | `10.0.10` | Logging abstractions and source-generated structured events in App/Infrastructure/tests | MIT | Microsoft-maintained .NET 10 line | Standard abstractions with compile-time templates and controlled fields |
| `Microsoft.Extensions.Logging.Debug` | `10.0.10` | Debugger-only provider in Debug builds | MIT | Microsoft-maintained .NET 10 line | No network sink, file sink, telemetry backend, or production provider is introduced |
| `Microsoft.Win32.SystemEvents` | `10.0.10` | Windows session-lock and suspend notifications | MIT | Microsoft-maintained .NET 10 line | Narrow managed access to established Windows events; avoids custom native message plumbing |
| `Microsoft.WindowsAppSDK` | `2.3.1` | Supported aggregate Windows App SDK package for WinUI 3, runtime/build assets, Fluent UI, pickers, clipboard, and WinRT APIs in App/tests | Microsoft Software License Terms in package `license.txt`; its redistribution conditions and bundled third-party notices apply | Microsoft-documented stable release dated 2026-07-16; pinned and subject to release/licence review | Uses the supported aggregate package and its explicit framework-dependent/self-contained redistribution terms rather than directly consuming an internal component package |
| `Microsoft.WindowsAppSDK.WinUI` | `2.3.2` | Centrally pinned transitive servicing component selected by NuGet beneath aggregate Windows App SDK 2.3.1 | Conflicting Microsoft Software License Terms in the component package's `license.txt`; see caveat below | Microsoft servicing build; not a direct application `PackageReference` | Pins the resolved WinUI component above the aggregate package's `2.3.0` dependency floor, but requires legal clarification before external redistribution |
| `Otp.NET` | `1.4.1` | RFC-compatible TOTP generation and Base32 decoding in Core/Infrastructure | MIT | Focused community library with a mature, small API surface; pinned and covered by RFC vector tests; monitor upstream/advisories | Avoids home-grown Base32/TOTP cryptographic code and supports SHA-1/SHA-256/SHA-512 and configurable digits/steps |
| `System.IO.FileSystem.AccessControl` | `5.0.0` | Restrictive Windows ACL construction for the final local vault | MIT | Microsoft `dotnet/runtime` package; older pinned API package, so compatibility/advisories should be re-evaluated during upgrades | Provides supported managed ACL APIs instead of custom P/Invoke security-descriptor code |
| `System.Security.Cryptography.ProtectedData` | `10.0.10` | DPAPI `CurrentUser` encryption for the local vault | MIT | Microsoft-maintained .NET 10 line | Uses the Windows user-bound protection facility instead of inventing local key storage |
| `ZXing.Net` | `0.16.11` | Fully local QR decoding after Windows image conversion | Apache-2.0 | Long-lived community port; pinned; input limits and strict URI parsing reduce its trust surface; monitor upstream/advisories | Avoids an online QR service and supports decoding from raw pixel buffers without persisting images |

### Windows App SDK release and licence verification

The application directly references the aggregate `Microsoft.WindowsAppSDK`
2.3.1 package. Its bundled Microsoft Software License Terms state that files
binplaced by the WindowsAppSDK NuGet package may be redistributed in
framework-dependent and self-contained applications, subject to the stated
distribution requirements and restrictions. Those aggregate terms, not an MIT
licence, are the intended redistribution basis.

The resolved graph also contains `Microsoft.WindowsAppSDK.WinUI` 2.3.2 because
central transitive pinning selects that servicing build above the aggregate
package's 2.3.0 dependency floor. It is not directly referenced by the
application, but its own bundled `license.txt` is titled **Microsoft Windows App
SDK Engineering Preview** and contains wording that conflicts with ordinary
live use/redistribution. The aggregate licence appears to cover files binplaced
by its NuGet package, but this component-level conflict must be resolved with
Microsoft or qualified legal review before external distribution. Do not omit
the caveat merely because both packages share a product family.

The aggregate package, the WinUI servicing component, transitive WebView2
terms, and all bundled notices must be reviewed again before each distribution.
See [`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md).

## Test-tool dependencies

| Package | Version | Purpose / projects | Licence | Maintenance assessment | Selection rationale |
| --- | ---: | --- | --- | --- | --- |
| `Microsoft.NET.Test.Sdk` | `18.8.1` | VSTest host/discovery for both test projects | MIT | Microsoft-maintained test platform | Standard `dotnet test` integration |
| `xunit` | `2.9.3` | Unit/integration test framework | Apache-2.0 | xUnit project; mature and actively used; pinned | Requested framework with concise facts/theories and broad .NET tooling support |
| `xunit.runner.visualstudio` | `3.1.5` | VSTest/Visual Studio xUnit adapter; marked `PrivateAssets=all` | Apache-2.0 | xUnit project runner; test-only and pinned | Makes xUnit tests discoverable by `dotnet test` and Visual Studio without entering runtime output |

## Framework and SDK baseline

These are platform/toolchain dependencies rather than `PackageReference` entries:

| Component | Pinned/target value | Role |
| --- | --- | --- |
| .NET SDK | `10.0.302`, roll forward to latest 10.0 patch, prerelease disabled | Build, analyzers, format, test, and publish |
| Core target | `net10.0` | Platform-neutral domain/service assembly |
| Windows targets | `net10.0-windows10.0.19041.0` | WinUI/Infrastructure/test Windows API baseline |
| Runtime identifiers | `win-x64`, `win-arm64` | Intended self-contained deployment architectures |
| C# language | `latest` as supplied by the pinned stable SDK | Nullable-enabled implementation |

`Directory.Build.props` enables nullable reference types, implicit usings, warnings as errors, latest-recommended .NET analyzers, deterministic builds, and embedded debug symbols.

## Alternatives considered

### UI: WPF, WinForms, Avalonia, or additional theme frameworks

WinUI 3 was a product requirement and supplies Fluent controls, Mica, title-bar integration, accessibility, and current Windows APIs. WPF/WinForms would simplify some deployment paths but would not meet the selected UI stack. Avalonia would add a cross-platform abstraction not needed by this Windows-only product. An additional theme library was avoided.

### MVVM: handwritten notifications or another MVVM framework

Handwritten `INotifyPropertyChanged` is viable but increases repetitive, error-prone code. CommunityToolkit.Mvvm is narrowly scoped, source-generator based, and aligned with WinUI/.NET.

### TOTP: custom implementation or another OTP package

A custom implementation was rejected because the application should not invent cryptographic primitives or Base32 handling. Otp.NET has a small API and is independently checked here with published RFC 6238 vectors. Any replacement must support all three hash algorithms, variable periods, six/eight digits, UTC timestamps, and equivalent vector tests.

### Local vault: app-managed AES key, Credential Locker, or plaintext per-secret encryption

An app-managed symmetric key creates a key-storage problem. Credential Locker does not naturally provide the versioned, atomically replaced whole-vault payload used here. DPAPI `CurrentUser` protects the complete payload using Windows profile keys. Its non-portability is addressed by the separate password-encrypted format.

### Portable KDF: Argon2id

The original portable `.pab` format remains PBKDF2-HMAC-SHA-512 with 600,000 iterations for backward compatibility. Windows v2 Recovery-A/Recovery-B bundles use the separately versioned Argon2id format with 64 MiB memory, three iterations, and parallelism two. Bundle headers carry bounded KDF parameters and are authenticated as AES-GCM associated data.

### Portable authenticated encryption: AES-CBC plus HMAC

AES-256-GCM is provided by .NET and supplies authenticated encryption in one construction. A custom encrypt-then-MAC composition was unnecessary and more error-prone.

### QR: online decoding, Windows-only custom decoder, or other bindings

Online decoding was rejected because QR images contain credentials. ZXing.Net operates locally from raw pixels and has a long interoperability history. Windows decodes the image container; ZXing handles QR recognition. Strict size limits and the independent provisioning parser constrain input.

### Logging: Serilog/NLog or remote telemetry

The app needs only local development diagnostics and fixed structured events. Microsoft logging abstractions plus the Debug provider avoid file retention, network sinks, remote telemetry, and another dependency family.

### Tests: MSTest or NUnit

xUnit was an explicit requirement and works with the standard .NET test SDK. No runtime code depends on the test stack.

## Upgrade policy

For each dependency update:

1. Read upstream release notes and security advisories.
2. Confirm the version is stable and compatible with the pinned .NET SDK/Windows target.
3. Re-check package metadata, bundled licence, and notices.
4. Review transitive changes with `dotnet list package --include-transitive`.
5. Restore, build Release x64 and ARM64, run all tests, and verify formatting.
6. Re-run RFC TOTP vectors, QR limits, DPAPI round trips, backup golden/tamper tests, and secret-leak searches.
7. Launch and manually exercise the application from clean publish output.
8. Update this file and `CHANGELOG.md`.

Do not automatically float cryptographic, Windows App SDK, QR, or build-tool dependencies in a production release.
