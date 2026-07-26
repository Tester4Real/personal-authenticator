# Publishing and MSIX assessment

## Unpackaged self-contained builds

The application project is intentionally configured with
`WindowsPackageType=None`. The two publish profiles create complete,
architecture-specific folders containing the application, the .NET runtime,
and the Windows App SDK runtime:

```powershell
dotnet publish .\src\PersonalAuthenticator.App\PersonalAuthenticator.App.csproj `
  -p:PublishProfile=UnpackagedSelfContained-x64

dotnet publish .\src\PersonalAuthenticator.App\PersonalAuthenticator.App.csproj `
  -p:PublishProfile=UnpackagedSelfContained-ARM64
```

For a clean, repeatable publish of either or both architectures, use the
repository script:

```powershell
# Both release architectures
.\scripts\Publish.ps1

# One release architecture
.\scripts\Publish.ps1 -Architecture x64
.\scripts\Publish.ps1 -Architecture arm64
```

The default output locations are:

```text
artifacts/publish/win-x64/
artifacts/publish/win-arm64/
```

The script deletes only the selected generated runtime directory before
publishing. Output is restricted to the repository's `artifacts/` subtree, and
existing reparse points in the output path are rejected before cleanup. The
script verifies the expected executable, non-empty
`THIRD-PARTY-NOTICES.md`, `PersonalAuthenticator.App.pri`, `App.xbf`,
`MainWindow.xbf`, `Dialogs\AddAccountDialog.xbf`, and
`Dialogs\SettingsDialog.xbf`. Copy the entire runtime directory when
deploying; the executable is not a single-file application, and the legal
notice must remain with it.

## Observed publish validation

The final observed Release run of `scripts\Publish.ps1` succeeded for both
`win-x64` and `win-arm64`. Both generated folders passed the script's
executable, legal-file, PRI, and XBF checks.

The published x64 executable launched, rendered, and remained responsive on the
development machine. During the monitored run, its process owned zero TCP and
zero UDP endpoints. ARM64 output was inspected by the publish script but has
not been executed. Neither architecture has yet been deployed on a clean
machine.

The target computer must run Windows 10 version 2004 (build 19041) or later.
Use `win-x64` on x64 Windows and `win-arm64` on ARM64 Windows. The folders
contain the selected .NET and Windows App SDK runtime files and are intended
not to require separate runtime installation; confirm that behavior during the
pending clean-machine deployment test.

These profiles and commands do not sign the binaries. Code signing is
recommended before distributing them to another computer.

The aggregate `Microsoft.WindowsAppSDK` 2.3.1 licence provides redistribution
terms for binplaced self-contained files, while the centrally pinned transitive
WinUI 2.3.2 component carries conflicting “Engineering Preview” wording. See
`docs\DEPENDENCIES.md` and `THIRD-PARTY-NOTICES.md`; obtain legal clarification
before external distribution.

## MSIX assessment

An MSIX option is practical, but it is deliberately not enabled in the normal
project yet:

- The existing application project explicitly selects unpackaged deployment.
- An MSIX package needs a stable package identity and a signing certificate.
- The manifest publisher must exactly equal the subject of that certificate.
- x64 and ARM64 packages must be generated separately or combined into a
  bundle by MSIX tooling.
- Enabling packaging changes application identity and installation/update
  behaviour, so it should be validated as a separate release workflow.

`Package.appxmanifest` is a starting template that uses the existing logo
assets. The manifest refers to the logical resource names
`Square150x150Logo.png` and `Square44x44Logo.png`; MakePri/MSIX resolves the
existing `.scale-100.png` and `.scale-200.png` qualified files.

To turn the template into a package:

1. Create or choose a code-signing certificate. Do not add its private key,
   `.pfx` file, or password to source control.
2. Replace the template `Identity/@Name` with the intended stable package
   identity, replace `Identity/@Publisher` with the certificate subject, and
   set `Properties/PublisherDisplayName` to the intended public publisher name.
3. Copy the reviewed manifest to
   `src/PersonalAuthenticator.App/Package.appxmanifest`.
4. In a packaging-specific project configuration, change
   `WindowsPackageType` from `None` to `MSIX` and enable the Windows App SDK
   MSIX tooling (`EnableMsixTooling`). Keep the unpackaged release
   configuration available.
5. Build and sign x64 and ARM64 packages with Visual Studio or Build Tools that
   include the Windows application packaging workload.
6. Install the signed package on a clean Windows test user, then validate
   launch, file and clipboard import, DPAPI vault persistence, backup restore,
   Windows Hello fallback, upgrades, and uninstall/reinstall behaviour.

For local development, a self-signed certificate may be trusted explicitly on
the test machine. For broader distribution, use a trusted code-signing
certificate or Microsoft Store signing. Never commit a private signing
certificate.

The template has been kept under `packaging/`, rather than in the application
project, so it cannot silently turn existing restore, build, or publish
commands into packaged builds.
