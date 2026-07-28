# Changelog

All notable changes to Personal Authenticator will be documented in this file.

The project follows semantic versioning once a production release is cut. Dates use `YYYY-MM-DD`.

## [1.0.0] - Unreleased

Initial implementation of the local Windows authenticator.

Windows v2 Phase 3 adds alternating Argon2id/AES-GCM Recovery-A and Recovery-B bundles, complete post-write verification, exact recovery-health change counts and age warnings, and corruption recovery through an independently verified replacement database/key before atomic pointer activation.

Windows v2 Phase 4 adds the schema-4 immutable encrypted operation log, transactional outbox, Windows device sequences and causal ordering, deterministic operation replay, encrypted local-folder transport, conflict preservation/resolution, and the Windows local-sync settings UI. It intentionally adds no GitHub API or token support.

Windows v2 Phase 5 extends verified recovery bundles with operation history and sync state, then adds optional encrypted private-repository GitHub transport, separate DPAPI token storage, durable offline upload, background/debounced sync, rollback detection, corruption quarantine, Remote Repair, and verified repository replacement.

Windows v2 Phase 6 adds the Devices & keys screen, sequence-cutoff revocation enforcement, staged vault key epochs, verified Recovery-A/B rotation, advanced clean-epoch purge, bounded non-recursive Git tree fallback, token-removal verification, security fault injection, an opt-in live GitHub release test, and the final release checklist.

### Added

- WinUI 3 Fluent desktop shell with Mica fallback, custom title bar, system/light/dark themes, search, favourites, account cards, empty/locked states, accessible countdown text, and InfoBar notifications
- TOTP-only account model supporting SHA-1, SHA-256, SHA-512, six/eight digits, and 15–300 second periods
- Strict `otpauth://totp/...` parser and manual Base32 entry
- Local PNG/JPEG and clipboard QR import with input, dimension, pixel, payload, and multiple-code protections
- Masked confirmation preview, duplicate cancel/replace/add-separate handling, account edit/order/favourite/delete operations, and explicit deletion warning
- Shared one-second countdown timer with code regeneration only at a TOTP step boundary
- Clock-jump warning without network time synchronization
- Version-1 DPAPI `CurrentUser` local vault with complete-payload encryption, versioned envelope, ciphertext hash, atomic replacement, encrypted previous copy, and restricted final-file ACL
- Transactional clone-and-commit vault mutations that retain the preceding live set on save failure, enter `Faulted`, and support reload from the last persisted state
- Vault state machine and best-effort mutable secret-buffer clearing on lock, delete, failure, replacement, and exit
- Inactivity, minimise, Windows session-lock, suspend, and explicit locking paths
- Optional Windows user-verification gates with DPAPI fallback when the OS capability is unavailable
- OTP-only clipboard copy, clipboard history/roaming suppression, independent delayed-clear cancellation, fresh random custom-format ownership markers, and immediate conditional clearing on lock/exit
- Version-1 portable `.pab` backups using PBKDF2-HMAC-SHA-512 with 600,000 iterations and AES-256-GCM with authenticated metadata
- Explicit atomic backup overwrite without destination pre-delete
- Four whole-import backup policies: merge/skip, merge/replace matches, merge/keep duplicates, and exact replacement preserving intentional duplicates
- Off-UI-thread PBKDF2/AES/JSON/QR continuations with cancellation checkpoints
- Strict malformed-percent/empty-parameter handling, bounded non-seekable QR input, serializer cleanup hardening, and overflow-safe backup-length validation
- Non-sensitive JSON settings stored separately from the encrypted vault
- Source-generated structured logging policy without application telemetry, remote logging, or secret fields
- Central package version management, nullable reference types, warnings as errors, analyzers, deterministic builds, and formatting configuration
- Application icon assets and x64/ARM64 self-contained project configuration
- Aggregate `Microsoft.WindowsAppSDK` 2.3.1 dependency, centrally pinned transitive WinUI 2.3.2 servicing build, and a third-party notice copied into build/publish output with the component-licence caveat
- Repeatable x64/ARM64 publish script that validates the executable, legal notice, application PRI, and required WinUI XBF resources
- Core, Infrastructure, security-regression, and ViewModel test suites
- Architecture, threat model, backup format, dependency/licence, build, test, run, and publish documentation

### Observed verification

- `dotnet restore` passed.
- `dotnet build --configuration Release` passed.
- 34 PersonalAuthenticator.Core.Tests tests passed.
- 36 PersonalAuthenticator.Infrastructure.Tests/ViewModel tests passed.
- 70 tests passed in total.
- `dotnet format --verify-no-changes` passed.
- Self-contained x64 and ARM64 publish scripts succeeded.
- Both publish folders passed checks for the executable, non-empty legal notice, application PRI, and required App/MainWindow/dialog XBF files.
- The published Release x64 application launched, rendered, remained responsive, and produced a verified screenshot.
- The monitored published x64 process owned zero TCP and zero UDP endpoints.

These are prior observed results, not a substitute for re-running validation on the release commit.

### Release blockers and known issues

- Exhaustive manual security-workflow validation should be repeated on the release commit.
- Clean-machine self-contained deployment has not been verified.
- ARM64 execution has not been verified.
- No packaged MSIX option, installer, signing workflow, or update mechanism exists; the project is unpackaged (`WindowsPackageType=None`).
- Backup restore has four whole-import policies but no per-account conflict report.
- PBKDF2 cannot be interrupted mid-derivation and has no progress/cancel UI, although CPU work is off the UI thread and surrounding cancellation checkpoints are present.
- The retained encrypted previous vault has no automatic recovery UI.
- The aggregate Windows App SDK redistribution terms and the resolved WinUI 2.3.2 component's conflicting “Engineering Preview” terms require legal clarification before external distribution.

Version 1.0.0 must not be dated or marked released until the remaining deployment, signing/licence, ARM64-execution, manual security-workflow, and recovery checks are resolved on the release commit.
