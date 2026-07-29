# Personal Authenticator for Android

Android companion for the Windows v2 Personal Authenticator. The application is
local-first, remains usable without a network connection, and will only join an
already-existing encrypted GitHub sync generation.

## Fixed build contract

- Application ID: `com.tester4real.personalauthenticator`
- Kotlin with Jetpack Compose and Material 3
- Minimum SDK: API 28
- Compile/target SDK: API 37 (current stable Android SDK in July 2026)
- Required device coverage includes API 28, 34, and 36
- Gradle 9.5.0 and Android Gradle Plugin 9.3.1
- All plugin and library versions are pinned in `gradle/libs.versions.toml`

AGP 9.3.1 officially defaults to Gradle 9.5.0 and embeds Kotlin 2.2.10. The
Compose compiler plugin intentionally matches that embedded Kotlin version even
though newer standalone Gradle/Kotlin releases exist.

The project modules are `:app`, `:domain`, `:vault`, `:sync`, and `:scanner`.

## Local build

Use Android Studio's bundled JDK 21:

```powershell
cd android
.\gradlew.bat test assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.
Release signing material is intentionally absent from the repository.

## Security foundation

The current foundation includes strict TOTP parsing/generation, RFC 6238 test
vectors, numeric 4–8 digit PIN policy, a non-exportable Android Keystore HMAC
key, Argon2id (64 MiB, 3 iterations, parallelism 2), AES-256-GCM wrapping of
independent SQLCipher and vault-root keys, atomic two-slot envelope storage,
persistent exponential retry delay, process/screen-off/background lock rules,
SQLCipher/Room storage under no-backup files, and a schema for immutable
operations, causal state, conflicts, outbox, staging, and Git health.

No GitHub token, PIN, sync password, signing key, production OTP seed, or
production repository data is present in source or test assets.
