# DCT Security Posture

Kotlin Android demo app that shows a checklist-style device/app security posture screen.

## Included checks

- Root binary detection
- Dangerous Android system properties
- Known root manager packages
- VM / emulator build fingerprint detection
- VM / emulator filesystem marker detection
- ADB enabled detection
- Runtime debugger detection
- App debuggable flag detection
- APK signature SHA-256 tamper baseline
- Install source / installer package detection
- Google Play services visibility
- Xposed / LSPosed / Substrate style framework indicators
- Cleartext HTTP traffic policy
- `allowBackup` policy
- Private app data directory writability
- Play Integrity client availability

## Build

```bash
cd DCTSecurityPosture
./gradlew assembleDebug
```

If you do not have a Gradle wrapper, build with your installed Gradle:

```bash
gradle assembleDebug
```

## Signature baseline

Build once, install/run, then copy the current SHA-256 shown under `Signature integrity` into:

```kotlin
private const val EXPECTED_RELEASE_SHA256 = "AA:BB:CC:..."
```

For production, use your **release signing certificate** SHA-256, not the debug cert.

## Install-source notes

Android 11+ uses `PackageManager.getInstallSourceInfo(packageName)`. Older versions fall back to `getInstallerPackageName(packageName)`.

Common installer packages:

```text
com.android.vending              Google Play Store
com.sec.android.app.samsungapps  Samsung Galaxy Store
com.amazon.venezia               Amazon Appstore
null / unknown                   Sideload, adb, or hidden/unavailable source
```

## Play Integrity

SafetyNet Attestation is deprecated/replaced by Play Integrity. This project includes `PlayIntegrity.kt` for the client token request, but the real verdict must be decoded and verified server-side using a server-generated nonce.

Do not treat the on-device token request itself as a trusted verdict.

## GitHub Actions build artifact

This project includes `.github/workflows/ci.yml`.

It builds the debug APK on:

- push to `main` or `master`
- pull request to `main` or `master`
- manual `workflow_dispatch`

Artifact path after CI:

```text
Actions → Android CI → latest run → Artifacts → DCTSecurityPosture-debug-apk
```

Local equivalent:

```bash
gradle :app:assembleDebug --stacktrace
```
