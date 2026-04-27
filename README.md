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
- Developer options enabled detection
- Tracer PID / ptrace detection
- App debuggable flag detection
- APK signature SHA-256 tamper baseline
- Suspicious sensitive permissions requested by app
- Known Frida server port scan
- Install source / installer package detection
- Xposed / LSPosed / Substrate style framework indicators
- Suspicious process memory map indicators (Frida/Xposed/Substrate)
- Verified boot property validation
- SELinux permissive mode indicators
- Writable `/system`/`/vendor` mount indicators
- Cleartext HTTP traffic policy
- `allowBackup` policy
- Private app data directory writability

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

## Custom integrity baseline

This app intentionally does **not** use Google Play Integrity. It uses a custom local baseline approach that includes:

- hard-coded release certificate SHA-256 matching
- install source trust checks
- boot state / SELinux / root / instrumentation indicators

Configured signing baseline:

```text
42:3E:15:F5:0C:27:D6:F6:AE:B8:32:BF:EF:8E:82:B7:7B:5C:F4:BD:D3:87:83:29:99:F6:F6:F1:18:E9:A5:F3
```

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
