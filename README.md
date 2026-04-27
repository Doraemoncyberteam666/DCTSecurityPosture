# DCT Security Posture

Kotlin Android demo app that shows a checklist-style device/app security posture screen.

## Included checks

### Level 1 — baseline posture

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

### Level 2 — anti-bypass + native cross-checks

Hardened detections that run from a JNI-loaded native library
(`libdctnative.so`) and from defensive Java paths designed to be harder to
silently flip with a single hook on `java.io.File`,
`android.os.SystemProperties`, or `Settings.Global`.

- Magisk / zygisk overlay mount detection (`/proc/self/mounts`,
  `/proc/mounts`, tmpfs over `/system|/vendor|/product`, `/data/adb` mounts)
- Bootloader / verity policy (`ro.boot.flash.locked`,
  `ro.boot.veritymode`, `ro.boot.vbmeta.device_state`,
  `ro.boot.verifiedbootstate`, warranty bit)
- Process identity (`applicationId` vs `/proc/self/cmdline`) and
  Java↔native cmdline cross-check
- Suspicious thread names from `/proc/self/task/<tid>/comm`
  (`gum-js-loop`, `gmain`, `gdbus`, `pool-frida-*`)
- Loaded library scan for `libfrida-agent`, `libfrida-gadget`,
  `libxposed`, `liblsposed`, `libsubstrate`, `libedxp`, `libriru`,
  `libzygisk`, `linjector`
- Runtime UID integrity (`Process.myUid` vs `ApplicationInfo.uid`)
- Native presence — `libdctnative.so` must be loaded; missing/stripped
  ABIs are themselves a tamper signal
- Native `TracerPid` read via raw `open(2)`/`read(2)` syscalls,
  cross-checked against the Java reading
- Native ptrace self-attach via `fork(2)` + `PTRACE_ATTACH` to detect
  an existing tracer
- Native `/proc/self/maps` indicator scan with XOR-obfuscated needles
  (`frida`, `gum-js-loop`, `frida-agent`, `frida-gadget`,
  `frida-server`, `xposed`, `lsposed`, `substrate`, `edxp`, `riru`,
  `zygisk`, `linjector`, `magisk`)
- Native `/proc/self/task/*/comm` thread-name scan
- Native SELinux enforce read from `/sys/fs/selinux/enforce`
- Native suspicious mounts scan
- Native APK path consistency — `/proc/self/maps` `base.apk` path must
  match `ApplicationInfo.sourceDir`
- Native timing watchdog — tight loop median runtime should stay within
  envelope; degradation flags inline hooks
- Layered `getprop` reads — native `__system_property_get` first,
  then Java reflection, then `getprop(1)` fallback

The native module is built for `armeabi-v7a`, `arm64-v8a`, `x86`, and
`x86_64` and is linked with `-fvisibility=hidden`, `-fno-rtti`,
`-fno-exceptions`, `--gc-sections`, RELRO + BIND_NOW, and a
non-executable stack. Indicator strings are XOR-encoded at compile
time so `strings(1)` on the `.so` does not reveal the watch list.

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
