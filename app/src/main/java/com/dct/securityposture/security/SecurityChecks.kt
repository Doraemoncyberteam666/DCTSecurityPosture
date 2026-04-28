package com.dct.securityposture.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.os.Process
import android.provider.Settings
import com.dct.securityposture.model.SecurityCheck
import com.dct.securityposture.model.Severity
import com.dct.securityposture.obf.V
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.security.MessageDigest
import java.util.Locale

object SecurityChecks {
    private const val EXPECTED_RELEASE_SHA256 = "42:3E:15:F5:0C:27:D6:F6:AE:B8:32:BF:EF:8E:82:B7:7B:5C:F4:BD:D3:87:83:29:99:F6:F6:F1:18:E9:A5:F3"

    fun runAll(context: Context): List<SecurityCheck> = listOf(
        rootBinaryCheck(),
        dangerousPropsCheck(),
        rootManagementAppsCheck(context),
        emulatorBuildCheck(),
        emulatorFilesCheck(),
        adbEnabledCheck(context),
        developerOptionsCheck(context),
        debuggerAttachedCheck(),
        tracerPidCheck(),
        appDebuggableFlagCheck(context),
        signatureIntegrityCheck(context),
        suspiciousRuntimePermissionsCheck(context),
        fridaPortCheck(),
        installerSourceCheck(context),
        hookingFrameworkCheck(context),
        suspiciousProcessMapsCheck(),
        verifiedBootCheck(),
        selinuxEnforcingCheck(),
        suspiciousMountsCheck(),
        cleartextTrafficPolicyCheck(context),
        allowBackupCheck(context),
        appDataDirWritableCheck(context),
        // ---------------- Level-2 anti-bypass checks (hardened Java side) ----------------
        magiskMountsCheck(),
        bootloaderUnlockCheck(),
        processIdentityCheck(context),
        processCmdlineCheck(context),
        suspiciousThreadNamesCheck(),
        suspiciousLoadedLibrariesCheck(),
        runtimeUidIntegrityCheck(context),
        // ---------------- Level-2 native (JNI) cross-checks ------------------------------
        nativeLibPresenceCheck(),
        nativeTracerPidCheck(),
        nativePtraceAttachCheck(),
        nativeMapsIndicatorsCheck(),
        nativeThreadIndicatorsCheck(),
        nativeSelinuxEnforceCheck(),
        nativeSuspiciousMountsCheck(),
        nativeApkPathConsistencyCheck(context),
        nativeTimingHookCheck()
    )

    private fun pass(title: String, summary: String, details: String, category: String, severity: Severity = Severity.INFO) =
        SecurityCheck(title, true, severity, summary, details, category)

    private fun fail(title: String, summary: String, details: String, category: String, severity: Severity) =
        SecurityCheck(title, false, severity, summary, details, category)

    private fun rootBinaryCheck(): SecurityCheck {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
            "/su/bin/su", "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
            "/system/app/Superuser.apk", "/system/bin/busybox", "/system/xbin/busybox"
        )
        val hits = paths.filter { File(it).exists() }
        return if (hits.isEmpty()) pass("Root binaries", "No common su/busybox paths found", "Checked ${paths.size} common root binary locations.", "Root")
        else fail("Root binaries", "Root artifacts found", hits.joinToString("\n"), "Root", Severity.CRITICAL)
    }

    private fun dangerousPropsCheck(): SecurityCheck {
        val props = mapOf(
            V.s(V.RO_DEBUGGABLE) to "0",
            V.s(V.RO_SECURE) to "1",
            V.s(V.SERVICE_ADB_ROOT) to "0",
            V.s(V.RO_BUILD_TAGS) to "release-keys"
        )
        val bad = mutableListOf<String>()
        val observed = mutableListOf<String>()
        val buildTagsKey = V.s(V.RO_BUILD_TAGS)
        for ((key, expected) in props) {
            val value = getProp(key)
            observed += "$key=$value"
            if (key == buildTagsKey) {
                if (value.contains("test-keys", ignoreCase = true)) bad += "$key=$value"
            } else if (value.isNotBlank() && value != expected) bad += "$key=$value expected=$expected"
        }
        return if (bad.isEmpty()) pass("System properties", "No dangerous root/debug properties", observed.joinToString("\n"), "Root")
        else fail("System properties", "Suspicious system properties", bad.joinToString("\n"), "Root", Severity.HIGH)
    }

    private fun rootManagementAppsCheck(context: Context): SecurityCheck {
        val packages = listOf(
            V.s(V.COM_TOPJOHNWU_MAGISK),
            V.s(V.EU_CHAINFIRE_SUPERSU),
            V.s(V.COM_KOUSHIKDUTTA_SUPERUSER),
            V.s(V.COM_NOSHUFOU_ANDROID_SU),
            V.s(V.COM_THIRDPARTY_SUPERUSER),
            V.s(V.IO_GITHUB_VVB2060_MAGISK)
        )
        val hits = packages.filter { isPackageInstalled(context, it) }
        return if (hits.isEmpty()) pass("Root manager apps", "No known root manager packages visible", packages.joinToString("\n"), "Root")
        else fail("Root manager apps", "Known root manager package visible", hits.joinToString("\n"), "Root", Severity.HIGH)
    }

    private fun emulatorBuildCheck(): SecurityCheck {
        val fields = mapOf(
            "fingerprint" to Build.FINGERPRINT,
            "model" to Build.MODEL,
            "manufacturer" to Build.MANUFACTURER,
            "brand" to Build.BRAND,
            "device" to Build.DEVICE,
            "product" to Build.PRODUCT,
            "hardware" to Build.HARDWARE,
            "board" to Build.BOARD,
            "bootloader" to Build.BOOTLOADER,
            "host" to Build.HOST
        )
        val blob = fields.values.joinToString(" ").lowercase(Locale.US)
        val indicators = listOf(
            "generic", "sdk_gphone", "google_sdk", "emulator", "android sdk built for x86",
            "goldfish", "ranchu", "vbox", "nox", "genymotion", "bluestacks", "qemu"
        )
        val hits = indicators.filter { blob.contains(it) }
        val details = fields.entries.joinToString("\n") { "${it.key}=${it.value}" }
        return if (hits.isEmpty()) pass("VM / emulator build", "No emulator build indicators", details, "Runtime")
        else fail("VM / emulator build", "Emulator indicators: ${hits.joinToString()}", details, "Runtime", Severity.HIGH)
    }

    private fun emulatorFilesCheck(): SecurityCheck {
        val paths = listOf(
            "/dev/qemu_pipe", "/dev/qemu_trace", "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/system/bin/qemu-props", "/dev/socket/qemud",
            "/system/bin/nox-prop", "/system/bin/androVM-prop"
        )
        val hits = paths.filter { File(it).exists() }
        return if (hits.isEmpty()) pass("VM / emulator files", "No emulator filesystem markers", paths.joinToString("\n"), "Runtime")
        else fail("VM / emulator files", "Emulator files found", hits.joinToString("\n"), "Runtime", Severity.HIGH)
    }

    private fun adbEnabledCheck(context: Context): SecurityCheck {
        val enabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) { false }
        return if (!enabled) pass("ADB state", "ADB disabled", "Settings.Global.ADB_ENABLED=0", "Debug")
        else fail("ADB state", "ADB enabled", "Settings.Global.ADB_ENABLED=1", "Debug", Severity.MEDIUM)
    }

    private fun debuggerAttachedCheck(): SecurityCheck {
        val waiting = Debug.waitingForDebugger()
        val connected = Debug.isDebuggerConnected()
        return if (!waiting && !connected) pass("Debugger", "No debugger attached", "isDebuggerConnected=false\nwaitingForDebugger=false", "Debug")
        else fail("Debugger", "Debugger detected", "isDebuggerConnected=$connected\nwaitingForDebugger=$waiting", "Debug", Severity.HIGH)
    }

    private fun appDebuggableFlagCheck(context: Context): SecurityCheck {
        val debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        return if (!debuggable) pass("App debuggable flag", "Release-style non-debuggable app", "ApplicationInfo.FLAG_DEBUGGABLE=false", "Debug")
        else fail("App debuggable flag", "Application is debuggable", "ApplicationInfo.FLAG_DEBUGGABLE=true", "Debug", Severity.MEDIUM)
    }

    private fun signatureIntegrityCheck(context: Context): SecurityCheck {
        val current = signingSha256(context)
        val expected = EXPECTED_RELEASE_SHA256.trim()
        val configured = expected.isNotBlank() && !expected.startsWith("PUT_")
        if (!configured) {
            return SecurityCheck(
                "Signature integrity",
                true,
                Severity.INFO,
                "Baseline not configured",
                "Current signing certificate SHA-256:\n$current\n\nSet EXPECTED_RELEASE_SHA256 in SecurityChecks.kt to enforce tamper detection.",
                "Integrity"
            )
        }
        return if (current.equals(expected, ignoreCase = true)) pass("Signature integrity", "Signature matches expected release cert", current, "Integrity")
        else fail("Signature integrity", "APK signature mismatch", "current=$current\nexpected=$expected", "Integrity", Severity.CRITICAL)
    }

    @Suppress("DEPRECATION")
    private fun installerSourceCheck(context: Context): SecurityCheck {
        val pm = context.packageManager
        val packageName = context.packageName
        val details = StringBuilder()
        var initiating: String? = null
        var installing: String? = null
        var originating: String? = null

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val source = pm.getInstallSourceInfo(packageName)
            initiating = source.initiatingPackageName
            installing = source.installingPackageName
            originating = source.originatingPackageName
            details.appendLine("initiatingPackageName=$initiating")
            details.appendLine("installingPackageName=$installing")
            details.appendLine("originatingPackageName=$originating")
        } else {
            installing = pm.getInstallerPackageName(packageName)
            details.appendLine("installerPackageName=$installing")
        }

        val installer = installing ?: initiating ?: originating
        val trustedStores = setOf(
            "com.android.vending",      // Google Play Store
            "com.google.android.feedback",
            "com.sec.android.app.samsungapps", // Galaxy Store
            "com.amazon.venezia"        // Amazon Appstore
        )
        val ok = installer in trustedStores
        val label = installer?.let { packageLabel(context, it) } ?: "Unknown / sideload / adb"
        details.appendLine("resolved=$installer")
        details.appendLine("label=$label")
        return if (ok) pass("Install source", "Installed by trusted store: $label", details.toString(), "Integrity")
        else fail("Install source", "Untrusted or unknown install source: $label", details.toString(), "Integrity", Severity.MEDIUM)
    }

    private fun developerOptionsCheck(context: Context): SecurityCheck {
        val enabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Throwable) { false }
        return if (!enabled) pass("Developer options", "Developer options disabled", "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED=0", "Debug")
        else fail("Developer options", "Developer options enabled", "Settings.Global.DEVELOPMENT_SETTINGS_ENABLED=1", "Debug", Severity.MEDIUM)
    }

    private fun tracerPidCheck(): SecurityCheck {
        val tracerKey = V.s(V.TRACERPID)
        val value = try {
            File(V.s(V.PROC_SELF_STATUS)).readLines()
                .firstOrNull { it.startsWith(tracerKey) }
                ?.substringAfter(":")
                ?.trim()
                ?.toIntOrNull() ?: 0
        } catch (_: Throwable) { 0 }
        return if (value == 0) pass("Tracer PID", "No ptrace tracer attached", "TracerPid=0", "Debug")
        else fail("Tracer PID", "Process is being traced", "TracerPid=$value", "Debug", Severity.HIGH)
    }

    private fun suspiciousRuntimePermissionsCheck(context: Context): SecurityCheck {
        val suspicious = listOf(
            android.Manifest.permission.READ_LOGS,
            android.Manifest.permission.WRITE_SECURE_SETTINGS,
            android.Manifest.permission.QUERY_ALL_PACKAGES
        )
        val requested = try {
            val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
            info.requestedPermissions?.toList().orEmpty()
        } catch (_: Throwable) { emptyList() }
        val hits = requested.intersect(suspicious.toSet())
        return if (hits.isEmpty()) pass("Sensitive permissions", "No high-risk debug/tamper permissions requested", requested.sorted().joinToString("\n"), "Config")
        else fail("Sensitive permissions", "High-risk permissions requested", hits.joinToString("\n"), "Config", Severity.MEDIUM)
    }

    private fun fridaPortCheck(): SecurityCheck {
        val ports = listOf(23946, 27042, 27043)
        val hits = ports.filter { portOpenLocalhost(it) }
        return if (hits.isEmpty()) pass("Frida ports", "No known Frida server ports open", ports.joinToString(", "), "Runtime")
        else fail("Frida ports", "Known dynamic instrumentation port open", hits.joinToString(", "), "Runtime", Severity.CRITICAL)
    }

    private fun hookingFrameworkCheck(context: Context): SecurityCheck {
        val packages = listOf(
            V.s(V.DE_ROBV_ANDROID_XPOSED_INSTALLER),
            V.s(V.ORG_LSPOSED_MANAGER),
            V.s(V.IO_GITHUB_VVB2060_MAGISK),
            V.s(V.COM_SAURIK_SUBSTRATE),
            V.s(V.COM_ZACHSPONG_TEMPROOTREMOVEJB),
            V.s(V.COM_DEVADVANCE_ROOTCLOAK)
        )
        val visible = packages.filter { isPackageInstalled(context, it) }
        val frameworkNeedles = listOf(V.s(V.XPOSED), V.s(V.SUBSTRATE), V.s(V.LSPOSED))
        val stackHit = Throwable().stackTrace.any { frame ->
            val name = frame.className.lowercase(Locale.US)
            frameworkNeedles.any { name.contains(it) }
        }
        val details = buildString {
            appendLine("visiblePackages=${visible.ifEmpty { listOf("none") }.joinToString()}")
            appendLine("stackHookIndicator=$stackHit")
        }
        return if (visible.isEmpty() && !stackHit) pass("Hooking frameworks", "No visible hooking framework indicators", details, "Runtime")
        else fail("Hooking frameworks", "Hooking/runtime instrumentation indicators found", details, "Runtime", Severity.HIGH)
    }

    private fun suspiciousProcessMapsCheck(): SecurityCheck {
        val indicators = listOf(
            V.s(V.FRIDA),
            V.s(V.GUM_JS_LOOP),
            V.s(V.XPOSED),
            V.s(V.SUBSTRATE),
            V.s(V.EDXP)
        )
        val hits = try {
            File(V.s(V.PROC_SELF_MAPS)).readText().lowercase(Locale.US).let { maps ->
                indicators.filter { maps.contains(it) }
            }
        } catch (_: Throwable) { emptyList() }
        return if (hits.isEmpty()) pass("Process maps", "No suspicious hooking libs in memory map", indicators.joinToString(", "), "Runtime")
        else fail("Process maps", "Suspicious in-memory artifacts detected", hits.joinToString(", "), "Runtime", Severity.CRITICAL)
    }

    private fun verifiedBootCheck(): SecurityCheck {
        val state = getProp(V.s(V.RO_BOOT_VERIFIEDBOOTSTATE)).ifBlank { "unknown" }.lowercase(Locale.US)
        val mode = getProp(V.s(V.RO_BOOT_FLASH_LOCKED)).ifBlank { "unknown" }
        val details = "verifiedbootstate=$state\nflash.locked=$mode"
        val ok = state == "green" || state == "unknown"
        return if (ok) pass("Verified boot", "Boot state not flagged as compromised", details, "Integrity")
        else fail("Verified boot", "Boot state indicates reduced trust", details, "Integrity", Severity.HIGH)
    }

    private fun selinuxEnforcingCheck(): SecurityCheck {
        val value = getProp(V.s(V.RO_BUILD_SELINUX)).ifBlank { "unknown" }
        val enforce = getProp(V.s(V.RO_BOOT_SELINUX)).ifBlank { "unknown" }
        val details = "ro.build.selinux=$value\nro.boot.selinux=$enforce"
        val risky = listOf(value, enforce).any { it.contains("permissive", ignoreCase = true) || it == "0" }
        return if (!risky) pass("SELinux mode", "No permissive SELinux indicator", details, "Runtime")
        else fail("SELinux mode", "Permissive SELinux indicator found", details, "Runtime", Severity.HIGH)
    }

    private fun suspiciousMountsCheck(): SecurityCheck {
        val mountsPath = V.s(V.PROC_MOUNTS)
        val lines = try { File(mountsPath).readLines() } catch (_: Throwable) { emptyList() }
        val hits = lines.filter { line ->
            (line.contains(" /system ") || line.contains(" /vendor ")) &&
                line.contains(" rw,")
        }
        return if (hits.isEmpty()) pass("Readonly partitions", "No writable system/vendor mount marker", "checked=$mountsPath", "Root")
        else fail("Readonly partitions", "System partition mounted read-write", hits.take(5).joinToString("\n"), "Root", Severity.HIGH)
    }

    private fun cleartextTrafficPolicyCheck(context: Context): SecurityCheck {
        val permitted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            android.security.NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted
        } else false
        return if (!permitted) pass("Cleartext traffic", "HTTP cleartext blocked", "NetworkSecurityPolicy.isCleartextTrafficPermitted=false", "Config")
        else fail("Cleartext traffic", "HTTP cleartext permitted", "NetworkSecurityPolicy.isCleartextTrafficPermitted=true", "Config", Severity.MEDIUM)
    }

    private fun allowBackupCheck(context: Context): SecurityCheck {
        val allowed = (context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0
        return if (!allowed) pass("Backup policy", "allowBackup disabled", "ApplicationInfo.FLAG_ALLOW_BACKUP=false", "Config")
        else fail("Backup policy", "allowBackup enabled", "ApplicationInfo.FLAG_ALLOW_BACKUP=true", "Config", Severity.LOW)
    }

    private fun appDataDirWritableCheck(context: Context): SecurityCheck {
        val dir = context.filesDir
        val ok = dir.canWrite()
        return if (ok) pass("App private storage", "Private files dir writable", dir.absolutePath, "Config")
        else fail("App private storage", "Private files dir is not writable", dir.absolutePath, "Config", Severity.MEDIUM)
    }

    // ---------------------------------------------------------------------------------------
    // Level-2 hardened Java-side checks. These complement the existing posture checks with
    // signals that are harder to fake from a single point hook.
    // ---------------------------------------------------------------------------------------

    private fun magiskMountsCheck(): SecurityCheck {
        val candidates = listOf(V.s(V.PROC_SELF_MOUNTS), V.s(V.PROC_MOUNTS))
        val magiskNeedle = V.s(V.MAGISK)
        val dataAdbNeedle = V.s(V.DATA_ADB)
        val hits = mutableListOf<String>()
        for (path in candidates) {
            val lines = try { File(path).readLines() } catch (_: Throwable) { continue }
            for (line in lines) {
                val l = line.lowercase(Locale.US)
                val isMagiskOverlay = l.contains(magiskNeedle) || l.contains(dataAdbNeedle)
                val isTmpfsOverSystem = l.contains("tmpfs") &&
                    (l.contains(" /system ") || l.contains(" /vendor ") || l.contains(" /product "))
                if (isMagiskOverlay || isTmpfsOverSystem) hits += line
            }
            if (hits.isNotEmpty()) break
        }
        return if (hits.isEmpty()) pass("Magisk mount overlay", "No magisk-style overlay mounts detected", candidates.joinToString("\n"), "Root")
        else fail("Magisk mount overlay", "Magisk/zygisk-style overlay mount detected", hits.take(5).joinToString("\n"), "Root", Severity.CRITICAL)
    }

    private fun bootloaderUnlockCheck(): SecurityCheck {
        val flashLockedKey = V.s(V.RO_BOOT_FLASH_LOCKED)
        val verityKey = V.s(V.RO_BOOT_VERITYMODE)
        val vbmetaKey = V.s(V.RO_BOOT_VBMETA_DEVICE_STATE)
        val warrantyKey = V.s(V.RO_BOOT_WARRANTY_BIT)
        val warrantyKey2 = V.s(V.RO_WARRANTY_BIT)
        val verifiedBootKey = V.s(V.RO_BOOT_VERIFIEDBOOTSTATE)
        val keys = listOf(flashLockedKey, verityKey, vbmetaKey, warrantyKey, warrantyKey2, verifiedBootKey)
        val observed = mutableMapOf<String, String>()
        for (key in keys) observed[key] = getProp(key).ifBlank { "unknown" }
        val locked = observed[flashLockedKey]?.trim() ?: "unknown"
        val vbState = observed[vbmetaKey]?.lowercase(Locale.US) ?: "unknown"
        val verityMode = observed[verityKey]?.lowercase(Locale.US) ?: "unknown"
        val vbState2 = observed[verifiedBootKey]?.lowercase(Locale.US) ?: "unknown"
        val warranty = (observed[warrantyKey] ?: "") + (observed[warrantyKey2] ?: "")
        val problems = mutableListOf<String>()
        if (locked == "0") problems += "flash.locked=0"
        if (vbState == "unlocked") problems += "vbmeta.device_state=unlocked"
        if (verityMode == "disabled" || verityMode == "logging") problems += "veritymode=$verityMode"
        if (vbState2 == "orange" || vbState2 == "red") problems += "verifiedbootstate=$vbState2"
        if (warranty.contains("1")) problems += "warranty_bit set"
        val details = observed.entries.joinToString("\n") { "${it.key}=${it.value}" }
        return if (problems.isEmpty()) pass("Bootloader / verity", "Bootloader locked & verity enforced", details, "Integrity")
        else fail("Bootloader / verity", "Bootloader/verity weakened", "$details\n\nproblems=${problems.joinToString()}", "Integrity", Severity.HIGH)
    }

    private fun processIdentityCheck(context: Context): SecurityCheck {
        val expectedPkg = context.packageName
        val cmdline = try {
            File(V.s(V.PROC_SELF_CMDLINE)).readBytes()
                .takeWhile { it != 0.toByte() }
                .toByteArray()
                .toString(Charsets.UTF_8)
        } catch (_: Throwable) { "" }
        val processName = cmdline.substringBefore(':').trim()
        val ok = processName == expectedPkg || cmdline.startsWith(expectedPkg)
        val details = "applicationId=$expectedPkg\ncmdline=$cmdline"
        return if (ok) pass("Process identity", "cmdline matches applicationId", details, "Integrity")
        else fail("Process identity", "cmdline does not match applicationId", details, "Integrity", Severity.HIGH)
    }

    private fun processCmdlineCheck(context: Context): SecurityCheck {
        val javaCmd = try { File(V.s(V.PROC_SELF_CMDLINE)).readText().replace('\u0000', ' ').trim() } catch (_: Throwable) { "" }
        val nativeCmd = if (NativeChecks.available()) NativeChecks.nativeProcCmdline() else ""
        val agree = javaCmd.isNotBlank() && nativeCmd.isNotBlank() && javaCmd.startsWith(nativeCmd.substringBefore(' ').trim())
        val details = "java=$javaCmd\nnative=$nativeCmd"
        return if (NativeChecks.available() && !agree) {
            fail("Cmdline cross-check", "Java vs native cmdline disagree", details, "Integrity", Severity.HIGH)
        } else if (javaCmd.isBlank()) {
            fail("Cmdline cross-check", "/proc/self/cmdline unreadable", details, "Integrity", Severity.MEDIUM)
        } else {
            pass("Cmdline cross-check", "Java/native cmdline match", details, "Integrity")
        }
    }

    private fun suspiciousThreadNamesCheck(): SecurityCheck {
        val needles = listOf(
            V.s(V.GUM_JS_LOOP),
            V.s(V.GMAIN),
            V.s(V.GDBUS),
            V.s(V.POOL_FRIDA),
            V.s(V.FRIDA)
        )
        val taskRoot = File(V.s(V.PROC_SELF_TASK))
        val children = try { taskRoot.listFiles()?.toList().orEmpty() } catch (_: Throwable) { emptyList() }
        val hits = mutableSetOf<String>()
        for (tid in children) {
            val comm = try { File(tid, "comm").readText().trim().lowercase(Locale.US) } catch (_: Throwable) { continue }
            for (n in needles) if (comm.contains(n)) hits += "${tid.name}=$comm"
        }
        return if (hits.isEmpty()) pass("Thread names", "No frida/xposed-style thread names", "sampled=${children.size}", "Runtime")
        else fail("Thread names", "Suspicious thread names present", hits.joinToString("\n"), "Runtime", Severity.CRITICAL)
    }

    private fun suspiciousLoadedLibrariesCheck(): SecurityCheck {
        val maps = try { File(V.s(V.PROC_SELF_MAPS)).readText() } catch (_: Throwable) { "" }
        val needles = listOf(
            V.s(V.LIBFRIDA_AGENT),
            V.s(V.LIBFRIDA_GADGET),
            V.s(V.FRIDA_SERVER),
            V.s(V.LIBXPOSED),
            V.s(V.LIBLSPOSED),
            V.s(V.LIBSUBSTRATE),
            V.s(V.LIBEDXP),
            V.s(V.LIBRIRU),
            V.s(V.LIBZYGISK),
            V.s(V.LINJECTOR)
        )
        val hits = needles.filter { maps.contains(it, ignoreCase = true) }
        return if (hits.isEmpty()) pass("Loaded library scan", "No instrumentation libraries mapped", "checked=${needles.size}", "Runtime")
        else fail("Loaded library scan", "Instrumentation libraries mapped into the process", hits.joinToString(", "), "Runtime", Severity.CRITICAL)
    }

    private fun runtimeUidIntegrityCheck(context: Context): SecurityCheck {
        val processUid = Process.myUid()
        val appUid = context.applicationInfo.uid
        val ok = processUid == appUid
        val details = "Process.myUid=$processUid\nApplicationInfo.uid=$appUid"
        return if (ok) pass("Runtime UID", "Process UID matches application UID", details, "Integrity")
        else fail("Runtime UID", "Process UID does not match application UID", details, "Integrity", Severity.HIGH)
    }

    // ---------------------------------------------------------------------------------------
    // Level-2 native cross-checks. Native variants read /proc and system properties via raw
    // syscalls, so single-point Java hooks (java.io.File, SystemProperties, Settings.Global)
    // cannot silently flip the result.
    // ---------------------------------------------------------------------------------------

    private fun nativeLibPresenceCheck(): SecurityCheck {
        val ok = NativeChecks.available()
        val details = "libdctnative.so loaded=$ok"
        return if (ok) pass("Native lib presence", "libdctnative.so loaded", details, "Integrity")
        else fail("Native lib presence", "libdctnative.so missing or stripped from APK", details, "Integrity", Severity.HIGH)
    }

    private fun nativeTracerPidCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native TracerPid", "Debug")
        val tracer = NativeChecks.nativeTracerPid()
        val tracerKey = V.s(V.TRACERPID)
        val javaTracer = try {
            File(V.s(V.PROC_SELF_STATUS)).readLines()
                .firstOrNull { it.startsWith(tracerKey) }
                ?.substringAfter(":")
                ?.trim()
                ?.toIntOrNull() ?: 0
        } catch (_: Throwable) { 0 }
        val details = "native=$tracer\njava=$javaTracer"
        return when {
            tracer < 0 -> fail("Native TracerPid", "Native /proc/self/status unreadable", details, "Debug", Severity.MEDIUM)
            tracer != javaTracer -> fail("Native TracerPid", "Java vs native TracerPid disagree", details, "Debug", Severity.CRITICAL)
            tracer != 0 -> fail("Native TracerPid", "Native confirms ptrace tracer attached", details, "Debug", Severity.HIGH)
            else -> pass("Native TracerPid", "Native confirms no tracer attached", details, "Debug")
        }
    }

    private fun nativePtraceAttachCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native ptrace attach", "Debug")
        val r = try { NativeChecks.nativePtraceSelfAttach() } catch (_: Throwable) { -1 }
        val details = "result=$r (0=clean, 1=tracer-present, -1=inconclusive)"
        return when (r) {
            0 -> pass("Native ptrace attach", "Self-attach succeeded - no other tracer", details, "Debug")
            1 -> fail("Native ptrace attach", "Self-attach refused - debugger present", details, "Debug", Severity.HIGH)
            else -> SecurityCheck("Native ptrace attach", true, Severity.INFO, "Inconclusive", details, "Debug")
        }
    }

    private fun nativeMapsIndicatorsCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native maps scan", "Runtime")
        val hits = NativeChecks.nativeMapsIndicators()
        return if (hits.isBlank()) pass("Native maps scan", "No instrumentation indicators in maps", "native scan clean", "Runtime")
        else fail("Native maps scan", "Native scan of /proc/self/maps found indicators", hits, "Runtime", Severity.CRITICAL)
    }

    private fun nativeThreadIndicatorsCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native thread scan", "Runtime")
        val hits = NativeChecks.nativeThreadIndicators()
        return if (hits.isBlank()) pass("Native thread scan", "No instrumentation thread names", "native scan clean", "Runtime")
        else fail("Native thread scan", "Native scan found instrumentation thread names", hits, "Runtime", Severity.CRITICAL)
    }

    private fun nativeSelinuxEnforceCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native SELinux", "Runtime")
        val v = NativeChecks.nativeSelinuxEnforce()
        val details = "/sys/fs/selinux/enforce=$v"
        return when (v) {
            1 -> pass("Native SELinux", "Native confirms enforcing", details, "Runtime")
            0 -> fail("Native SELinux", "Native confirms permissive", details, "Runtime", Severity.HIGH)
            else -> SecurityCheck("Native SELinux", true, Severity.INFO, "Unknown", details, "Runtime")
        }
    }

    private fun nativeSuspiciousMountsCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native mount scan", "Root")
        val hits = NativeChecks.nativeSuspiciousMounts()
        return if (hits.isBlank()) pass("Native mount scan", "Native scan of /proc/self/mounts clean", "native scan clean", "Root")
        else fail("Native mount scan", "Native scan flagged magisk-style overlays", hits.take(2000), "Root", Severity.CRITICAL)
    }

    private fun nativeApkPathConsistencyCheck(context: Context): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native APK path", "Integrity")
        val nativePath = NativeChecks.nativeApkPath()
        val expected = context.applicationInfo.sourceDir
        val ok = nativePath.isNotBlank() && nativePath == expected
        val details = "native=$nativePath\nexpected=$expected"
        return if (ok) pass("Native APK path", "sourceDir matches /proc/self/maps", details, "Integrity")
        else fail("Native APK path", "sourceDir disagrees with native /proc/self/maps", details, "Integrity", Severity.HIGH)
    }

    private fun nativeTimingHookCheck(): SecurityCheck {
        if (!NativeChecks.available()) return skipped("Native timing hook", "Runtime")
        // Run a few iterations and pick the median to dampen scheduler noise.
        val samples = LongArray(5) { NativeChecks.nativeTimingNanos() }
        samples.sort()
        val median = samples[samples.size / 2]
        val max = samples.maxOrNull() ?: median
        // Empirically a clean run completes the loop in < 50 ms even on slow ARMv7 devices.
        // A wildly larger value (>= 250 ms) is a strong indicator of inline hooks slowing
        // every iteration. A single max outlier far above the median is also suspicious.
        val medianMs = median / 1_000_000.0
        val maxMs = max / 1_000_000.0
        val details = "samples_ns=${samples.joinToString()}\nmedian_ms=$medianMs\nmax_ms=$maxMs"
        val degraded = median > 250_000_000L || max > 4 * median.coerceAtLeast(1)
        return if (!degraded) pass("Native timing hook", "Tight loop timing within expected envelope", details, "Runtime")
        else fail("Native timing hook", "Tight loop timing degraded (possible inline hooks)", details, "Runtime", Severity.MEDIUM)
    }

    private fun skipped(title: String, category: String): SecurityCheck =
        SecurityCheck(title, true, Severity.INFO, "Skipped (native lib unavailable)", "libdctnative.so not loaded", category)

    private fun portOpenLocalhost(port: Int): Boolean {
        return try {
            java.net.Socket("127.0.0.1", port).use { true }
        } catch (_: Throwable) { false }
    }

    private fun isPackageInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfoCompat(pkg)
        true
    } catch (_: PackageManager.NameNotFoundException) { false }

    private fun packageLabel(context: Context, pkg: String): String = try {
        val app = context.packageManager.getApplicationInfo(pkg, 0)
        context.packageManager.getApplicationLabel(app).toString()
    } catch (_: Exception) { pkg }

    private fun signingSha256(context: Context): String {
        val info = context.packageManager.getPackageInfoCompat(context.packageName)
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            @Suppress("DEPRECATION") info.signatures?.toList().orEmpty()
        }
        val cert = signatures.firstOrNull()?.toByteArray() ?: return "NO_SIGNATURE"
        val digest = MessageDigest.getInstance("SHA-256").digest(cert)
        return digest.joinToString(":") { "%02X".format(it) }
    }

    @SuppressLint("PrivateApi")
    private fun getProp(key: String): String {
        // Layered reads: native first (resists Java reflection hooks), then SystemProperties
        // reflection, then a final getprop(1) fallback. Multiple sources let us cross-check.
        if (NativeChecks.available()) {
            val nativeVal = runCatching { NativeChecks.nativeGetProp(key) }.getOrDefault("")
            if (nativeVal.isNotBlank()) return nativeVal
        }
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java)
            get.invoke(null, key) as? String ?: ""
        } catch (_: Throwable) {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("getprop", key))
                BufferedReader(InputStreamReader(p.inputStream)).readLine() ?: ""
            } catch (_: Throwable) { "" }
        }
    }

    @Suppress("DEPRECATION")
    private fun PackageManager.getPackageInfoCompat(pkg: String): PackageInfo {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
        }
    }
}
