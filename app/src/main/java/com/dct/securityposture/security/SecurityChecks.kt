package com.dct.securityposture.security

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import com.dct.securityposture.model.SecurityCheck
import com.dct.securityposture.model.Severity
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
        appDataDirWritableCheck(context)
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
            "ro.debuggable" to "0",
            "ro.secure" to "1",
            "service.adb.root" to "0",
            "ro.build.tags" to "release-keys"
        )
        val bad = mutableListOf<String>()
        val observed = mutableListOf<String>()
        for ((key, expected) in props) {
            val value = getProp(key)
            observed += "$key=$value"
            if (key == "ro.build.tags") {
                if (value.contains("test-keys", ignoreCase = true)) bad += "$key=$value"
            } else if (value.isNotBlank() && value != expected) bad += "$key=$value expected=$expected"
        }
        return if (bad.isEmpty()) pass("System properties", "No dangerous root/debug properties", observed.joinToString("\n"), "Root")
        else fail("System properties", "Suspicious system properties", bad.joinToString("\n"), "Root", Severity.HIGH)
    }

    private fun rootManagementAppsCheck(context: Context): SecurityCheck {
        val packages = listOf(
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.noshufou.android.su", "com.thirdparty.superuser", "io.github.vvb2060.magisk"
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
        val value = try {
            File("/proc/self/status").readLines()
                .firstOrNull { it.startsWith("TracerPid:") }
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
            "de.robv.android.xposed.installer", "org.lsposed.manager", "io.github.vvb2060.magisk",
            "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.devadvance.rootcloak"
        )
        val visible = packages.filter { isPackageInstalled(context, it) }
        val stackHit = Throwable().stackTrace.any { frame ->
            val name = frame.className.lowercase(Locale.US)
            name.contains("xposed") || name.contains("substrate") || name.contains("lsposed")
        }
        val details = buildString {
            appendLine("visiblePackages=${visible.ifEmpty { listOf("none") }.joinToString()}")
            appendLine("stackHookIndicator=$stackHit")
        }
        return if (visible.isEmpty() && !stackHit) pass("Hooking frameworks", "No visible hooking framework indicators", details, "Runtime")
        else fail("Hooking frameworks", "Hooking/runtime instrumentation indicators found", details, "Runtime", Severity.HIGH)
    }

    private fun suspiciousProcessMapsCheck(): SecurityCheck {
        val indicators = listOf("frida", "gum-js-loop", "xposed", "substrate", "edxp")
        val hits = try {
            File("/proc/self/maps").readText().lowercase(Locale.US).let { maps ->
                indicators.filter { maps.contains(it) }
            }
        } catch (_: Throwable) { emptyList() }
        return if (hits.isEmpty()) pass("Process maps", "No suspicious hooking libs in memory map", indicators.joinToString(", "), "Runtime")
        else fail("Process maps", "Suspicious in-memory artifacts detected", hits.joinToString(", "), "Runtime", Severity.CRITICAL)
    }

    private fun verifiedBootCheck(): SecurityCheck {
        val state = getProp("ro.boot.verifiedbootstate").ifBlank { "unknown" }.lowercase(Locale.US)
        val mode = getProp("ro.boot.flash.locked").ifBlank { "unknown" }
        val details = "verifiedbootstate=$state\nflash.locked=$mode"
        val ok = state == "green" || state == "unknown"
        return if (ok) pass("Verified boot", "Boot state not flagged as compromised", details, "Integrity")
        else fail("Verified boot", "Boot state indicates reduced trust", details, "Integrity", Severity.HIGH)
    }

    private fun selinuxEnforcingCheck(): SecurityCheck {
        val value = getProp("ro.build.selinux").ifBlank { "unknown" }
        val enforce = getProp("ro.boot.selinux").ifBlank { "unknown" }
        val details = "ro.build.selinux=$value\nro.boot.selinux=$enforce"
        val risky = listOf(value, enforce).any { it.contains("permissive", ignoreCase = true) || it == "0" }
        return if (!risky) pass("SELinux mode", "No permissive SELinux indicator", details, "Runtime")
        else fail("SELinux mode", "Permissive SELinux indicator found", details, "Runtime", Severity.HIGH)
    }

    private fun suspiciousMountsCheck(): SecurityCheck {
        val lines = try { File("/proc/mounts").readLines() } catch (_: Throwable) { emptyList() }
        val hits = lines.filter { line ->
            (line.contains(" /system ") || line.contains(" /vendor ")) &&
                line.contains(" rw,")
        }
        return if (hits.isEmpty()) pass("Readonly partitions", "No writable system/vendor mount marker", "checked=/proc/mounts", "Root")
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
