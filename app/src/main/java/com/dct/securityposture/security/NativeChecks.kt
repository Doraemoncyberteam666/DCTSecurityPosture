package com.dct.securityposture.security

import com.dct.securityposture.obf.V

/**
 * Bridge to the Level-2 native (`libdctnative.so`) integrity checks.
 *
 * All entry points are intentionally pure native methods so that hooks on
 * `java.io.File`, `android.os.SystemProperties`, or reflection-based property
 * APIs do not see the underlying I/O.
 *
 * Call [available] before consuming results: when `System.loadLibrary` failed
 * (e.g. someone stripped the .so out of the APK or deleted the ABI splits)
 * every other function returns a sentinel. That itself is reported as a
 * tamper signal by the checks layer.
 */
object NativeChecks {
    private val loaded: Boolean = runCatching {
        // Library name is XOR-encoded in the StringVault and only materialised
        // here at runtime so static `strings(1)`/baksmali searches for the
        // .so name don't reveal it.
        System.loadLibrary(V.s(V.DCTNATIVE))
        true
    }.getOrDefault(false)

    fun available(): Boolean = loaded && runCatching { nativeLibLoaded() }.getOrDefault(false)

    @JvmStatic external fun nativeLibLoaded(): Boolean
    @JvmStatic external fun nativeTracerPid(): Int
    @JvmStatic external fun nativePtraceSelfAttach(): Int
    @JvmStatic external fun nativeMapsIndicators(): String
    @JvmStatic external fun nativeThreadIndicators(): String
    @JvmStatic external fun nativeSelinuxEnforce(): Int
    @JvmStatic external fun nativeApkPath(): String
    @JvmStatic external fun nativeGetProp(key: String): String
    @JvmStatic external fun nativeTimingNanos(): Long
    @JvmStatic external fun nativeSuspiciousMounts(): String
    @JvmStatic external fun nativeLoadedLibraries(): String
    @JvmStatic external fun nativeProcCmdline(): String
}
