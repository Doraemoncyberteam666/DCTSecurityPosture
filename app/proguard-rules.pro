# Keep app entry points and model classes used by RecyclerView rendering.
-keep class com.dct.securityposture.MainActivity { *; }
-keep class com.dct.securityposture.model.** { *; }

# Keep Android framework subclasses referenced via manifest or reflection.
-keep class * extends android.app.Activity
-keep class * extends android.app.Application

# Native (JNI) bridge: preserve method names so JNI symbol lookup
# (Java_com_dct_securityposture_security_NativeChecks_<name>) keeps working
# under R8/ProGuard renaming.
-keepclasseswithmembernames class com.dct.securityposture.security.NativeChecks {
    native <methods>;
}
-keep class com.dct.securityposture.security.NativeChecks {
    public static <methods>;
}
-keepclasseswithmembernames class * {
    native <methods>;
}

# Custom obfuscator: keep the generated string vault's surface so the
# decoder + byte-array tables aren't shrunk away. Method names can still be
# obfuscated by R8 (callers reference the const-val IDs through the same class
# so renaming stays consistent within the class). The byte arrays themselves
# are encoded with a per-build random rolling XOR key by GenerateStringVaultTask.
-keep,allowobfuscation class com.dct.securityposture.obf.V {
    <fields>;
    <methods>;
}

# Remove logs and make static analysis harder in release.
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** i(...);
    public static *** v(...);
    public static *** w(...);
    public static *** e(...);
}

# Strip Kotlin intrinsic null-check messages — they leak parameter / function
# names that would otherwise survive obfuscation.
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
    public static void checkNotNull(java.lang.Object);
    public static void checkNotNull(java.lang.Object, java.lang.String);
    public static void checkExpressionValueIsNotNull(java.lang.Object, java.lang.String);
    public static void checkNotNullExpressionValue(java.lang.Object, java.lang.String);
    public static void checkParameterIsNotNull(java.lang.Object, java.lang.String);
    public static void checkNotNullParameter(java.lang.Object, java.lang.String);
    public static void checkReturnedValueIsNotNull(java.lang.Object, java.lang.String, java.lang.String);
    public static void checkReturnedValueIsNotNull(java.lang.Object, java.lang.String);
    public static void checkFieldIsNotNull(java.lang.Object, java.lang.String, java.lang.String);
    public static void checkFieldIsNotNull(java.lang.Object, java.lang.String);
    public static void throwUninitializedPropertyAccessException(java.lang.String);
}

# Increase optimization/obfuscation pressure.
-repackageclasses 'x'
-allowaccessmodification
-overloadaggressively
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents
-dontnote kotlin.**

# Drop source-file metadata so attached-debugger / crash dumps don't reveal
# original file/line numbers for the security checks.
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
