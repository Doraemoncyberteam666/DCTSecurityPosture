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

# Remove logs and make static analysis harder in release.
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** i(...);
    public static *** v(...);
    public static *** w(...);
    public static *** e(...);
}

# Increase optimization/obfuscation pressure.
-repackageclasses 'x'
-allowaccessmodification
-overloadaggressively
-adaptclassstrings
-adaptresourcefilenames
-adaptresourcefilecontents
-dontnote kotlin.**
