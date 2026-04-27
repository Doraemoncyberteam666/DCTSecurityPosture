# Keep app entry points and model classes used by RecyclerView rendering.
-keep class com.dct.securityposture.MainActivity { *; }
-keep class com.dct.securityposture.model.** { *; }

# Keep Android framework subclasses referenced via manifest or reflection.
-keep class * extends android.app.Activity
-keep class * extends android.app.Application

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
