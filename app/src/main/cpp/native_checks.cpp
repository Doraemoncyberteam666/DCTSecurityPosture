// Level-2 native security posture checks.
//
// These run in the app process via JNI so that hooks targeting only Java
// reflection / java.io.File / android.os.SystemProperties do not see them.
// Indicators are XOR-obfuscated at compile time so a `strings(1)` over the
// shared object does not trivially reveal the watch list.
//
// All entry points return primitive types or simple strings to keep the JNI
// surface minimal and avoid Java-side hookable wrappers.

#include <jni.h>

#include <android/log.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "DCTSecPosture"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

// -----------------------------------------------------------------------------
// Compile-time XOR string obfuscation.
//
// Bytes are stored XOR-encoded in .rodata and decoded into a stack buffer at
// the call site. This raises the bar for `strings(1)`, naive memory scans, and
// quick patches against detected indicator names.
// -----------------------------------------------------------------------------

constexpr char kXorKey = 0x5A;

template <size_t N>
struct XorStr {
    char data[N];
};

template <size_t N>
constexpr XorStr<N> X(const char (&s)[N]) {
    XorStr<N> r{};
    for (size_t i = 0; i < N; ++i) r.data[i] = s[i] ^ kXorKey;
    return r;
}

template <size_t N>
inline void DecodeInto(const XorStr<N>& s, char (&out)[N]) {
    for (size_t i = 0; i < N; ++i) out[i] = s.data[i] ^ kXorKey;
}

// Hooking framework / instrumentation indicators we look for in maps + threads.
constexpr auto kIFrida      = X("frida");
constexpr auto kIGumJsLoop  = X("gum-js-loop");
constexpr auto kIGmainCtx   = X("gmain");
constexpr auto kIGdbus      = X("gdbus");
constexpr auto kIPoolFrida  = X("pool-frida");
constexpr auto kIFridaServer= X("frida-server");
constexpr auto kIFridaAgent = X("frida-agent");
constexpr auto kIGadget     = X("frida-gadget");
constexpr auto kIXposed     = X("xposed");
constexpr auto kILsposed    = X("lsposed");
constexpr auto kISubstrate  = X("substrate");
constexpr auto kIEdxp       = X("edxp");
constexpr auto kIRiru       = X("riru");
constexpr auto kIZygisk     = X("zygisk");
constexpr auto kILinjector  = X("linjector");
constexpr auto kIMagisk     = X("magisk");

// Path / filesystem indicators.
constexpr auto kPProcMaps   = X("/proc/self/maps");
constexpr auto kPProcStatus = X("/proc/self/status");
constexpr auto kPProcMounts = X("/proc/self/mounts");
constexpr auto kPProcTask   = X("/proc/self/task");
constexpr auto kPSelinux    = X("/sys/fs/selinux/enforce");
constexpr auto kPProcCmd    = X("/proc/self/cmdline");
constexpr auto kPDataAdb    = X("/data/adb");
constexpr auto kPDevHwc     = X("/dev/hw_random");
constexpr auto kSBaseApk    = X("base.apk");

// -----------------------------------------------------------------------------
// Helpers.
// -----------------------------------------------------------------------------

// Read up to cap-1 bytes of `path` into `buf` using raw open/read syscalls.
// Returns bytes read (>=0) on success; -1 on failure. Always NUL-terminates
// when >= 0.
ssize_t ReadFileSmall(const char* path, char* buf, size_t cap) {
    if (cap == 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            buf[total] = '\0';
            return -1;
        }
        if (n == 0) break;
        total += static_cast<size_t>(n);
    }
    close(fd);
    buf[total] = '\0';
    return static_cast<ssize_t>(total);
}

bool Contains(const char* haystack, const char* needle) {
    return strstr(haystack, needle) != nullptr;
}

// Append `src` to `dest` if not already present, using ", " as separator.
// Truncates silently if the destination is full.
void AppendUnique(char* dest, size_t cap, const char* src) {
    if (Contains(dest, src)) return;
    size_t dl = strlen(dest);
    size_t sl = strlen(src);
    if (sl == 0) return;
    if (dl + sl + (dl > 0 ? 2 : 0) + 1 >= cap) return;
    if (dl > 0) {
        dest[dl++] = ',';
        dest[dl++] = ' ';
    }
    memcpy(dest + dl, src, sl);
    dest[dl + sl] = '\0';
}

template <size_t N>
void ScanForIndicator(const char* haystack, const XorStr<N>& enc,
                      char* out, size_t out_cap) {
    char tmp[N];
    DecodeInto(enc, tmp);
    if (Contains(haystack, tmp)) AppendUnique(out, out_cap, tmp);
}

jstring NewJString(JNIEnv* env, const char* s) {
    return env->NewStringUTF(s == nullptr ? "" : s);
}

}  // namespace

// -----------------------------------------------------------------------------
// JNI surface.
// -----------------------------------------------------------------------------

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeLibLoaded(JNIEnv*, jclass) {
    return JNI_TRUE;
}

// Returns TracerPid value, or -1 if unreadable. Reads /proc/self/status via
// raw open/read syscalls so that Java-level java.io.File hooks miss it.
JNIEXPORT jint JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeTracerPid(JNIEnv*, jclass) {
    char path[sizeof(kPProcStatus.data)];
    DecodeInto(kPProcStatus, path);
    char buf[8192];
    if (ReadFileSmall(path, buf, sizeof(buf)) < 0) return -1;

    const char* needle = "TracerPid:";
    char* p = strstr(buf, needle);
    if (!p) return -1;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t') ++p;
    return static_cast<jint>(strtol(p, nullptr, 10));
}

// Best-effort ptrace self-attach via fork(). The child attempts to ptrace
// the parent: if a debugger is already attached, the attach fails; otherwise
// the child detaches and reports clean. Returns:
//   0 - clean (no other tracer)
//   1 - tracer present (attach refused)
//  -1 - inconclusive (fork/pipe failure or signal-mask issues)
JNIEXPORT jint JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativePtraceSelfAttach(JNIEnv*, jclass) {
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) return -1;

    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return -1;
    }

    if (child == 0) {
        // Child: try to attach to the parent.
        close(pipe_fd[0]);
        char result;
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) == 0) {
            int status = 0;
            waitpid(parent, &status, 0);
            ptrace(PTRACE_CONT, parent, 0, 0);
            ptrace(PTRACE_DETACH, parent, 0, 0);
            result = '0';
        } else {
            result = '1';
        }
        ssize_t ignored = write(pipe_fd[1], &result, 1);
        (void)ignored;
        close(pipe_fd[1]);
        _exit(0);
    }

    close(pipe_fd[1]);
    char r = '?';
    ssize_t got = 0;
    do {
        got = read(pipe_fd[0], &r, 1);
    } while (got < 0 && errno == EINTR);
    close(pipe_fd[0]);

    int status = 0;
    waitpid(child, &status, 0);

    if (r == '0') return 0;
    if (r == '1') return 1;
    return -1;
}

// Returns a comma-separated list of hooking-framework indicators found in
// /proc/self/maps. Empty string when the map is clean.
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeMapsIndicators(JNIEnv* env, jclass) {
    char path[sizeof(kPProcMaps.data)];
    DecodeInto(kPProcMaps, path);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NewJString(env, "");

    char hits[256] = {0};
    char chunk[8192];
    char carry[256] = {0};
    size_t carry_len = 0;

    while (true) {
        ssize_t n = read(fd, chunk, sizeof(chunk) - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        chunk[n] = '\0';

        // Combine with carry prefix to catch indicators straddling a chunk.
        char combined[sizeof(chunk) + sizeof(carry)];
        memcpy(combined, carry, carry_len);
        memcpy(combined + carry_len, chunk, static_cast<size_t>(n) + 1);

        ScanForIndicator(combined, kIFrida,       hits, sizeof(hits));
        ScanForIndicator(combined, kIGumJsLoop,   hits, sizeof(hits));
        ScanForIndicator(combined, kIFridaAgent,  hits, sizeof(hits));
        ScanForIndicator(combined, kIFridaServer, hits, sizeof(hits));
        ScanForIndicator(combined, kIGadget,      hits, sizeof(hits));
        ScanForIndicator(combined, kIXposed,      hits, sizeof(hits));
        ScanForIndicator(combined, kILsposed,     hits, sizeof(hits));
        ScanForIndicator(combined, kISubstrate,   hits, sizeof(hits));
        ScanForIndicator(combined, kIEdxp,        hits, sizeof(hits));
        ScanForIndicator(combined, kIRiru,        hits, sizeof(hits));
        ScanForIndicator(combined, kIZygisk,      hits, sizeof(hits));
        ScanForIndicator(combined, kILinjector,   hits, sizeof(hits));
        ScanForIndicator(combined, kIMagisk,      hits, sizeof(hits));

        // Keep a small carry to bridge chunk boundaries.
        size_t combined_len = carry_len + static_cast<size_t>(n);
        carry_len = combined_len < sizeof(carry) - 1 ? combined_len : sizeof(carry) - 1;
        memcpy(carry, combined + (combined_len - carry_len), carry_len);
        carry[carry_len] = '\0';
    }
    close(fd);

    return NewJString(env, hits);
}

// Returns a comma-separated list of suspicious thread names found in
// /proc/self/task/<tid>/comm. Catches thread-name-only indicators (the Frida
// agent always spawns "gum-js-loop", "gmain", "gdbus", or "pool-frida-*"
// threads even when its libraries are unmapped).
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeThreadIndicators(JNIEnv* env, jclass) {
    char base[sizeof(kPProcTask.data)];
    DecodeInto(kPProcTask, base);

    DIR* d = opendir(base);
    if (!d) return NewJString(env, "");

    char hits[256] = {0};
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path), "%s/%s/comm", base, ent->d_name);
        char comm[64] = {0};
        if (ReadFileSmall(comm_path, comm, sizeof(comm)) < 0) continue;
        // Strip trailing newline.
        size_t cl = strlen(comm);
        while (cl > 0 && (comm[cl - 1] == '\n' || comm[cl - 1] == '\r')) {
            comm[--cl] = '\0';
        }
        ScanForIndicator(comm, kIGumJsLoop,  hits, sizeof(hits));
        ScanForIndicator(comm, kIGmainCtx,   hits, sizeof(hits));
        ScanForIndicator(comm, kIGdbus,      hits, sizeof(hits));
        ScanForIndicator(comm, kIPoolFrida,  hits, sizeof(hits));
        ScanForIndicator(comm, kIFrida,      hits, sizeof(hits));
    }
    closedir(d);

    return NewJString(env, hits);
}

// SELinux enforce: 0 permissive, 1 enforcing, -1 unknown.
JNIEXPORT jint JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeSelinuxEnforce(JNIEnv*, jclass) {
    char path[sizeof(kPSelinux.data)];
    DecodeInto(kPSelinux, path);
    char buf[8] = {0};
    if (ReadFileSmall(path, buf, sizeof(buf)) < 0) return -1;
    if (buf[0] == '1') return 1;
    if (buf[0] == '0') return 0;
    return -1;
}

// Returns the first base.apk path discovered in /proc/self/maps, or empty.
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeApkPath(JNIEnv* env, jclass) {
    char path[sizeof(kPProcMaps.data)];
    DecodeInto(kPProcMaps, path);
    char marker[sizeof(kSBaseApk.data)];
    DecodeInto(kSBaseApk, marker);

    FILE* fp = fopen(path, "r");
    if (!fp) return NewJString(env, "");
    char line[1024];
    char found[512] = {0};
    while (fgets(line, sizeof(line), fp)) {
        char* m = strstr(line, marker);
        if (!m) continue;
        // Walk back to the start of the path within the maps line.
        char* start = m;
        while (start > line && start[-1] != ' ') --start;
        char* end = m + strlen(marker);
        size_t len = static_cast<size_t>(end - start);
        if (len >= sizeof(found)) len = sizeof(found) - 1;
        memcpy(found, start, len);
        found[len] = '\0';
        break;
    }
    fclose(fp);
    return NewJString(env, found);
}

// __system_property_get bypassing Java reflection / Runtime.exec("getprop").
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeGetProp(JNIEnv* env, jclass, jstring jKey) {
    if (!jKey) return NewJString(env, "");
    const char* key = env->GetStringUTFChars(jKey, nullptr);
    if (!key) return NewJString(env, "");
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(key, value);
    env->ReleaseStringUTFChars(jKey, key);
    return NewJString(env, value);
}

// Tight CPU loop. Returns elapsed nanoseconds. A large or wildly variable
// value across calls indicates execution-side hooks slowing the path down.
JNIEXPORT jlong JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeTimingNanos(JNIEnv*, jclass) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile uint64_t acc = 0;
    for (uint64_t i = 0; i < 200000ULL; ++i) {
        acc += i * 2654435761ULL;
        acc ^= acc >> 13;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int64_t ns = static_cast<int64_t>(t1.tv_sec - t0.tv_sec) * 1000000000LL +
                 static_cast<int64_t>(t1.tv_nsec - t0.tv_nsec);
    if (acc == 0) ns += 1;  // prevent dead-store elimination of acc
    return static_cast<jlong>(ns);
}

// Returns lines from /proc/self/mounts that look like Magisk-style overlay
// mounts (tmpfs over /system, /data/adb, magisk-managed dirs). Empty when
// nothing matches.
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeSuspiciousMounts(JNIEnv* env, jclass) {
    char path[sizeof(kPProcMounts.data)];
    DecodeInto(kPProcMounts, path);
    char magisk[sizeof(kIMagisk.data)];
    DecodeInto(kIMagisk, magisk);
    char dataAdb[sizeof(kPDataAdb.data)];
    DecodeInto(kPDataAdb, dataAdb);

    FILE* fp = fopen(path, "r");
    if (!fp) return NewJString(env, "");
    char line[1024];
    char hits[2048] = {0};
    while (fgets(line, sizeof(line), fp)) {
        bool match =
            strstr(line, magisk) ||
            strstr(line, dataAdb) ||
            (strstr(line, "tmpfs") && (strstr(line, " /system ") || strstr(line, " /vendor ")));
        if (!match) continue;
        size_t hl = strlen(hits);
        size_t ll = strlen(line);
        if (hl + ll + 1 < sizeof(hits)) {
            memcpy(hits + hl, line, ll + 1);
        }
    }
    fclose(fp);
    return NewJString(env, hits);
}

// Returns newline-separated unique library paths visible in /proc/self/maps.
// Java side cross-checks against an allowlist + indicator set.
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeLoadedLibraries(JNIEnv* env, jclass) {
    char path[sizeof(kPProcMaps.data)];
    DecodeInto(kPProcMaps, path);

    FILE* fp = fopen(path, "r");
    if (!fp) return NewJString(env, "");
    char line[1024];
    char libs[8192] = {0};
    while (fgets(line, sizeof(line), fp)) {
        char* slash = strchr(line, '/');
        if (!slash) continue;
        size_t ll = strlen(slash);
        while (ll > 0 && (slash[ll - 1] == '\n' || slash[ll - 1] == '\r')) {
            slash[--ll] = '\0';
        }
        if (ll < 4) continue;
        const char* dot = strrchr(slash, '.');
        if (!dot || strncmp(dot, ".so", 3) != 0) continue;
        if (strstr(libs, slash)) continue;
        size_t cur = strlen(libs);
        if (cur + ll + 2 >= sizeof(libs)) break;
        memcpy(libs + cur, slash, ll);
        libs[cur + ll] = '\n';
        libs[cur + ll + 1] = '\0';
    }
    fclose(fp);
    return NewJString(env, libs);
}

// /proc/self/cmdline content (NUL-stripped). Used by Java side to confirm the
// declared package name matches reality.
JNIEXPORT jstring JNICALL
Java_com_dct_securityposture_security_NativeChecks_nativeProcCmdline(JNIEnv* env, jclass) {
    char path[sizeof(kPProcCmd.data)];
    DecodeInto(kPProcCmd, path);
    char buf[1024];
    ssize_t n = ReadFileSmall(path, buf, sizeof(buf));
    if (n <= 0) return NewJString(env, "");
    for (ssize_t i = 0; i < n; ++i) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    // Trim trailing spaces.
    while (n > 0 && buf[n - 1] == ' ') buf[--n] = '\0';
    return NewJString(env, buf);
}

}  // extern "C"
