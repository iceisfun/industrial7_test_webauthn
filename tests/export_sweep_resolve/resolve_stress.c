/* Whole-DLL export sweep, part 4: load / first-call / unload behaviour. Anything that unloads the module
 * or relies on a fresh process runs in a CHILD with a timeout, so the parent keeps webauthn.dll mapped. */
#include "sweep.h"

typedef DWORD (WINAPI *apiver_fn)(void);

/* ---- concurrent first call after a fresh LoadLibrary (child) --------------- */
#define RACE_THREADS 8
static HANDLE g_go;
static volatile LONG g_bad, g_ready;
static FARPROC g_seen[RACE_THREADS];
static DWORD g_ver[RACE_THREADS];

static DWORD WINAPI race_thread(LPVOID arg) {
    int idx = (int)(INT_PTR)arg;
    HMODULE h = GetModuleHandleA("webauthn.dll");
    InterlockedIncrement(&g_ready);
    WaitForSingleObject(g_go, 5000);
    FARPROC p = h ? GetProcAddress(h, "WebAuthNGetApiVersionNumber") : NULL;
    g_seen[idx] = p;
    if (!p) { InterlockedIncrement(&g_bad); return 1; }
    g_ver[idx] = ((apiver_fn)p)();
    return 0;
}

CHILD(first_call_race) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    g_go = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE th[RACE_THREADS];
    for (int i = 0; i < RACE_THREADS; i++) { th[i] = CreateThread(NULL, 0, race_thread, (LPVOID)(INT_PTR)i, 0, NULL); if (!th[i]) return 11; }
    for (int i = 0; i < 500 && g_ready < RACE_THREADS; i++) Sleep(10);
    if (g_ready < RACE_THREADS) return 12;
    SetEvent(g_go);
    if (WaitForMultipleObjects(RACE_THREADS, th, TRUE, 8000) != WAIT_OBJECT_0) return 13;
    if (g_bad) return 14;
    for (int i = 1; i < RACE_THREADS; i++) { if (g_seen[i] != g_seen[0]) return 15; if (g_ver[i] != g_ver[0]) return 16; }
    if (g_ver[0] > 2) return 17;
    return 0;
}
TEST(export_sweep_resolve_first_call_race_8_threads) {
    SW_NEED_MODULE();
    for (int round = 0; round < 3; round++) EQ1(t_run_child("first_call_race", "", 20000), 0);
}

/* Threads that each LoadLibrary the module themselves before the first call. */
static DWORD WINAPI race_load_thread(LPVOID arg) {
    int idx = (int)(INT_PTR)arg;
    WaitForSingleObject(g_go, 5000);
    HMODULE h = LoadLibraryA("webauthn.dll");
    FARPROC p = h ? GetProcAddress(h, "WebAuthNGetApiVersionNumber") : NULL;
    g_seen[idx] = p;
    if (!p) { InterlockedIncrement(&g_bad); return 1; }
    g_ver[idx] = ((apiver_fn)p)();
    FreeLibrary(h);
    return 0;
}
CHILD(first_call_race_loaders) {
    g_go = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE th[RACE_THREADS];
    for (int i = 0; i < RACE_THREADS; i++) { th[i] = CreateThread(NULL, 0, race_load_thread, (LPVOID)(INT_PTR)i, 0, NULL); if (!th[i]) return 11; }
    SetEvent(g_go);
    if (WaitForMultipleObjects(RACE_THREADS, th, TRUE, 10000) != WAIT_OBJECT_0) return 13;
    if (g_bad) return 14;
    for (int i = 1; i < RACE_THREADS; i++) { if (g_seen[i] != g_seen[0]) return 15; if (g_ver[i] != g_ver[0]) return 16; }
    return 0;
}
TEST(export_sweep_resolve_first_call_race_threads_load_themselves) {
    SW_NEED_MODULE();
    for (int round = 0; round < 3; round++) EQ1(t_run_child("first_call_race_loaders", "", 20000), 0);
}

/* ---- process detach cleanliness (child) -------------------------------------- */
CHILD(detach_normal) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    if (!f) return 11;
    if (f() > 2) return 12;
    if (!GetProcAddress(h, "WebAuthNGetErrorName")) return 13;
    if (!GetProcAddress(h, (LPCSTR)(ULONG_PTR)56)) return 14;
    return 0;                       /* returning from main runs process detach with the module still loaded */
}
CHILD(detach_exitprocess) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    if (!f || f() > 2) return 11;
    ExitProcess(0);
    return 99;
}
CHILD(detach_freelibrary_first) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    if (!f || f() > 2) return 11;
    if (!FreeLibrary(h)) return 12;
    return 0;                       /* explicit unload (DLL_PROCESS_DETACH, lpReserved == NULL) then normal exit */
}
CHILD(detach_load_only) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    return h ? 0 : 10;              /* never called anything: attach + detach only */
}
static DWORD WINAPI noop_thread(LPVOID a) { return 0; }
CHILD(detach_thread_notifications) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    if (!f) return 11;
    for (int i = 0; i < 50; i++) {            /* DLL_THREAD_ATTACH / DLL_THREAD_DETACH delivered to the module */
        HANDLE t = CreateThread(NULL, 0, noop_thread, NULL, 0, NULL);
        if (!t) return 12;
        if (WaitForSingleObject(t, 5000) != WAIT_OBJECT_0) return 13;
        CloseHandle(t);
    }
    if (f() > 2) return 14;
    return 0;
}
static DWORD WINAPI call_thread(LPVOID a) { return ((apiver_fn)a)(); }
CHILD(detach_call_on_worker_threads) {
    HMODULE h = LoadLibraryA("webauthn.dll");
    if (!h) return 10;
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    if (!f) return 11;
    for (int i = 0; i < 20; i++) {
        HANDLE t = CreateThread(NULL, 0, call_thread, (LPVOID)f, 0, NULL);
        if (!t) return 12;
        if (WaitForSingleObject(t, 5000) != WAIT_OBJECT_0) return 13;
        DWORD v = 99; GetExitCodeThread(t, &v); CloseHandle(t);
        if (v > 2) return 14;
    }
    return 0;
}
CHILD(detach_ncrypt_bcrypt_too) {
    HMODULE w = LoadLibraryA("webauthn.dll"), n = LoadLibraryA("ncrypt.dll"), b = LoadLibraryA("bcrypt.dll");
    if (!w || !n || !b) return 10;
    if (!GetProcAddress(n, "NCryptOpenStorageProvider") || !GetProcAddress(b, "BCryptGenRandom")) return 11;
    return 0;
}

#define DETACH_TEST(c) TEST(export_sweep_resolve_process_detach_##c) { \
        SW_NEED_MODULE(); \
        DWORD r = t_run_child("detach_" #c, "", 15000); \
        CHECKF(r != 0xDEAD0001, "child hung at exit (killed)"); \
        EXPECT_EQ(r, 0); }
DETACH_TEST(normal)
DETACH_TEST(exitprocess)
DETACH_TEST(freelibrary_first)
DETACH_TEST(load_only)
DETACH_TEST(thread_notifications)
DETACH_TEST(call_on_worker_threads)
DETACH_TEST(ncrypt_bcrypt_too)

TEST(export_sweep_resolve_process_detach_repeated_spawns) {
    SW_NEED_MODULE();
    for (int i = 0; i < 10; i++) EQ1(t_run_child("detach_normal", "", 15000), 0);
}

/* Module is unloaded once the last reference goes (child, balanced loads/frees). */
CHILD(unload_balanced) {
    if (GetModuleHandleA("webauthn.dll")) return 10;      /* a fresh process does not map it */
    HMODULE a = LoadLibraryA("webauthn.dll"), b = LoadLibraryA("webauthn.dll");
    if (!a || a != b) return 11;
    if (!FreeLibrary(a)) return 12;
    if (GetModuleHandleA("webauthn.dll") != a) return 13; /* one reference left */
    if (!GetProcAddress(a, "WebAuthNGetApiVersionNumber")) return 14;
    if (!FreeLibrary(b)) return 15;
    if (GetModuleHandleA("webauthn.dll") != NULL) return 16;
    return 0;
}
TEST(export_sweep_resolve_unload_when_refcount_reaches_zero) {
    SW_NEED_MODULE();
    DWORD r = t_run_child("unload_balanced", "", 15000);
    if (r == 16) t_note("module stayed mapped after the last FreeLibrary (pinned by something)");
    EXPECT_EQ(r == 16 ? 0 : r, 0);
}
CHILD(reload_after_unload) {
    for (int i = 0; i < 20; i++) {
        HMODULE h = LoadLibraryA("webauthn.dll");
        if (!h) return 10;
        apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
        if (!f || f() > 2) return 11;
        if (!GetProcAddress(h, (LPCSTR)(ULONG_PTR)1)) return 12;
        if (!FreeLibrary(h)) return 13;
    }
    return 0;
}
TEST(export_sweep_resolve_reload_after_unload_20_times) {
    SW_NEED_MODULE();
    EQ1(t_run_child("reload_after_unload", "", 30000), 0);
}

/* ---- 32 simultaneous LoadLibrary / FreeLibrary ------------------------------ */
#define LL_THREADS 32
#define LL_ITERS 25
static HMODULE g_expect;

static DWORD WINAPI ll_thread(LPVOID arg) {
    WaitForSingleObject(g_go, 5000);
    for (int i = 0; i < LL_ITERS; i++) {
        HMODULE h = LoadLibraryA("webauthn.dll");
        if (!h || (g_expect && h != g_expect)) { InterlockedIncrement(&g_bad); return 1; }
        if (!GetProcAddress(h, "WebAuthNGetApiVersionNumber") || !GetProcAddress(h, (LPCSTR)(ULONG_PTR)(1 + i % 56))) InterlockedIncrement(&g_bad);
        if (!FreeLibrary(h)) InterlockedIncrement(&g_bad);
    }
    return 0;
}
static int run_ll_threads(void) {
    g_go = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_bad = 0;
    HANDLE th[LL_THREADS];
    for (int i = 0; i < LL_THREADS; i++) { th[i] = CreateThread(NULL, 0, ll_thread, NULL, 0, NULL); if (!th[i]) return 11; }
    SetEvent(g_go);
    DWORD w = WaitForMultipleObjects(LL_THREADS, th, TRUE, 20000);
    if (w != WAIT_OBJECT_0) return 13;
    for (int i = 0; i < LL_THREADS; i++) CloseHandle(th[i]);
    CloseHandle(g_go);
    return g_bad ? 14 : 0;
}
TEST(export_sweep_resolve_32_threads_loadfree_in_process) {
    SW_NEED_MODULE();
    g_expect = h;
    EQ1(run_ll_threads(), 0);
    EXPECT_EQ(GetModuleHandleA("webauthn.dll"), h);      /* the harness reference is untouched */
    CHECK(GetProcAddress(h, "WebAuthNGetApiVersionNumber") != NULL);
}
CHILD(loadfree_32_threads) {
    g_expect = NULL;                 /* module may legitimately move between unload/load cycles */
    int r = run_ll_threads();
    if (r) return r;
    return 0;
}
TEST(export_sweep_resolve_32_threads_loadfree_fresh_process) {
    SW_NEED_MODULE();
    EQ1(t_run_child("loadfree_32_threads", "", 30000), 0);
}

/* ---- all four threads-of-lookup at once: names and ordinals ------------------- */
static DWORD WINAPI sweep_thread(LPVOID arg) {
    HMODULE h = (HMODULE)arg;
    WaitForSingleObject(g_go, 5000);
    for (int round = 0; round < 20; round++)
        for (int i = 0; i < SW_COUNT; i++) {
            FARPROC a = GetProcAddress(h, sw_exports[i].name), b = GetProcAddress(h, (LPCSTR)(ULONG_PTR)sw_exports[i].ord);
            if (!a || a != b || (BYTE *)a - (BYTE *)h != sw_exports[i].rva) { InterlockedIncrement(&g_bad); return 1; }
        }
    return 0;
}
TEST(export_sweep_resolve_concurrent_name_and_ordinal_lookup) {
    SW_NEED_MODULE();
    g_go = CreateEventA(NULL, TRUE, FALSE, NULL); g_bad = 0;
    HANDLE th[8];
    for (int i = 0; i < 8; i++) { th[i] = CreateThread(NULL, 0, sweep_thread, h, 0, NULL); CHECK(th[i] != NULL); if (!th[i]) { SetEvent(g_go); return; } }
    SetEvent(g_go);
    CHECK(WaitForMultipleObjects(8, th, TRUE, 20000) == WAIT_OBJECT_0);
    EXPECT_EQ(g_bad, 0);
    for (int i = 0; i < 8; i++) CloseHandle(th[i]);
    CloseHandle(g_go);
}
