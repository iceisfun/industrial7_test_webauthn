/* WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable: ordinal 56,
 *   HRESULT WINAPI f(BOOL *pbIsUserVerifyingPlatformAuthenticatorAvailable)
 *
 * Behaviour taken from the Windows 10 19041 implementation:
 *  - NULL out pointer: returns 0 (S_OK) immediately; it is NOT an error and nothing is written.
 *  - otherwise *pb is first set to 0 (FALSE), then the local (or, in a remote session, remote) query
 *    runs and may set it to 1 (TRUE). Exactly one 32-bit value is written; it is always 0 or 1.
 *  - the function returns 0 (S_OK) whatever the query result was (errors inside are swallowed).
 * The TRUE/FALSE answer depends on whether the signed-in user has Windows Hello (NGC) containers
 * provisioned, so it is only recorded with t_note, never asserted. The call is a read-only
 * enumeration; it shows no UI and touches no authenticator. */
#include "apv.h"

static HRESULT iu_call(BOOL *p) { return apv_iuvpaa()(p); }

TEST(apv_iu_resolves) { APV_REQUIRE_MOD(m); CHECK(GetProcAddress(m, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable") != NULL); }
TEST(apv_iu_ordinal_56_is_it) {
    APV_REQUIRE_MOD(m);
    FARPROC a = GetProcAddress(m, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    CHECK(a != NULL);
    EXPECT_EQ(a, GetProcAddress(m, MAKEINTRESOURCEA(56)));
}
TEST(apv_iu_is_last_export) {
    APV_REQUIRE_MOD(m);
    const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL);
    if (!e) return;
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames);
    EXPECT_STR((const char *)apv_rva(m, names[e->NumberOfNames - 1]), "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
}

/* ---- NULL out pointer ---------------------------------------------------- */
TEST(apv_iu_null_returns_s_ok) {
    APV_REQUIRE_MOD(m);
    EXPECT_EQ(iu_call(NULL), S_OK);
}
TEST(apv_iu_null_is_not_an_error_hresult) {
    APV_REQUIRE_MOD(m);
    HRESULT hr = iu_call(NULL);
    CHECK(SUCCEEDED(hr));
    CHECK(hr != E_INVALIDARG);
    CHECK(hr != E_POINTER);
}
TEST(apv_iu_null_leaves_last_error_untouched) {
    APV_REQUIRE_MOD(m);
    apv_iuvpaa_fn f = apv_iuvpaa();
    SET_ERR(0x1234);
    f(NULL);
    EXPECT_ERR(0x1234);
}
TEST(apv_iu_null_100_times) {
    APV_REQUIRE_MOD(m);
    int bad = 0;
    for (int i = 0; i < 100; i++) if (iu_call(NULL) != S_OK) bad++;
    EXPECT_EQ(bad, 0);
}
TEST(apv_iu_null_then_valid_still_works) {
    APV_REQUIRE_MOD(m);
    EXPECT_EQ(iu_call(NULL), S_OK);
    BOOL b = 0x55;
    EXPECT_EQ(iu_call(&b), S_OK);
    CHECK(b == 0 || b == 1);
}

/* ---- valid out pointer --------------------------------------------------- */
TEST(apv_iu_valid_returns_s_ok) {
    APV_REQUIRE_MOD(m);
    BOOL b = 0xCCCCCCCC;
    EXPECT_EQ(iu_call(&b), S_OK);
}
TEST(apv_iu_valid_writes_boolean_0_or_1) {
    APV_REQUIRE_MOD(m);
    BOOL b = 0xCCCCCCCC;
    iu_call(&b);
    CHECKF(b == 0 || b == 1, "value 0x%x", (unsigned)b);
    t_note("user-verifying platform authenticator available: %d", (int)b);
}
TEST(apv_iu_value_is_hresult_independent_range) {
    APV_REQUIRE_MOD(m);
    BOOL b = -1;
    HRESULT hr = iu_call(&b);
    CHECK(hr == S_OK && (unsigned)b <= 1u);
}
TEST(apv_iu_prefill_does_not_leak_through) {
    /* *pb is reset to FALSE before the query, so no prefill value can survive other than via the answer. */
    APV_REQUIRE_MOD(m);
    static const unsigned prefill[] = { 0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xCCCCCCCC, 0x00010000, 0x100 };
    BOOL base = 0xAAAAAAAA;
    EXPECT_EQ(iu_call(&base), S_OK);
    for (unsigned i = 0; i < sizeof prefill / sizeof *prefill; i++) {
        BOOL b = (BOOL)prefill[i];
        HRESULT hr = iu_call(&b);
        CHECKF(hr == S_OK, "prefill 0x%x hr 0x%lx", prefill[i], hr);
        CHECKF(b == base, "prefill 0x%x -> %d, baseline %d", prefill[i], (int)b, (int)base);
    }
}
TEST(apv_iu_prefill_true_can_be_reset_to_false) {
    APV_REQUIRE_MOD(m);
    BOOL base = 0;
    iu_call(&base);
    BOOL b = TRUE;
    iu_call(&b);
    EXPECT_EQ(b, base);
}
TEST(apv_iu_writes_only_four_bytes) {
    APV_REQUIRE_MOD(m);
    struct { uint32_t pre[4]; BOOL v; uint32_t post[4]; } g;
    memset(&g, 0xA5, sizeof g);
    EXPECT_EQ(iu_call(&g.v), S_OK);
    int bad = 0;
    for (int i = 0; i < 4; i++) { if (g.pre[i] != 0xA5A5A5A5u) bad++; if (g.post[i] != 0xA5A5A5A5u) bad++; }
    EXPECT_EQ(bad, 0);
    CHECK(g.v == 0 || g.v == 1);
}
TEST(apv_iu_writes_only_four_bytes_null_untouched) {
    APV_REQUIRE_MOD(m);
    BYTE buf[16]; memset(buf, 0x3C, sizeof buf);
    iu_call(NULL);
    int bad = 0;
    for (int i = 0; i < 16; i++) if (buf[i] != 0x3C) bad++;
    EXPECT_EQ(bad, 0);
}
TEST(apv_iu_out_at_end_of_committed_page) {
    /* The BOOL is the last 4 bytes of a committed page followed by a NOACCESS page: any wider write would fault. */
    APV_REQUIRE_MOD(m);
    BYTE *p = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc failed"); return; }
    DWORD old;
    VirtualProtect(p + 0x1000, 0x1000, PAGE_NOACCESS, &old);
    BOOL *b = (BOOL *)(p + 0x1000 - sizeof(BOOL));
    *b = 0x77;
    EXPECT_EQ(iu_call(b), S_OK);
    CHECK(*b == 0 || *b == 1);
    VirtualFree(p, 0, MEM_RELEASE);
}
TEST(apv_iu_out_at_start_of_committed_page) {
    APV_REQUIRE_MOD(m);
    BYTE *p = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) { t_skip("VirtualAlloc failed"); return; }
    DWORD old;
    VirtualProtect(p, 0x1000, PAGE_NOACCESS, &old);
    BOOL *b = (BOOL *)(p + 0x1000);
    *b = 0x77;
    EXPECT_EQ(iu_call(b), S_OK);
    CHECK(*b == 0 || *b == 1);
    VirtualFree(p, 0, MEM_RELEASE);
}
TEST(apv_iu_out_on_heap) {
    APV_REQUIRE_MOD(m);
    BOOL *b = HeapAlloc(GetProcessHeap(), 0, sizeof(BOOL));
    if (!b) { t_skip("alloc"); return; }
    *b = 9;
    EXPECT_EQ(iu_call(b), S_OK);
    CHECK(*b == 0 || *b == 1);
    HeapFree(GetProcessHeap(), 0, b);
}
static BOOL g_iu_global = 9;
TEST(apv_iu_out_in_global_data) {
    APV_REQUIRE_MOD(m);
    g_iu_global = 9;
    EXPECT_EQ(iu_call(&g_iu_global), S_OK);
    CHECK(g_iu_global == 0 || g_iu_global == 1);
}
TEST(apv_iu_out_in_array_element) {
    APV_REQUIRE_MOD(m);
    BOOL arr[3] = { 5, 5, 5 };
    EXPECT_EQ(iu_call(&arr[1]), S_OK);
    EXPECT_EQ(arr[0], 5);
    EXPECT_EQ(arr[2], 5);
    CHECK(arr[1] == 0 || arr[1] == 1);
}
TEST(apv_iu_out_as_dword_and_int_alias) {
    APV_REQUIRE_MOD(m);
    DWORD d = 0xFFFFFFFF;
    EXPECT_EQ(iu_call((BOOL *)&d), S_OK);
    CHECK(d == 0 || d == 1);
}
TEST(apv_iu_out_upper_bytes_of_wider_slot_untouched) {
    APV_REQUIRE_MOD(m);
    uint64_t slot = 0xDEADBEEF00000000ull | 0x5A5A5A5Au;
    EXPECT_EQ(iu_call((BOOL *)&slot), S_OK);
    EXPECT_EQ((uint32_t)(slot >> 32), 0xDEADBEEFu);
    CHECK((uint32_t)slot <= 1u);
}

/* ---- repetition ---------------------------------------------------------- */
TEST(apv_iu_repeat_50_consistent) {
    APV_REQUIRE_MOD(m);
    BOOL first = 0xAAAA, v; iu_call(&first);
    int diff = 0, bad_hr = 0;
    for (int i = 0; i < 50; i++) { v = 0xBBBB; if (iu_call(&v) != S_OK) bad_hr++; if (v != first) diff++; }
    EXPECT_EQ(bad_hr, 0);
    EXPECT_EQ(diff, 0);
}
TEST(apv_iu_repeat_with_null_interleaved) {
    APV_REQUIRE_MOD(m);
    BOOL first = 0; iu_call(&first);
    int diff = 0;
    for (int i = 0; i < 20; i++) { BOOL v = 7; iu_call(NULL); iu_call(&v); if (v != first) diff++; }
    EXPECT_EQ(diff, 0);
}
TEST(apv_iu_call_does_not_change_module_handle) {
    APV_REQUIRE_MOD(m);
    BOOL b; iu_call(&b);
    EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m);
}
TEST(apv_iu_does_not_change_api_version) {
    APV_REQUIRE_MOD(m);
    DWORD v0 = apv_getver()();
    BOOL b; iu_call(&b);
    EXPECT_EQ(apv_getver()(), v0);
}

/* ---- threads and COM apartments ----------------------------------------- */
typedef struct { DWORD coinit; int use_com; HRESULT cohr, hr, again; BOOL val; int rounds; BOOL first; int diff, bad_hr; HANDLE go; } iu_ctx;
static DWORD WINAPI iu_worker(LPVOID p) {
    iu_ctx *c = p;
    apv_iuvpaa_fn f = apv_iuvpaa();
    if (c->go) WaitForSingleObject(c->go, 5000);
    for (int i = 0; i < c->rounds; i++) {
        BOOL v = 0x1234;
        HRESULT hr = f(&v);
        if (hr != S_OK) c->bad_hr++;
        if (i == 0) c->first = v; else if (v != c->first) c->diff++;
    }
    return 0;
}
static DWORD WINAPI iu_com_worker(LPVOID p) {
    iu_ctx *c = p;
    c->cohr = c->use_com ? CoInitializeEx(NULL, c->coinit) : S_OK;
    c->val = 0xCCCC;
    c->hr = apv_iuvpaa()(&c->val);
    if (c->use_com && SUCCEEDED(c->cohr)) {
        c->again = CoInitializeEx(NULL, c->coinit);
        if (SUCCEEDED(c->again)) CoUninitialize();
        CoUninitialize();
    } else if (!c->use_com) {
        /* thread was never initialised: whatever the call did internally, a plain STA init must still be possible. */
        c->again = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(c->again)) CoUninitialize();
    }
    return 0;
}
static void iu_com(int use_com, DWORD coinit) {
    BOOL base = 0xAAAA; iu_call(&base);
    iu_ctx c; memset(&c, 0, sizeof c);
    c.coinit = coinit; c.use_com = use_com; c.hr = E_FAIL; c.again = E_FAIL;
    HANDLE h = CreateThread(NULL, 0, iu_com_worker, &c, 0, NULL);
    CHECK(h && apv_join(h, 20000));
    if (use_com) EXPECT_EQ(c.cohr, S_OK);
    EXPECT_EQ(c.hr, S_OK);
    CHECK(c.val == 0 || c.val == 1);
    EXPECT_EQ(c.val, base);
    if (use_com) EXPECT_EQ(c.again, S_FALSE);   /* apartment still initialised in the same mode */
    else t_note("CoInitializeEx(STA) after the call on a never-initialised thread: 0x%lx", c.again);
}
TEST(apv_iu_com_uninitialized_thread) { APV_REQUIRE_MOD(m); iu_com(0, 0); }
TEST(apv_iu_com_mta_thread) { APV_REQUIRE_MOD(m); iu_com(1, COINIT_MULTITHREADED); }
TEST(apv_iu_com_sta_thread) { APV_REQUIRE_MOD(m); iu_com(1, COINIT_APARTMENTTHREADED); }
TEST(apv_iu_com_sta_disable_ole1_thread) { APV_REQUIRE_MOD(m); iu_com(1, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE); }
TEST(apv_iu_com_mta_speed_over_memory_thread) { APV_REQUIRE_MOD(m); iu_com(1, COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY); }
static DWORD WINAPI iu_null_in_apartment(LPVOID p) {
    iu_ctx *c = p;
    c->cohr = CoInitializeEx(NULL, c->coinit);
    c->hr = apv_iuvpaa()(NULL);
    if (SUCCEEDED(c->cohr)) CoUninitialize();
    return 0;
}
static void iu_null_in(DWORD coinit) {
    iu_ctx c; memset(&c, 0, sizeof c); c.coinit = coinit; c.hr = E_FAIL;
    HANDLE h = CreateThread(NULL, 0, iu_null_in_apartment, &c, 0, NULL);
    CHECK(h && apv_join(h, 20000));
    EXPECT_EQ(c.cohr, S_OK);
    EXPECT_EQ(c.hr, S_OK);
}
TEST(apv_iu_null_pointer_in_mta) { APV_REQUIRE_MOD(m); iu_null_in(COINIT_MULTITHREADED); }
TEST(apv_iu_null_pointer_in_sta) { APV_REQUIRE_MOD(m); iu_null_in(COINIT_APARTMENTTHREADED); }

TEST(apv_iu_sequential_apartment_switching_threads) {
    /* A sequence of fresh threads alternating MTA / STA / none all see the same answer. */
    APV_REQUIRE_MOD(m);
    BOOL base = 0; iu_call(&base);
    int bad = 0;
    static const DWORD modes[] = { COINIT_MULTITHREADED, COINIT_APARTMENTTHREADED, 0xFFFFFFFF };
    for (int i = 0; i < 9; i++) {
        iu_ctx c; memset(&c, 0, sizeof c);
        DWORD md = modes[i % 3];
        c.use_com = md != 0xFFFFFFFF; c.coinit = md; c.hr = E_FAIL; c.again = E_FAIL;
        HANDLE h = CreateThread(NULL, 0, iu_com_worker, &c, 0, NULL);
        if (!h || !apv_join(h, 20000) || c.hr != S_OK || c.val != base) bad++;
    }
    EXPECT_EQ(bad, 0);
}
static void iu_parallel(int n, int rounds) {
    BOOL base = 0; iu_call(&base);
    iu_ctx c[16]; HANDLE h[16];
    HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (n > 16) n = 16;
    for (int i = 0; i < n; i++) {
        memset(&c[i], 0, sizeof c[i]); c[i].rounds = rounds; c[i].go = go;
        h[i] = CreateThread(NULL, 0, iu_worker, &c[i], 0, NULL);
    }
    SetEvent(go);
    int joined = 0, diff = 0, bad_hr = 0, notbase = 0;
    for (int i = 0; i < n; i++) {
        if (!h[i] || !apv_join(h[i], 30000)) continue;
        joined++; diff += c[i].diff; bad_hr += c[i].bad_hr; if (c[i].first != base) notbase++;
    }
    CloseHandle(go);
    EXPECT_EQ(joined, n);
    EXPECT_EQ(bad_hr, 0);
    EXPECT_EQ(diff, 0);
    EXPECT_EQ(notbase, 0);
}
TEST(apv_iu_parallel_2_threads) { APV_REQUIRE_MOD(m); iu_parallel(2, 20); }
TEST(apv_iu_parallel_4_threads) { APV_REQUIRE_MOD(m); iu_parallel(4, 20); }
TEST(apv_iu_parallel_8_threads) { APV_REQUIRE_MOD(m); iu_parallel(8, 10); }
TEST(apv_iu_fresh_thread_sequence) {
    APV_REQUIRE_MOD(m);
    BOOL base = 0; iu_call(&base);
    int bad = 0;
    for (int i = 0; i < 10; i++) {
        iu_ctx c; memset(&c, 0, sizeof c); c.rounds = 1;
        HANDLE h = CreateThread(NULL, 0, iu_worker, &c, 0, NULL);
        if (!h || !apv_join(h, 20000) || c.bad_hr || c.first != base) bad++;
    }
    EXPECT_EQ(bad, 0);
}

/* ---- impersonation ------------------------------------------------------- */
static DWORD WINAPI iu_imp_self(LPVOID p) {
    iu_ctx *c = p;
    c->cohr = E_FAIL; c->hr = E_FAIL; c->val = 0xCCCC;
    if (ImpersonateSelf(SecurityImpersonation)) {
        c->cohr = S_OK;
        c->hr = apv_iuvpaa()(&c->val);
        RevertToSelf();
    }
    return 0;
}
TEST(apv_iu_impersonating_self_same_answer) {
    APV_REQUIRE_MOD(m);
    BOOL base = 0; iu_call(&base);
    iu_ctx c; memset(&c, 0, sizeof c);
    HANDLE h = CreateThread(NULL, 0, iu_imp_self, &c, 0, NULL);
    CHECK(h && apv_join(h, 20000));
    if (c.cohr != S_OK) { t_skip("ImpersonateSelf failed"); return; }
    EXPECT_EQ(c.hr, S_OK);
    EXPECT_EQ(c.val, base);
}
static DWORD WINAPI iu_imp_anon(LPVOID p) {
    iu_ctx *c = p;
    c->cohr = E_FAIL; c->hr = E_FAIL; c->val = 0xCCCC;
    HANDLE th = GetCurrentThread();
    if (ImpersonateAnonymousToken(th)) {
        c->cohr = S_OK;
        c->hr = apv_iuvpaa()(&c->val);
        RevertToSelf();
    }
    return 0;
}
TEST(apv_iu_impersonating_anonymous_still_s_ok) {
    /* Internal failures are swallowed: the HRESULT stays S_OK and the BOOL is still a clean 0/1. */
    APV_REQUIRE_MOD(m);
    iu_ctx c; memset(&c, 0, sizeof c);
    HANDLE h = CreateThread(NULL, 0, iu_imp_anon, &c, 0, NULL);
    CHECK(h && apv_join(h, 20000));
    if (c.cohr != S_OK) { t_skip("ImpersonateAnonymousToken failed"); return; }
    EXPECT_EQ(c.hr, S_OK);
    CHECK(c.val == 0 || c.val == 1);
    t_note("answer while impersonating anonymous: %d", (int)c.val);
}

/* ---- other processes ----------------------------------------------------- */
/* exit code: 0x100 | (S_OK ? 0 : 0x200) | (value << 4) */
CHILD(apv_iu_child) {
    HMODULE m = LoadLibraryA(APV_DLL);
    if (!m) return 0x77;
    apv_iuvpaa_fn f = (apv_iuvpaa_fn)GetProcAddress(m, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    if (!f) return 0x78;
    BOOL b = 0x55;
    HRESULT hr = f(&b);
    return 0x100 | (hr == S_OK ? 0 : 0x200) | ((b & 0xF) << 4);
}
TEST(apv_iu_child_process_agrees) {
    APV_REQUIRE_MOD(m);
    BOOL b = 0; iu_call(&b);
    DWORD rc = t_run_child("apv_iu_child", "", 30000);
    EXPECT_EQ(rc, 0x100 | ((b & 0xF) << 4));
}
CHILD(apv_iu_child_mta_exit) {
    /* Leaves COM initialised and the module loaded at exit; process teardown must not hang. */
    HMODULE m = LoadLibraryA(APV_DLL);
    if (!m) return 0x77;
    apv_iuvpaa_fn f = (apv_iuvpaa_fn)GetProcAddress(m, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL b = 0; HRESULT hr = f(&b);
    return hr == S_OK ? 0 : 1;
}
TEST(apv_iu_child_exits_cleanly_with_mta_and_module_loaded) {
    APV_REQUIRE_MOD(m);
    EXPECT_EQ(t_run_child("apv_iu_child_mta_exit", "", 30000), 0);
}
CHILD(apv_iu_child_sta_exit) {
    HMODULE m = LoadLibraryA(APV_DLL);
    if (!m) return 0x77;
    apv_iuvpaa_fn f = (apv_iuvpaa_fn)GetProcAddress(m, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL b = 0; HRESULT hr = f(&b);
    ExitProcess(hr == S_OK ? 0 : 1);
    return 2;
}
TEST(apv_iu_child_exitprocess_with_sta_and_module_loaded) {
    APV_REQUIRE_MOD(m);
    EXPECT_EQ(t_run_child("apv_iu_child_sta_exit", "", 30000), 0);
}
CHILD(apv_iu_child_thread_exit) {
    /* A worker thread calls the API and exits; the process then ends normally. */
    HMODULE m = LoadLibraryA(APV_DLL);
    if (!m) return 0x77;
    iu_ctx c; memset(&c, 0, sizeof c); c.rounds = 2;
    HANDLE h = CreateThread(NULL, 0, iu_worker, &c, 0, NULL);
    if (!h || WaitForSingleObject(h, 20000) != WAIT_OBJECT_0) return 3;
    return c.bad_hr ? 1 : 0;
}
TEST(apv_iu_child_worker_thread_then_exit) {
    APV_REQUIRE_MOD(m);
    EXPECT_EQ(t_run_child("apv_iu_child_thread_exit", "", 30000), 0);
}

/* The call is safe to repeat while another thread queries the API version at the same time. */
static DWORD WINAPI iu_mix_ver(LPVOID p) { iu_ctx *c = p; for (int i = 0; i < 50; i++) if (apv_getver()() > 2) c->diff++; return 0; }
TEST(apv_iu_concurrent_with_version_query) {
    APV_REQUIRE_MOD(m);
    BOOL base = 0; iu_call(&base);
    iu_ctx c; memset(&c, 0, sizeof c); c.rounds = 10;
    HANDLE h[2];
    h[0] = CreateThread(NULL, 0, iu_worker, &c, 0, NULL);
    iu_ctx d; memset(&d, 0, sizeof d);
    h[1] = CreateThread(NULL, 0, iu_mix_ver, &d, 0, NULL);
    CHECK(h[0] && apv_join(h[0], 20000));
    CHECK(h[1] && apv_join(h[1], 20000));
    EXPECT_EQ(c.bad_hr, 0);
    EXPECT_EQ(c.diff, 0);
    EXPECT_EQ(d.diff, 0);
    EXPECT_EQ(c.first, base);
}
