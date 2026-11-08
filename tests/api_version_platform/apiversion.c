/* WebAuthNGetApiVersionNumber: ordinal 49, DWORD WINAPI f(void).
 *
 * Behaviour taken from the Windows 10 19041 implementation: the function takes no inputs. In an
 * ordinary (non-remote) session it returns the constant 2 (WEBAUTHN_API_VERSION_2). Only when the
 * calling session is a remoteable terminal-services session does it ask the remote side and then
 * return min(remote, 2), or 0 if that query fails. It never returns a value above 2. */
#include "apv.h"

#define APV_MAX_API_VERSION 2u

static DWORD apv_expected_version(void) { return APV_MAX_API_VERSION; }

TEST(apv_ver_resolves) {
    APV_REQUIRE_MOD(m);
    CHECK(GetProcAddress(m, "WebAuthNGetApiVersionNumber") != NULL);
}
TEST(apv_ver_ordinal_49_is_it) {
    APV_REQUIRE_MOD(m);
    FARPROC byname = GetProcAddress(m, "WebAuthNGetApiVersionNumber");
    FARPROC byord = GetProcAddress(m, MAKEINTRESOURCEA(49));
    CHECK(byname != NULL);
    EXPECT_EQ(byname, byord);
}
TEST(apv_ver_returns_at_most_2) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD v = U(WebAuthNGetApiVersionNumber)();
    CHECKF(v <= APV_MAX_API_VERSION, "version %lu", v);
}
TEST(apv_ver_local_session_returns_2) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD v = U(WebAuthNGetApiVersionNumber)();
    t_note("api version %lu (remote session: %d)", v, apv_is_remote_session());
    if (apv_is_remote_session()) { t_skip("remote session takes the remote query path"); return; }
    EXPECT_EQ(v, apv_expected_version());
}
TEST(apv_ver_nonzero_locally) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    if (apv_is_remote_session()) { t_skip("remote session"); return; }
    CHECK(U(WebAuthNGetApiVersionNumber)() != 0);
}
TEST(apv_ver_is_current_api_version_of_header) {
    /* The SDK constant WEBAUTHN_API_CURRENT_VERSION for this API level is WEBAUTHN_API_VERSION_2. */
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    if (apv_is_remote_session()) { t_skip("remote session"); return; }
    EXPECT_EQ(U(WebAuthNGetApiVersionNumber)(), 2);
}
TEST(apv_ver_constant_over_100_calls) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD first = U(WebAuthNGetApiVersionNumber)();
    int diff = 0;
    for (int i = 0; i < 100; i++) if (U(WebAuthNGetApiVersionNumber)() != first) diff++;
    EXPECT_EQ(diff, 0);
}
TEST(apv_ver_constant_over_2000_calls) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD first = U(WebAuthNGetApiVersionNumber)();
    int diff = 0;
    for (int i = 0; i < 2000; i++) if (U(WebAuthNGetApiVersionNumber)() != first) diff++;
    EXPECT_EQ(diff, 0);
}
TEST(apv_ver_two_resolutions_same_pointer) {
    APV_REQUIRE_MOD(m);
    CHECK(GetProcAddress(m, "WebAuthNGetApiVersionNumber") == GetProcAddress(m, "WebAuthNGetApiVersionNumber"));
}
TEST(apv_ver_pointer_inside_image) {
    APV_REQUIRE_MOD(m);
    const IMAGE_NT_HEADERS64 *n = apv_nt(m);
    BYTE *p = (BYTE *)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
    CHECK(n && p >= (BYTE *)m && p < (BYTE *)m + n->OptionalHeader.SizeOfImage);
}
TEST(apv_ver_export_rva_in_text) {
    APV_REQUIRE_MOD(m);
    BYTE *p = (BYTE *)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
    const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, (DWORD)(p - (BYTE *)m));
    CHECK(s && !strncmp((const char *)s->Name, ".text", 8));
}

/* ---- threads ------------------------------------------------------------ */
typedef struct { DWORD first; int diff; int calls; HANDLE go; } ver_ctx;
static DWORD WINAPI ver_worker(LPVOID p) {
    ver_ctx *c = p;
    apv_getver_fn f = apv_getver();
    if (c->go) WaitForSingleObject(c->go, 5000);
    for (int i = 0; i < c->calls; i++) {
        DWORD v = f();
        if (i == 0) c->first = v;
        else if (v != c->first) c->diff++;
    }
    return 0;
}
TEST(apv_ver_fresh_thread) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD main_v = U(WebAuthNGetApiVersionNumber)();
    ver_ctx c = { 0, 0, 1, NULL };
    HANDLE h = CreateThread(NULL, 0, ver_worker, &c, 0, NULL);
    CHECK(h && apv_join(h, 10000));
    EXPECT_EQ(c.first, main_v);
}
TEST(apv_ver_20_sequential_threads) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD main_v = U(WebAuthNGetApiVersionNumber)();
    int bad = 0;
    for (int i = 0; i < 20; i++) {
        ver_ctx c = { 0xFFFFFFFF, 0, 1, NULL };
        HANDLE h = CreateThread(NULL, 0, ver_worker, &c, 0, NULL);
        if (!h || !apv_join(h, 10000) || c.first != main_v) bad++;
    }
    EXPECT_EQ(bad, 0);
}
static void ver_parallel(int nthreads, int calls) {
    DWORD main_v = U(WebAuthNGetApiVersionNumber)();
    HANDLE go = CreateEventW(NULL, TRUE, FALSE, NULL);
    ver_ctx c[16]; HANDLE h[16];
    if (nthreads > 16) nthreads = 16;
    for (int i = 0; i < nthreads; i++) {
        c[i] = (ver_ctx){ 0xFFFFFFFF, 0, calls, go };
        h[i] = CreateThread(NULL, 0, ver_worker, &c[i], 0, NULL);
    }
    SetEvent(go);
    int diffs = 0, firstbad = 0, notjoined = 0;
    for (int i = 0; i < nthreads; i++) {
        if (!h[i] || !apv_join(h[i], 15000)) { notjoined++; continue; }
        diffs += c[i].diff;
        if (c[i].first != main_v) firstbad++;
    }
    CloseHandle(go);
    EXPECT_EQ(notjoined, 0);
    EXPECT_EQ(diffs, 0);
    EXPECT_EQ(firstbad, 0);
}
TEST(apv_ver_parallel_2_threads) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_parallel(2, 500); }
TEST(apv_ver_parallel_4_threads) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_parallel(4, 500); }
TEST(apv_ver_parallel_8_threads) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_parallel(8, 500); }
TEST(apv_ver_parallel_16_threads) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_parallel(16, 200); }

/* ---- COM apartment state of the caller does not matter ------------------- */
typedef struct { DWORD coinit; int use_com; HRESULT cohr; DWORD v; HRESULT again; } ver_com_ctx;
static DWORD WINAPI ver_com_worker(LPVOID p) {
    ver_com_ctx *c = p;
    if (c->use_com) c->cohr = CoInitializeEx(NULL, c->coinit);
    c->v = apv_getver()();
    if (c->use_com && SUCCEEDED(c->cohr)) {
        c->again = CoInitializeEx(NULL, c->coinit);   /* still initialised as before: S_FALSE */
        if (SUCCEEDED(c->again)) CoUninitialize();
        CoUninitialize();
    }
    return 0;
}
static void ver_com(int use_com, DWORD coinit, const char *label) {
    DWORD base = U(WebAuthNGetApiVersionNumber)();
    ver_com_ctx c = { coinit, use_com, E_FAIL, 0xFFFFFFFF, E_FAIL };
    HANDLE h = CreateThread(NULL, 0, ver_com_worker, &c, 0, NULL);
    CHECK(h && apv_join(h, 15000));
    if (use_com) EXPECT_EQ(c.cohr, S_OK);
    EXPECT_EQ(c.v, base);
    if (use_com) { EXPECT_EQ(c.again, S_FALSE); }
}
TEST(apv_ver_com_uninitialized_thread) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_com(0, 0, "none"); }
TEST(apv_ver_com_mta_thread) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_com(1, COINIT_MULTITHREADED, "mta"); }
TEST(apv_ver_com_sta_thread) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_com(1, COINIT_APARTMENTTHREADED, "sta"); }
TEST(apv_ver_com_sta_disable_ole1_thread) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_com(1, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE, "sta-noole1"); }
TEST(apv_ver_com_mta_speed_over_memory_thread) { REQUIRE(U(WebAuthNGetApiVersionNumber)); ver_com(1, COINIT_MULTITHREADED | COINIT_SPEED_OVER_MEMORY, "mta-fast"); }

/* ---- impersonation: the version is not per-user ------------------------- */
static DWORD WINAPI ver_imp_self(LPVOID p) {
    ver_ctx *c = p;
    c->first = 0xFFFFFFFF;
    if (ImpersonateSelf(SecurityImpersonation)) {
        c->first = apv_getver()();
        RevertToSelf();
    } else c->diff = 1;
    return 0;
}
TEST(apv_ver_under_impersonation_of_self) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    ver_ctx c = { 0, 0, 1, NULL };
    HANDLE h = CreateThread(NULL, 0, ver_imp_self, &c, 0, NULL);
    CHECK(h && apv_join(h, 10000));
    if (c.diff) { t_skip("ImpersonateSelf failed"); return; }
    EXPECT_EQ(c.first, U(WebAuthNGetApiVersionNumber)());
}

/* ---- another process ---------------------------------------------------- */
CHILD(apv_ver_child) {
    HMODULE m = LoadLibraryA(APV_DLL);
    if (!m) return 0x77;
    apv_getver_fn f = (apv_getver_fn)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
    if (!f) return 0x78;
    return (int)(0x100 + f());
}
TEST(apv_ver_child_process_agrees) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD rc = t_run_child("apv_ver_child", "", 30000);
    EXPECT_EQ(rc, 0x100 + U(WebAuthNGetApiVersionNumber)());
}
TEST(apv_ver_child_process_value_range) {
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    DWORD rc = t_run_child("apv_ver_child", "", 30000);
    CHECKF(rc >= 0x100 && rc <= 0x100 + APV_MAX_API_VERSION, "rc 0x%lx", rc);
}

/* ---- no side effects on module state ------------------------------------ */
TEST(apv_ver_does_not_change_module_handle) {
    APV_REQUIRE_MOD(m);
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    U(WebAuthNGetApiVersionNumber)();
    EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m);
}
static DWORD WINAPI ver_com_probe(LPVOID p) {
    ver_com_ctx *c = p;
    c->v = apv_getver()();
    c->cohr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(c->cohr)) CoUninitialize();
    return 0;
}
TEST(apv_ver_preserves_thread_com_state_uninitialized) {
    /* The call must not initialise COM on the caller: CoInitializeEx(STA) afterwards on the same fresh
     * thread is S_OK (not S_FALSE, not RPC_E_CHANGED_MODE). */
    REQUIRE(U(WebAuthNGetApiVersionNumber));
    if (apv_is_remote_session()) { t_skip("remote session may touch COM"); return; }
    ver_com_ctx c = { COINIT_APARTMENTTHREADED, 0, E_FAIL, 0, 0 };
    HANDLE h = CreateThread(NULL, 0, ver_com_probe, &c, 0, NULL);
    CHECK(h && apv_join(h, 10000));
    EXPECT_EQ(c.cohr, S_OK);
}
