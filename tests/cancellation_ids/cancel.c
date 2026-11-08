#include "cid.h"
/* WebAuthNCancelCurrentOperation: decomp is  I_NgcCancelCurrentOperation(id); return 0;
 * i.e. the return value is S_OK unconditionally for any id it is given. NULL is deliberately not passed
 * (the callee's handling is not visible in the webauthn.dll decomp). No operation is ever started here. */

static const GUID k_known = {0x6b29fc40, 0xca47, 0x1067, {0xb3, 0x1d, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda}};
static const GUID k_ones = {0xFFFFFFFF, 0xFFFF, 0xFFFF, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

TEST(cancel_export_resolves) { REQUIRE(CANCEL()); }
TEST(cancel_export_by_ordinal) {
    REQUIRE(CANCEL());
    EXPECT_EQ(t_proc_ord(CID_MOD, 9), CANCEL());
}
TEST(cancel_export_via_U) { REQUIRE(CANCEL()); }
TEST(cancel_export_case_sensitive) {
    REQUIRE(CANCEL());
    SET_ERR(0);
    CHECK(t_proc_in(CID_MOD, "WEBAUTHNCANCELCURRENTOPERATION") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(cancel_export_not_forwarded) {
    REQUIRE(CANCEL());
    HMODULE m = t_module(CID_MOD);
    char *p = (char *)CANCEL();
    CHECK(m != NULL && cid_in_image((const char *)m, p));
}
TEST(cancel_distinct_from_getid) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    CHECK((void *)CANCEL() != (void *)GETID());
}
TEST(cancel_never_used_id_returns_s_ok) {
    REQUIRE(CANCEL());
    EXPECT_EQ(CANCEL()(&k_known), S_OK);
}
TEST(cancel_nil_guid_returns_s_ok) {
    REQUIRE(CANCEL());
    GUID z; memset(&z, 0, sizeof z);
    EXPECT_EQ(CANCEL()(&z), S_OK);
}
TEST(cancel_all_ones_guid_returns_s_ok) {
    REQUIRE(CANCEL());
    EXPECT_EQ(CANCEL()(&k_ones), S_OK);
}
TEST(cancel_fresh_id_returns_s_ok) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    EXPECT_EQ(CANCEL()(&g), S_OK);
}
TEST(cancel_fresh_id_twice) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    EXPECT_EQ(CANCEL()(&g), S_OK);
    EXPECT_EQ(CANCEL()(&g), S_OK);
}
TEST(cancel_fresh_id_many_times) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    for (int i = 0; i < 20; i++) CHECK(CANCEL()(&g) == S_OK);
}
TEST(cancel_same_const_guid_repeated) {
    REQUIRE(CANCEL());
    for (int i = 0; i < 20; i++) CHECK(CANCEL()(&k_known) == S_OK);
}
TEST(cancel_does_not_modify_input) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g, c; CHECK(GETID()(&g) == S_OK); c = g;
    CHECK(CANCEL()(&g) == S_OK);
    CHECK(cid_eq(&g, &c));
}
TEST(cancel_does_not_invalidate_getid) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID a, b;
    CHECK(GETID()(&a) == S_OK);
    CHECK(CANCEL()(&a) == S_OK);
    CHECK(GETID()(&b) == S_OK);
    CHECK(!cid_eq(&a, &b));
    CHECK(!cid_is_nil(&b));
}
TEST(cancel_one_hundred_distinct_ids) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    for (int i = 0; i < 100; i++) {
        GUID g; CHECK(GETID()(&g) == S_OK);
        if (CANCEL()(&g) != S_OK) { CHECKF(0, "iter %d", i); break; }
    }
}
TEST(cancel_misaligned_guid) {
    REQUIRE(CANCEL());
    unsigned char buf[32]; memcpy(buf + 1, &k_known, 16);
    EXPECT_EQ(CANCEL()((const GUID *)(buf + 1)), S_OK);
}
TEST(cancel_heap_guid) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID *g = (GUID *)HeapAlloc(GetProcessHeap(), 0, sizeof(GUID));
    if (!g) { CHECK(0); return; }
    CHECK(GETID()(g) == S_OK);
    EXPECT_EQ(CANCEL()(g), S_OK);
    HeapFree(GetProcessHeap(), 0, g);
}
TEST(cancel_returns_success_hresult) {
    REQUIRE(CANCEL());
    HRESULT hr = CANCEL()(&k_known);
    CHECK(SUCCEEDED(hr));
    CHECK(hr == 0);
}
TEST(cancel_upper_dword_of_return_clear) {
    REQUIRE(CANCEL());
    /* decomp returns a full 64-bit zero; the HRESULT is the low 32 bits */
    unsigned long long (WINAPI *f)(const GUID *) = (unsigned long long (WINAPI *)(const GUID *))CANCEL();
    unsigned long long r = f(&k_known);
    EXPECT_EQ((DWORD)r, 0);
}

/* concurrency */
static GUID g_shared;
static volatile LONG g_bad;
static DWORD WINAPI thr_cancel(LPVOID p) {
    for (int i = 0; i < 50; i++) if (CANCEL()(&g_shared) != S_OK) InterlockedIncrement(&g_bad);
    return 0;
}
TEST(cancel_from_other_thread) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    CHECK(GETID()(&g_shared) == S_OK);
    g_bad = 0;
    HANDLE h = CreateThread(NULL, 0, thr_cancel, NULL, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    EXPECT_EQ(g_bad, 0);
}
TEST(cancel_concurrent_same_id) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    CHECK(GETID()(&g_shared) == S_OK);
    g_bad = 0;
    HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, thr_cancel, NULL, 0, NULL);
    CHECK(WaitForMultipleObjects(4, h, TRUE, 15000) == WAIT_OBJECT_0);
    for (int i = 0; i < 4; i++) CloseHandle(h[i]);
    EXPECT_EQ(g_bad, 0);
}
static DWORD WINAPI thr_gen_cancel(LPVOID p) {
    for (int i = 0; i < 100; i++) {
        GUID g;
        if (GETID()(&g) != S_OK) { InterlockedIncrement(&g_bad); continue; }
        if (CANCEL()(&g) != S_OK) InterlockedIncrement(&g_bad);
    }
    return 0;
}
TEST(cancel_concurrent_generate_and_cancel) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    g_bad = 0;
    HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, thr_gen_cancel, NULL, 0, NULL);
    CHECK(WaitForMultipleObjects(4, h, TRUE, 20000) == WAIT_OBJECT_0);
    for (int i = 0; i < 4; i++) CloseHandle(h[i]);
    EXPECT_EQ(g_bad, 0);
}
static DWORD WINAPI thr_cancel_arg(LPVOID p) { return (DWORD)CANCEL()((const GUID *)p); }
TEST(cancel_id_made_on_other_thread) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    HANDLE h = CreateThread(NULL, 0, thr_cancel_arg, &g, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    DWORD c = 99; GetExitCodeThread(h, &c); CloseHandle(h);
    EXPECT_EQ(c, 0);
}

CHILD(cancel_child) {
    if (!CANCEL() || !GETID()) return 90;
    GUID g;
    if (GETID()(&g) != S_OK) return 91;
    if (CANCEL()(&g) != S_OK) return 92;
    if (CANCEL()(&g) != S_OK) return 93;
    GUID z = {0};
    if (CANCEL()(&z) != S_OK) return 94;
    return 0;
}
TEST(cancel_in_fresh_process) {
    REQUIRE(CANCEL());
    EXPECT_EQ(t_run_child("cancel_child", "", 20000), 0);
}
CHILD(cancel_foreign_child) {
    /* id generated in the parent, passed by hex on the command line */
    if (argc < 2 || strlen(argv[1]) != 32 || !CANCEL()) return 90;
    GUID g; unsigned char *b = (unsigned char *)&g;
    for (int i = 0; i < 16; i++) { unsigned v; if (sscanf(argv[1] + 2 * i, "%2x", &v) != 1) return 91; b[i] = (unsigned char)v; }
    return CANCEL()(&g) == S_OK ? 0 : 92;
}
TEST(cancel_id_from_other_process) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    char hex[40]; unsigned char *b = (unsigned char *)&g;
    for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", b[i]);
    EXPECT_EQ(t_run_child("cancel_foreign_child", hex, 20000), 0);
    CHECK(CANCEL()(&g) == S_OK);
}
TEST(cancel_bounded_runtime) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    DWORD t0 = GetTickCount();
    for (int i = 0; i < 50; i++) { GUID g; GETID()(&g); CANCEL()(&g); }
    DWORD dt = GetTickCount() - t0;
    CHECKF(dt < 30000, "took %lu ms", dt);
    t_note("50 get+cancel took %lu ms", dt);
}
TEST(cancel_null_pointer_not_exercised) {
    REQUIRE(CANCEL());
    t_note("NULL id is not passed: the decomp forwards it to I_NgcCancelCurrentOperation whose handling is not in webauthn.dll");
}

TEST(cancel_byte_pattern_table) {
    REQUIRE(CANCEL());
    for (int v = 0; v < 256; v += 17) {
        GUID g; memset(&g, v, sizeof g);
        if (CANCEL()(&g) != S_OK) { CHECKF(0, "pattern 0x%02x", v); break; }
    }
}
TEST(cancel_mutated_fresh_id) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    for (int b = 0; b < 16; b++) {
        GUID m = g; ((unsigned char *)&m)[b] ^= 0x01;
        if (CANCEL()(&m) != S_OK) { CHECKF(0, "byte %d", b); break; }
    }
}
TEST(cancel_does_not_modify_nil_input) {
    REQUIRE(CANCEL());
    GUID z; memset(&z, 0, sizeof z);
    CHECK(CANCEL()(&z) == S_OK);
    CHECK(cid_is_nil(&z));
}
TEST(cancel_interleaved_with_getid_same_thread) {
    REQUIRE(CANCEL()); REQUIRE(GETID());
    GUID a, b;
    CHECK(GETID()(&a) == S_OK);
    CHECK(GETID()(&b) == S_OK);
    CHECK(CANCEL()(&b) == S_OK);
    CHECK(CANCEL()(&a) == S_OK);
    CHECK(CANCEL()(&b) == S_OK);
}
