#include "pc.h"
/* WebAuthNGetPlatformCredentials: early parameter validation only (decomp: arg1 == 0 || ppList == NULL
 * -> return 0x80090027 before anything else, *ppList untouched). */

#define SENT ((PVOID)(ULONG_PTR)0x5A5A5A5A5A5A5A5AULL)

static HRESULT call(pc_get_fn f, ULONG_PTR a1, PCWSTR rp, PVOID *out) { return f(a1, rp, out); }

TEST(pc_get_exported_by_name) { REQUIRE(pc_get()); CHECK(pc_get() != NULL); }
TEST(pc_get_ordinal_54) {
    FARPROC o = t_proc_ord("webauthn.dll", 54); REQUIRE(o);
    EXPECT_EQ(o, t_proc_in("webauthn.dll", "WebAuthNGetPlatformCredentials"));
}
TEST(pc_free_ordinal_47) {
    FARPROC o = t_proc_ord("webauthn.dll", 47); REQUIRE(o);
    EXPECT_EQ(o, t_proc_in("webauthn.dll", "WebAuthNFreePlatformCredentials"));
}
TEST(pc_delete_ordinal_41) {
    FARPROC o = t_proc_ord("webauthn.dll", 41); REQUIRE(o);
    EXPECT_EQ(o, t_proc_in("webauthn.dll", "WebAuthNDeletePlatformCredential"));
}
TEST(pc_freeue_ordinal_48) {
    FARPROC o = t_proc_ord("webauthn.dll", 48); REQUIRE(o);
    EXPECT_EQ(o, t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"));
}
TEST(pc_no_list_options_export) {
    /* The options-struct style query exports do not exist on this build. */
    REQUIRE(pc_get());
    CHECK(t_proc_in("webauthn.dll", "WebAuthNGetPlatformCredentialList") == NULL);
    CHECK(t_proc_in("webauthn.dll", "WebAuthNFreePlatformCredentialList") == NULL);
    CHECK(t_proc_in("webauthn.dll", "WebAuthNGetPlatformCredentialsList") == NULL);
}

/* ---- ppList == NULL ---------------------------------------------------- */
#define NULLOUT_TEST(nm, a1, rp) \
    TEST(pc_get_nullout_##nm) { pc_get_fn f = pc_get(); REQUIRE(f); \
        HRESULT hr = call(f, a1, rp, NULL); EXPECT_EQ((DWORD)hr, (DWORD)PC_NTE_INVALID_PARAMETER); }
NULLOUT_TEST(a1_1_rp_null, 1, NULL)
NULLOUT_TEST(a1_1_rp_empty, 1, L"")
NULLOUT_TEST(a1_1_rp_dot, 1, L"example.com")
NULLOUT_TEST(a1_2_rp_null, 2, NULL)
NULLOUT_TEST(a1_0x10_rp_null, 0x10, NULL)
NULLOUT_TEST(a1_0xffff_rp_dot, 0xFFFF, L"login.example.test")
NULLOUT_TEST(a1_0x12345678_rp_null, 0x12345678, NULL)
NULLOUT_TEST(a1_0_rp_null, 0, NULL)
NULLOUT_TEST(a1_0_rp_dot, 0, L"example.com")
NULLOUT_TEST(a1_0_rp_empty, 0, L"")
NULLOUT_TEST(a1_hi_rp_null, ((ULONG_PTR)1 << 40), NULL)
NULLOUT_TEST(a1_hi_rp_dot, ((ULONG_PTR)1 << 40), L"example.com")
NULLOUT_TEST(a1_all_ones_rp_null, (ULONG_PTR)-1, NULL)
NULLOUT_TEST(a1_all_ones_rp_dot, (ULONG_PTR)-1, L"example.com")
NULLOUT_TEST(a1_low32_zero_hi_set, ((ULONG_PTR)1 << 32), NULL)

TEST(pc_get_nullout_long_rpid) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    static WCHAR rp[1025]; for (int i = 0; i < 1024; i++) rp[i] = L'a' + (i % 26); rp[1024] = 0;
    EXPECT_EQ((DWORD)call(f, 1, rp, NULL), (DWORD)PC_NTE_INVALID_PARAMETER);
}
TEST(pc_get_nullout_rpid_non_ascii) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    EXPECT_EQ((DWORD)call(f, 1, L"b\x00fc" L"cher.example", NULL), (DWORD)PC_NTE_INVALID_PARAMETER);
}
TEST(pc_get_nullout_failure_is_negative_hresult) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    HRESULT hr = call(f, 1, NULL, NULL);
    CHECK(FAILED(hr)); EXPECT_EQ(HRESULT_FACILITY(hr), 9); /* FACILITY_SECURITY (NTE_*) */
}
TEST(pc_get_nullout_repeatable) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    for (int i = 0; i < 50; i++) EXPECT_EQ((DWORD)call(f, 1, NULL, NULL), (DWORD)PC_NTE_INVALID_PARAMETER);
}
TEST(pc_get_nullout_all_args_null) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    EXPECT_EQ((DWORD)call(f, 0, NULL, NULL), (DWORD)PC_NTE_INVALID_PARAMETER);
}
TEST(pc_get_nullout_not_win32_error) {
    /* The result is an HRESULT return value, not delivered through SetLastError. */
    pc_get_fn f = pc_get(); REQUIRE(f);
    SET_ERR(0x1357); HRESULT hr = call(f, 1, NULL, NULL); DWORD e = GetLastError();
    EXPECT_EQ((DWORD)hr, (DWORD)PC_NTE_INVALID_PARAMETER);
    if (e != 0x1357) t_note("pc_get early failure changed last error to %lu", e);
}

/* ---- arg1 == 0 with a valid out pointer: out is not written ------------- */
#define ZEROA1_TEST(nm, rp) \
    TEST(pc_get_zero_arg1_##nm) { pc_get_fn f = pc_get(); REQUIRE(f); \
        PVOID out = SENT; HRESULT hr = call(f, 0, rp, &out); \
        EXPECT_EQ((DWORD)hr, (DWORD)PC_NTE_INVALID_PARAMETER); EXPECT_EQ(out, SENT); }
ZEROA1_TEST(rp_null, NULL)
ZEROA1_TEST(rp_empty, L"")
ZEROA1_TEST(rp_example, L"example.com")
ZEROA1_TEST(rp_sub, L"a.b.c.example.test")
ZEROA1_TEST(rp_upper, L"EXAMPLE.COM")
ZEROA1_TEST(rp_space, L" ")
ZEROA1_TEST(rp_url, L"https://example.com")

TEST(pc_get_zero_arg1_out_null_ptr_value_kept) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    PVOID out = NULL; HRESULT hr = call(f, 0, L"example.com", &out);
    EXPECT_EQ((DWORD)hr, (DWORD)PC_NTE_INVALID_PARAMETER); EXPECT_EQ(out, NULL);
}
TEST(pc_get_zero_arg1_out_not_freed_or_touched_twice) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    PVOID out = SENT;
    for (int i = 0; i < 20; i++) { EXPECT_EQ((DWORD)call(f, 0, NULL, &out), (DWORD)PC_NTE_INVALID_PARAMETER); EXPECT_EQ(out, SENT); }
}
TEST(pc_get_zero_arg1_out_existing_alloc_preserved) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    void *blk = LocalAlloc(LPTR, 32); PVOID out = blk;
    EXPECT_EQ((DWORD)call(f, 0, NULL, &out), (DWORD)PC_NTE_INVALID_PARAMETER);
    EXPECT_EQ(out, blk);
    CHECK(LocalSize(blk) >= 32); /* block was not freed by the call */
    LocalFree(blk);
}
TEST(pc_get_zero_arg1_stack_out_array_untouched) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    PVOID arr[4] = { SENT, SENT, SENT, SENT };
    EXPECT_EQ((DWORD)call(f, 0, NULL, &arr[1]), (DWORD)PC_NTE_INVALID_PARAMETER);
    for (int i = 0; i < 4; i++) EXPECT_EQ(arr[i], SENT);
}

/* ---- result list for failed query must be treated as absent; free(NULL) ok */
TEST(pc_get_failed_query_then_free_null_out) {
    pc_get_fn f = pc_get(); pc_free_fn fr = pc_freepc(); REQUIRE(f); REQUIRE(fr);
    PVOID out = NULL;
    EXPECT_EQ((DWORD)call(f, 0, NULL, &out), (DWORD)PC_NTE_INVALID_PARAMETER);
    fr(out); /* NULL: no-op */
    CHECK(1);
}
TEST(pc_get_failed_query_all_rps_table) {
    pc_get_fn f = pc_get(); REQUIRE(f);
    static const PCWSTR rps[] = { NULL, L"", L"a", L"example.com", L"EXAMPLE.COM", L"localhost", L"192.0.2.1",
        L"[::1]", L"example.com:443", L"a..b", L".", L"-", L"xn--bcher-kva.example", L"very.long.sub.domain.example.org" };
    for (unsigned i = 0; i < sizeof rps / sizeof *rps; i++) {
        PVOID out = SENT;
        HRESULT hr = call(f, 0, rps[i], &out);
        CHECKF((DWORD)hr == (DWORD)PC_NTE_INVALID_PARAMETER, "i=%u hr=0x%lx", i, (unsigned long)hr);
        CHECKF(out == SENT, "i=%u out modified", i);
        hr = call(f, 7, rps[i], NULL);
        CHECKF((DWORD)hr == (DWORD)PC_NTE_INVALID_PARAMETER, "null-out i=%u hr=0x%lx", i, (unsigned long)hr);
    }
}
static pc_get_fn tf;
static DWORD WINAPI th(LPVOID p) { PVOID out = SENT; HRESULT hr = tf(0, NULL, &out); return (hr == PC_NTE_INVALID_PARAMETER && out == SENT) ? 0 : 1; }
TEST(pc_get_validation_precedes_everything_threaded) {
    /* From a second thread the early validation behaves identically. */
    pc_get_fn f = pc_get(); REQUIRE(f);
    tf = f;
    HANDLE h = CreateThread(NULL, 0, th, NULL, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0);
    DWORD code = 99; GetExitCodeThread(h, &code); EXPECT_EQ(code, 0); CloseHandle(h);
}
