#include "gap4.h"
#include <objbase.h>
/* webauthn.dll helpers: WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable, WebAuthNGetCancellationId,
 * WebAuthNCancelCurrentOperation and the outer parameter check of WebAuthNAuthenticatorGetAssertion.
 *
 * Reference behaviour (Windows 10 19041 decompilation):
 *  IsUserVerifyingPlatformAuthenticatorAvailable(BOOL *p): p == NULL -> returns 0 and writes nothing; else
 *     writes exactly one 32-bit value (0, then possibly 1) and returns 0.
 *  GetCancellationId(GUID *g): UuidCreate(g); statuses >0 (RPC_S_UUID_LOCAL_ONLY) map to success; returns 0.
 *  CancelCurrentOperation(const GUID *g): returns 0.
 *  AuthenticatorGetAssertion: sets *ppAssertion = NULL first; RP id NULL, client data NULL, client data
 *     dwVersion/cbClientDataJSON/pbClientDataJSON/pwszHashAlgId zero, or options->dwVersion == 0 are all
 *     rejected with NTE_INVALID_PARAMETER (0x80090027) before any request is built. Those calls are run in a
 *     child process only on the build the proof was made against, so they can never reach UI or a device. */

UDECL(HRESULT, WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable, (BOOL *));
UDECL(HRESULT, WebAuthNGetCancellationId, (GUID *));
UDECL(HRESULT, WebAuthNCancelCurrentOperation, (const GUID *));
UDECL(HRESULT, WebAuthNAuthenticatorGetAssertion, (HWND, LPCWSTR, const void *, const void *, void **));
static WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable_pfn iu(void) { return (WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable_pfn)t_proc_in("webauthn.dll", "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"); }
static WebAuthNGetCancellationId_pfn gid(void) { return (WebAuthNGetCancellationId_pfn)t_proc_in("webauthn.dll", "WebAuthNGetCancellationId"); }
static WebAuthNCancelCurrentOperation_pfn can(void) { return (WebAuthNCancelCurrentOperation_pfn)t_proc_in("webauthn.dll", "WebAuthNCancelCurrentOperation"); }
static WebAuthNAuthenticatorGetAssertion_pfn gaf(void) { return (WebAuthNAuthenticatorGetAssertion_pfn)t_proc_in("webauthn.dll", "WebAuthNAuthenticatorGetAssertion"); }

/* ---- IsUserVerifyingPlatformAuthenticatorAvailable ---- */
TEST(gap4_iu_writes_one_dword_only) {
    REQUIRE(iu());
    DWORD buf[3] = { 0x7F7F7F7F, 0x5A5A5A5A, 0xA5A5A5A5 };
    HRESULT hr = iu()((BOOL *)&buf[0]);
    EXPECT_EQ(hr, 0);
    CHECK(buf[0] == 0 || buf[0] == 1);
    EXPECT_EQ(buf[1], 0x5A5A5A5A);
    EXPECT_EQ(buf[2], 0xA5A5A5A5);
}
TEST(gap4_iu_sentinel_values_all_overwritten) {
    REQUIRE(iu());
    static const DWORD sent[] = { 0, 1, 2, 0xFF, 0x80000000, 0xFFFFFFFF, 0x12345678 };
    for (size_t i = 0; i < sizeof sent / sizeof sent[0]; i++) {
        DWORD v = sent[i];
        HRESULT hr = iu()((BOOL *)&v);
        t_check(hr == 0, __FILE__, __LINE__, "hr == S_OK", "sentinel 0x%lx hr 0x%lx", (unsigned long)sent[i], (unsigned long)hr);
        t_check(v == 0 || v == 1, __FILE__, __LINE__, "result is 0 or 1", "sentinel 0x%lx -> 0x%lx", (unsigned long)sent[i], (unsigned long)v);
    }
}
TEST(gap4_iu_null_does_not_change_last_error) {
    REQUIRE(iu());
    SET_ERR(0x4242);
    EQC(iu()(NULL), 0);
    EXPECT_ERR(0x4242);
}
TEST(gap4_iu_misaligned_destination) {
    REQUIRE(iu());
    BYTE raw[16]; memset(raw, 0xCD, sizeof raw);
    HRESULT hr = iu()((BOOL *)(raw + 1));
    EXPECT_EQ(hr, 0);
    DWORD v; memcpy(&v, raw + 1, 4);
    CHECK(v == 0 || v == 1);
    EXPECT_EQ(raw[0], 0xCD);
    EXPECT_EQ(raw[5], 0xCD);
}
TEST(gap4_iu_stable_over_repeats) {
    REQUIRE(iu());
    BOOL first = -1; int diff = 0;
    for (int i = 0; i < 20; i++) {
        BOOL b = 5;
        if (iu()(&b) != 0) diff += 100;
        if (i == 0) first = b; else if (b != first) diff++;
    }
    EXPECT_EQ(diff, 0);
    t_note("platform authenticator available: %d", (int)first);
}
static DWORD WINAPI iu_thread(LPVOID p) { BOOL b = 9; HRESULT hr = iu()(&b); *(int *)p = (hr == 0 && (b == 0 || b == 1)) ? 1 : -1; return 0; }
TEST(gap4_iu_from_worker_threads) {
    REQUIRE(iu());
    HANDLE th[4]; int res[4] = { 0 };
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, iu_thread, &res[i], 0, NULL);
    for (int i = 0; i < 4; i++) { if (th[i]) { WaitForSingleObject(th[i], 15000); CloseHandle(th[i]); } }
    for (int i = 0; i < 4; i++) EXPECT_EQ(res[i], 1);
}

/* ---- GetCancellationId / CancelCurrentOperation ---- */
TEST(gap4_cid_result_is_zero_hresult_success) {
    REQUIRE(gid());
    GUID g; memset(&g, 0xEE, sizeof g);
    HRESULT hr = gid()(&g);
    EXPECT_EQ(hr, 0);
}
TEST(gap4_cid_bits_set_random_version4) {
    REQUIRE(gid());
    for (int i = 0; i < 50; i++) {
        GUID g; gid()(&g);
        t_check(((g.Data3 >> 12) & 0xF) == 4 && (g.Data4[0] & 0xC0) == 0x80, __FILE__, __LINE__, "RFC 4122 v4", "iteration %d", i);
    }
}
TEST(gap4_cid_first_call_after_nil_buffer) {
    REQUIRE(gid());
    GUID g; memset(&g, 0, sizeof g);
    EQC(gid()(&g), 0);
    GUID z; memset(&z, 0, sizeof z);
    CHECK(memcmp(&g, &z, sizeof g) != 0);
}
TEST(gap4_cancel_with_fresh_id) {
    REQUIRE(gid()); REQUIRE(can());
    GUID g; EQC(gid()(&g), 0);
    EQC(can()(&g), 0);
    EQC(can()(&g), 0);
}
TEST(gap4_cancel_nothing_pending_many_ids) {
    REQUIRE(gid()); REQUIRE(can());
    int bad = 0;
    for (int i = 0; i < 200; i++) { GUID g; if (gid()(&g) != 0 || can()(&g) != 0) bad++; }
    EXPECT_EQ(bad, 0);
}
TEST(gap4_cancel_null_returns_zero) {
    REQUIRE(can());
    EQC(can()(NULL), 0);
}
TEST(gap4_cancel_does_not_change_last_error) {
    REQUIRE(can());
    GUID g = { 0x11111111, 0x2222, 0x4333, { 0x93, 5, 6, 7, 8, 9, 10, 11 } };
    SET_ERR(0x3131);
    EQC(can()(&g), 0);
    EXPECT_ERR(0x3131);
}

/* ---- GetAssertion: outer parameter check (child process, proven build only) ---- */
#define GA_PROVEN_RVA 0x16780u
typedef struct { DWORD dwVersion; DWORD cb; PBYTE pb; LPCWSTR hash; } cdat;
typedef struct { DWORD dwVersion; BYTE rest[0x54]; } gopt;   /* 0x58 bytes, v1..v4 layout; pCancellationId at +0x48 */
_Static_assert(sizeof(gopt) == 0x58, "gopt");

static int build_proven(void)
{
    HMODULE m = t_module("webauthn.dll");
    FARPROC p = m ? GetProcAddress(m, "WebAuthNAuthenticatorGetAssertion") : NULL;
    if (p && (DWORD)((BYTE *)p - (BYTE *)m) == GA_PROVEN_RVA) return 1;
    return GetEnvironmentVariableA("GA_ALLOW_OTHER_BUILD", NULL, 0) != 0;
}

/* case table: which single defect makes the outer check fail */
enum { C_RP_NULL, C_CD_NULL, C_CD_V0, C_CD_CB0, C_CD_PB_NULL, C_CD_HASH_NULL, C_OPT_V0, C_OPT_V0_CANCEL, C_ALL_ZERO_CD,
       C_RP_NULL_OPT_NULL, C_RP_NULL_OPT_V4, C_CD_V0_CB_BIG, C_OPT_V0_FULL_ZERO, C_RP_EMPTY_STILL_PASSES_OUTER = 99 };
#define NCASES 13

static int run_case(int c, int hw)
{
    gaf();
    static const BYTE json[] = "{\"type\":\"webauthn.get\",\"challenge\":\"AAAA\",\"origin\":\"https://example.test\"}";
    cdat cd = { 1, sizeof json - 1, (PBYTE)json, L"SHA-256" };
    gopt opt; memset(&opt, 0, sizeof opt); opt.dwVersion = 4;
    GUID cid = { 0xC0DEC0DE, 0x1234, 0x4abc, { 0x8d, 1, 2, 3, 4, 5, 6, 7 } };
    LPCWSTR rp = L"example.test";
    const cdat *pcd = &cd; const gopt *popt = &opt;
    switch (c) {
    case C_RP_NULL: rp = NULL; break;
    case C_CD_NULL: pcd = NULL; break;
    case C_CD_V0: cd.dwVersion = 0; break;
    case C_CD_CB0: cd.cb = 0; break;
    case C_CD_PB_NULL: cd.pb = NULL; break;
    case C_CD_HASH_NULL: cd.hash = NULL; break;
    case C_OPT_V0: opt.dwVersion = 0; break;
    case C_OPT_V0_CANCEL: opt.dwVersion = 0; *(GUID **)(opt.rest + 0x48 - 4) = &cid; break;
    case C_ALL_ZERO_CD: memset(&cd, 0, sizeof cd); break;
    case C_RP_NULL_OPT_NULL: rp = NULL; popt = NULL; break;
    case C_RP_NULL_OPT_V4: rp = NULL; break;
    case C_CD_V0_CB_BIG: cd.dwVersion = 0; cd.cb = 0xFFFF; break;
    case C_OPT_V0_FULL_ZERO: memset(&opt, 0, sizeof opt); break;
    default: return 0x7E7E0001;
    }
    void *out = (void *)(ULONG_PTR)0x1; /* must be reset to NULL */
    HWND h = hw == 0 ? NULL : (HWND)(ULONG_PTR)0x10;
    HRESULT hr = gaf()(h, rp, pcd, popt, &out);
    if (out != NULL) return 0x7E7E0002;
    if ((DWORD)hr != 0x80090027u) return (int)hr;
    return 0;
}
CHILD(gap4_ga) {
    if (!gaf()) return 0x7E7E0000;
    if (!build_proven()) return 0x7E7E0003;
    int c = argc > 1 ? atoi(argv[1]) : 0, hw = argc > 2 ? atoi(argv[2]) : 0;
    return run_case(c, hw);
}
static void ga_case(int c)
{
    if (!gaf()) { t_skip("missing export: WebAuthNAuthenticatorGetAssertion"); return; }
    if (!build_proven()) { t_skip("not the build the local-failure proof was made against"); return; }
    for (int hw = 0; hw < 2; hw++) {
        char a[32]; snprintf(a, sizeof a, "%d %d", c, hw);
        DWORD r = t_run_child("gap4_ga", a, 20000);
        if (r == 0xDEAD0000) { t_skip("could not spawn child"); return; }
        t_check(r != 0xDEAD0001, __FILE__, __LINE__, "child finished", "case %d timed out", c);
        if (r == 0x7E7E0000 || r == 0x7E7E0003) { t_skip("export missing / build not proven in child"); return; }
        t_check(r == 0, __FILE__, __LINE__, "NTE_INVALID_PARAMETER and out==NULL", "case %d hwnd %d child result 0x%lx", c, hw, (unsigned long)r);
    }
}
#define GA_T(n, c) TEST(gap4_ga_outer_##n) { ga_case(c); }
GA_T(rp_null, C_RP_NULL) GA_T(cd_null, C_CD_NULL) GA_T(cd_v0, C_CD_V0) GA_T(cd_cb0, C_CD_CB0) GA_T(cd_pb_null, C_CD_PB_NULL)
GA_T(cd_hash_null, C_CD_HASH_NULL) GA_T(opt_v0, C_OPT_V0) GA_T(opt_v0_with_cancel_ptr, C_OPT_V0_CANCEL) GA_T(cd_all_zero, C_ALL_ZERO_CD)
GA_T(rp_null_opt_null, C_RP_NULL_OPT_NULL) GA_T(rp_null_opt_v4, C_RP_NULL_OPT_V4) GA_T(cd_v0_big_cb, C_CD_V0_CB_BIG) GA_T(opt_all_zero, C_OPT_V0_FULL_ZERO)

CHILD(gap4_ga_repeat_worker) {
    if (!gaf() || !build_proven()) return 0x7E7E0000;
    for (int i = 0; i < 50; i++) { int r = run_case(i % NCASES, 0); if (r) return r; }
    return 0;
}
TEST(gap4_ga_outer_repeated_rejections_stay_rejections) {
    REQUIRE(gaf());
    if (!build_proven()) { t_skip("not the proven build"); return; }
    DWORD r = t_run_child("gap4_ga_repeat_worker", "", 30000);
    if (r == 0x7E7E0000) { t_skip("child skipped"); return; }
    EXPECT_EQ(r, 0);
}
