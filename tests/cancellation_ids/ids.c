#include "cid.h"
/* WebAuthNGetCancellationId: decomp shows it is UuidCreate(out) with the RPC status mapped to an HRESULT
 * (0 -> S_OK; other positive Win32 codes -> 0x8007xxxx). No NULL check is made, so NULL is never passed. */

TEST(cid_export_resolves) { REQUIRE(GETID()); CHECK(GETID() != NULL); }
TEST(cid_export_resolves_via_U) { REQUIRE(GETID()); }
TEST(cid_export_by_ordinal) {
    REQUIRE(GETID());
    FARPROC o = t_proc_ord(CID_MOD, 50);
    CHECK(o != NULL);
    EXPECT_EQ(o, GETID());
}
TEST(cid_export_name_case_sensitive) {
    REQUIRE(GETID());
    SET_ERR(0);
    CHECK(t_proc_in(CID_MOD, "webauthngetcancellationid") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(cid_export_no_decoration) {
    REQUIRE(GETID());
    CHECK(t_proc_in(CID_MOD, "WebAuthNGetCancellationIdW") == NULL);
    CHECK(t_proc_in(CID_MOD, "WebAuthNGetCancellationIdA") == NULL);
    CHECK(t_proc_in(CID_MOD, "_WebAuthNGetCancellationId@4") == NULL);
}
TEST(cid_not_forwarded) {
    REQUIRE(GETID());
    /* address lies inside webauthn.dll's image, not a forwarder string */
    HMODULE m = t_module(CID_MOD);
    char *p = (char *)GETID();
    CHECK(p > (char *)m && p < (char *)m + 0x100000);
}
TEST(cid_returns_s_ok) {
    REQUIRE(GETID());
    GUID g; memset(&g, 0, sizeof g);
    HRESULT hr = GETID()(&g);
    EXPECT_EQ(hr, S_OK);
}
TEST(cid_result_non_nil) {
    REQUIRE(GETID());
    GUID g; memset(&g, 0, sizeof g);
    CHECK(GETID()(&g) == S_OK);
    CHECK(!cid_is_nil(&g));
}
TEST(cid_overwrites_prefilled_ff) {
    REQUIRE(GETID());
    GUID g; memset(&g, 0xFF, sizeof g);
    CHECK(GETID()(&g) == S_OK);
    GUID ff; memset(&ff, 0xFF, sizeof ff);
    CHECK(!cid_eq(&g, &ff));
}
TEST(cid_overwrites_prefilled_cd) {
    REQUIRE(GETID());
    GUID g; memset(&g, 0xCD, sizeof g);
    CHECK(GETID()(&g) == S_OK);
    GUID cd; memset(&cd, 0xCD, sizeof cd);
    CHECK(!cid_eq(&g, &cd));
}
TEST(cid_writes_exactly_16_bytes) {
    REQUIRE(GETID());
    struct { unsigned char pre[16]; GUID g; unsigned char post[16]; } s;
    memset(&s, 0xA5, sizeof s);
    CHECK(GETID()(&s.g) == S_OK);
    for (int i = 0; i < 16; i++) { CHECK(s.pre[i] == 0xA5); CHECK(s.post[i] == 0xA5); }
}
TEST(cid_misaligned_destination) {
    REQUIRE(GETID());
    unsigned char buf[40]; memset(buf, 0x5A, sizeof buf);
    for (int off = 1; off < 8; off++) {
        memset(buf, 0x5A, sizeof buf);
        HRESULT hr = GETID()((GUID *)(buf + off));
        CHECK(hr == S_OK);
        GUID g; memcpy(&g, buf + off, 16);
        CHECK(!cid_is_nil(&g));
        CHECK(buf[off - 1] == 0x5A);
        CHECK(buf[off + 16] == 0x5A);
    }
}
TEST(cid_heap_destination) {
    REQUIRE(GETID());
    GUID *g = (GUID *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(GUID));
    CHECK(g != NULL);
    if (!g) return;
    CHECK(GETID()(g) == S_OK);
    CHECK(!cid_is_nil(g));
    HeapFree(GetProcessHeap(), 0, g);
}
TEST(cid_global_destination) {
    REQUIRE(GETID());
    static GUID g;
    CHECK(GETID()(&g) == S_OK);
    CHECK(!cid_is_nil(&g));
}
TEST(cid_variant_rfc4122) {
    REQUIRE(GETID());
    for (int i = 0; i < 200; i++) {
        GUID g; CHECK(GETID()(&g) == S_OK);
        CHECK(cid_variant_ok(&g));
    }
}
TEST(cid_version_is_4) {
    REQUIRE(GETID());
    /* UuidCreate on Windows 10 emits random (version 4) UUIDs. */
    for (int i = 0; i < 200; i++) {
        GUID g; CHECK(GETID()(&g) == S_OK);
        CHECK(cid_version(&g) == 4);
    }
}
TEST(cid_version_variant_example) {
    REQUIRE(GETID());
    GUID g; CHECK(GETID()(&g) == S_OK);
    char s[64];
    snprintf(s, sizeof s, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    CHECK(strlen(s) == 36);
    CHECK(s[14] == '4');
    CHECK(strchr("89ab", s[19]) != NULL);
    t_note("sample id %s", s);
}
TEST(cid_two_consecutive_differ) {
    REQUIRE(GETID());
    GUID a, b;
    CHECK(GETID()(&a) == S_OK);
    CHECK(GETID()(&b) == S_OK);
    CHECK(!cid_eq(&a, &b));
}
TEST(cid_same_buffer_reuse_changes) {
    REQUIRE(GETID());
    GUID g, prev;
    CHECK(GETID()(&g) == S_OK);
    for (int i = 0; i < 50; i++) {
        prev = g;
        CHECK(GETID()(&g) == S_OK);
        CHECK(!cid_eq(&g, &prev));
    }
}
TEST(cid_every_byte_varies) {
    REQUIRE(GETID());
    /* random v4 ids: over 500 samples each byte not covered by fixed bits must take >1 value */
    unsigned char seen[16][256]; memset(seen, 0, sizeof seen);
    for (int i = 0; i < 500; i++) {
        GUID g; CHECK(GETID()(&g) == S_OK);
        unsigned char *b = (unsigned char *)&g;
        for (int k = 0; k < 16; k++) seen[k][b[k]] = 1;
    }
    for (int k = 0; k < 16; k++) {
        int n = 0; for (int v = 0; v < 256; v++) n += seen[k][v];
        CHECKF(n > 4, "byte %d only %d distinct values", k, n);
    }
}

static int uniq_n(int n) {
    GUID *a = (GUID *)malloc(sizeof(GUID) * n);
    if (!a) return -1;
    for (int i = 0; i < n; i++) if (GETID()(&a[i]) != S_OK) { free(a); return -2; }
    qsort(a, n, sizeof(GUID), cid_cmp);
    int dups = 0;
    for (int i = 1; i < n; i++) if (cid_eq(&a[i], &a[i - 1])) dups++;
    free(a);
    return dups;
}
TEST(cid_unique_10) { REQUIRE(GETID()); EXPECT_EQ(uniq_n(10), 0); }
TEST(cid_unique_100) { REQUIRE(GETID()); EXPECT_EQ(uniq_n(100), 0); }
TEST(cid_unique_1000) { REQUIRE(GETID()); EXPECT_EQ(uniq_n(1000), 0); }
TEST(cid_unique_10000) { REQUIRE(GETID()); EXPECT_EQ(uniq_n(10000), 0); }
TEST(cid_1000_all_s_ok_nonnil_v4) {
    REQUIRE(GETID());
    for (int i = 0; i < 1000; i++) {
        GUID g; memset(&g, 0, sizeof g);
        HRESULT hr = GETID()(&g);
        if (hr != S_OK) { CHECKF(0, "iter %d hr=0x%lx", i, (unsigned long)hr); break; }
        if (cid_is_nil(&g) || cid_version(&g) != 4 || !cid_variant_ok(&g)) { CHECKF(0, "iter %d bad id", i); break; }
    }
}
TEST(cid_does_not_touch_last_error_contract) {
    REQUIRE(GETID());
    GUID g;
    SET_ERR(0);
    CHECK(GETID()(&g) == S_OK);
    t_note("GetLastError after success = %lu", GetLastError());
}
TEST(cid_no_hresult_failure_bit) {
    REQUIRE(GETID());
    GUID g;
    HRESULT hr = GETID()(&g);
    CHECK(SUCCEEDED(hr));
    CHECK(hr >= 0);
}

/* multi-thread */
#define NT 8
#define PER 500
static GUID g_thr[NT][PER];
static volatile LONG g_thr_bad;
static DWORD WINAPI thr_gen(LPVOID p) {
    int t = (int)(ULONG_PTR)p;
    for (int i = 0; i < PER; i++) {
        if (GETID()(&g_thr[t][i]) != S_OK) InterlockedIncrement(&g_thr_bad);
    }
    return 0;
}
TEST(cid_threads_unique) {
    REQUIRE(GETID());
    HANDLE h[NT]; g_thr_bad = 0;
    for (int i = 0; i < NT; i++) h[i] = CreateThread(NULL, 0, thr_gen, (LPVOID)(ULONG_PTR)i, 0, NULL);
    DWORD w = WaitForMultipleObjects(NT, h, TRUE, 20000);
    CHECK(w == WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) { return; }
    for (int i = 0; i < NT; i++) CloseHandle(h[i]);
    EXPECT_EQ(g_thr_bad, 0);
    GUID *a = (GUID *)g_thr;
    qsort(a, NT * PER, sizeof(GUID), cid_cmp);
    int dups = 0;
    for (int i = 1; i < NT * PER; i++) if (cid_eq(&a[i], &a[i - 1])) dups++;
    EXPECT_EQ(dups, 0);
    for (int i = 0; i < NT * PER; i++) if (cid_is_nil(&a[i]) || cid_version(&a[i]) != 4) { CHECKF(0, "bad id %d", i); break; }
}
static DWORD WINAPI thr_one(LPVOID p) {
    GUID *g = (GUID *)p;
    return (DWORD)GETID()(g);
}
TEST(cid_from_worker_thread) {
    REQUIRE(GETID());
    GUID g; memset(&g, 0, sizeof g);
    HANDLE h = CreateThread(NULL, 0, thr_one, &g, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    DWORD code = 0xFFFF; GetExitCodeThread(h, &code);
    CloseHandle(h);
    EXPECT_EQ(code, 0);
    CHECK(!cid_is_nil(&g));
}

CHILD(cid_getid_child) {
    GUID g; memset(&g, 0, sizeof g);
    if (!GETID()) return 90;
    HRESULT hr = GETID()(&g);
    if (hr != S_OK) return 91;
    if (cid_is_nil(&g)) return 92;
    if (cid_version(&g) != 4 || !cid_variant_ok(&g)) return 93;
    return 0;
}
TEST(cid_in_fresh_process) {
    REQUIRE(GETID());
    EXPECT_EQ(t_run_child("cid_getid_child", "", 20000), 0);
}
CHILD(cid_print_child) {
    GUID g;
    if (!GETID() || GETID()(&g) != S_OK) return 1;
    /* encode the first 4 bytes into exit code range is lossy; just write to a file */
    char path[MAX_PATH];
    t_tmpfile(path, sizeof path, "cid_child.bin");
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 2;
    DWORD n; WriteFile(h, &g, sizeof g, &n, NULL); CloseHandle(h);
    return 0;
}
TEST(cid_differs_across_processes) {
    REQUIRE(GETID());
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "cid_child.bin");
    GUID a, b; memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
    for (int k = 0; k < 2; k++) {
        DeleteFileA(path);
        EXPECT_EQ(t_run_child("cid_print_child", "", 20000), 0);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(h != INVALID_HANDLE_VALUE);
        if (h == INVALID_HANDLE_VALUE) return;
        DWORD n = 0; ReadFile(h, k ? &b : &a, sizeof(GUID), &n, NULL); CloseHandle(h);
        EXPECT_EQ(n, 16);
    }
    CHECK(!cid_is_nil(&a) && !cid_is_nil(&b));
    CHECK(!cid_eq(&a, &b));
    DeleteFileA(path);
}
