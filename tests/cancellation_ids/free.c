#include "cid.h"
/* Free functions. Decomp facts (Windows 10 build under the reference corpus):
 *  - WebAuthNFreeAssertion, WebAuthNFreeUserEntityList, WebAuthNFreeDecodedAccountInformation,
 *    WebAuthNFreeEncodedAccountInformation, WebAuthNCtapFreeSelectedDeviceInformation share one body:
 *    if (p) LocalFree(p).
 *  - WebAuthNFreePlatformCredentials and WebAuthNCtapManageFreeDisplayCredentials share one body:
 *    NULL tolerated; otherwise frees p->array[i] for i < p->count (count at +0, array pointer at +8), then p.
 *  - WebAuthNFreeCredentialAttestation: NULL tolerated; frees non-NULL pointers at +0x38, +0x48, +0x68, then p. */

#define F(n) ((n##_pfn)t_proc_in(CID_MOD, #n))

TEST(free_resolve_all) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    CHECK(F(WebAuthNFreeAssertion) != NULL);
    CHECK(F(WebAuthNFreePlatformCredentials) != NULL);
    CHECK(F(WebAuthNFreeUserEntityList) != NULL);
    CHECK(F(WebAuthNFreeDecodedAccountInformation) != NULL);
    CHECK(F(WebAuthNFreeEncodedAccountInformation) != NULL);
}
#define RESOLVE_TWICE(n) TEST(free_resolve_twice_##n) { \
    FARPROC a = t_proc_in(CID_MOD, #n); if (!a) { t_skip("missing export: " #n); return; } \
    FARPROC b = t_proc_in(CID_MOD, #n); FARPROC c = t_proc(#n); \
    EXPECT_EQ(a, b); EXPECT_EQ(a, c); }
RESOLVE_TWICE(WebAuthNFreeCredentialAttestation)
RESOLVE_TWICE(WebAuthNFreeAssertion)
RESOLVE_TWICE(WebAuthNFreePlatformCredentials)
RESOLVE_TWICE(WebAuthNFreeUserEntityList)
RESOLVE_TWICE(WebAuthNFreeDecodedAccountInformation)
RESOLVE_TWICE(WebAuthNFreeEncodedAccountInformation)
RESOLVE_TWICE(WebAuthNCancelCurrentOperation)
RESOLVE_TWICE(WebAuthNGetCancellationId)

TEST(free_resolve_by_ordinal) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    static const struct { unsigned ord; const char *name; } t[] = {
        {43, "WebAuthNFreeAssertion"}, {44, "WebAuthNFreeCredentialAttestation"},
        {45, "WebAuthNFreeDecodedAccountInformation"}, {46, "WebAuthNFreeEncodedAccountInformation"},
        {47, "WebAuthNFreePlatformCredentials"}, {48, "WebAuthNFreeUserEntityList"},
        {9, "WebAuthNCancelCurrentOperation"}, {50, "WebAuthNGetCancellationId"},
        {12, "WebAuthNCtapFreeSelectedDeviceInformation"}, {24, "WebAuthNCtapManageFreeDisplayCredentials"} };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        FARPROC o = t_proc_ord(CID_MOD, t[i].ord), n = t_proc_in(CID_MOD, t[i].name);
        CHECKF(o != NULL && o == n, "ordinal %u vs %s", t[i].ord, t[i].name);
    }
}
TEST(free_shared_body_identical_code_folding) {
    REQUIRE(F(WebAuthNFreeAssertion));
    /* Observed in the reference decomp: these exports share one address. Implementation detail; recorded only. */
    FARPROC a = t_proc_in(CID_MOD, "WebAuthNFreeAssertion");
    int same = a == t_proc_in(CID_MOD, "WebAuthNFreeUserEntityList") &&
               a == t_proc_in(CID_MOD, "WebAuthNFreeDecodedAccountInformation") &&
               a == t_proc_in(CID_MOD, "WebAuthNFreeEncodedAccountInformation") &&
               a == t_proc_in(CID_MOD, "WebAuthNCtapFreeSelectedDeviceInformation");
    /* the reference decomp lists ordinals 12, 43, 45, 46, 48 at one address (identical code folding) */
    t_note("LocalFree-wrapper exports share an address: %d", same);
    FARPROC p = t_proc_in(CID_MOD, "WebAuthNFreePlatformCredentials");
    t_note("FreePlatformCredentials == CtapManageFreeDisplayCredentials: %d", p == t_proc_in(CID_MOD, "WebAuthNCtapManageFreeDisplayCredentials"));
}

#define NULL_NOOP(n) TEST(free_null_##n) { \
    n##_pfn f = F(n); if (!f) { t_skip("missing export: " #n); return; } \
    SET_ERR(0x1234); f(NULL); \
    t_note(#n "(NULL) returned; GetLastError=%lu", GetLastError()); CHECK(1); } \
  TEST(free_null_repeated_##n) { \
    n##_pfn f = F(n); if (!f) { t_skip("missing export: " #n); return; } \
    for (int i = 0; i < 1000; i++) f(NULL); CHECK(1); }
NULL_NOOP(WebAuthNFreeCredentialAttestation)
NULL_NOOP(WebAuthNFreeAssertion)
NULL_NOOP(WebAuthNFreePlatformCredentials)
NULL_NOOP(WebAuthNFreeUserEntityList)
NULL_NOOP(WebAuthNFreeDecodedAccountInformation)
NULL_NOOP(WebAuthNFreeEncodedAccountInformation)
NULL_NOOP(WebAuthNCtapFreeSelectedDeviceInformation)
NULL_NOOP(WebAuthNCtapManageFreeDisplayCredentials)

TEST(free_null_all_in_sequence) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    F(WebAuthNFreeAssertion)(NULL);
    F(WebAuthNFreeCredentialAttestation)(NULL);
    F(WebAuthNFreePlatformCredentials)(NULL);
    F(WebAuthNFreeUserEntityList)(NULL);
    CHECK(1);
}
TEST(free_null_does_not_change_last_error) {
    REQUIRE(F(WebAuthNFreeAssertion));
    SET_ERR(ERROR_ACCESS_DENIED);
    F(WebAuthNFreeAssertion)(NULL);
    EXPECT_ERR(ERROR_ACCESS_DENIED);   /* NULL path does no API call */
    SET_ERR(ERROR_ACCESS_DENIED);
    F(WebAuthNFreeCredentialAttestation)(NULL);
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    SET_ERR(ERROR_ACCESS_DENIED);
    F(WebAuthNFreePlatformCredentials)(NULL);
    EXPECT_ERR(ERROR_ACCESS_DENIED);
    SET_ERR(ERROR_ACCESS_DENIED);
    F(WebAuthNFreeUserEntityList)(NULL);
    EXPECT_ERR(ERROR_ACCESS_DENIED);
}

/* Real allocations: the free routines release with LocalFree, so LocalAlloc'd blocks are valid inputs. */
#define LOCALFREE_TEST(n) TEST(free_localalloc_##n) { \
    n##_pfn f = F(n); if (!f) { t_skip("missing export: " #n); return; } \
    for (int sz = 1; sz <= 4096; sz *= 4) { void *p = LocalAlloc(LMEM_FIXED, sz); CHECK(p != NULL); if (p) { memset(p, 0, sz); f(p); } } \
    void *z = LocalAlloc(LPTR, 64); CHECK(z != NULL); if (z) f(z); }
LOCALFREE_TEST(WebAuthNFreeAssertion)
LOCALFREE_TEST(WebAuthNFreeUserEntityList)
LOCALFREE_TEST(WebAuthNFreeDecodedAccountInformation)
LOCALFREE_TEST(WebAuthNFreeEncodedAccountInformation)

TEST(free_assertion_many_blocks) {
    REQUIRE(F(WebAuthNFreeAssertion));
    for (int i = 0; i < 1000; i++) { void *p = LocalAlloc(LPTR, 32 + i % 200); if (!p) { CHECK(0); return; } F(WebAuthNFreeAssertion)(p); }
    CHECK(1);
}
TEST(free_assertion_moveable_not_used) {
    REQUIRE(F(WebAuthNFreeAssertion));
    /* LMEM_FIXED handle == pointer; the routine treats its argument as such */
    void *p = LocalAlloc(LMEM_FIXED, 16);
    CHECK(p != NULL);
    if (p) F(WebAuthNFreeAssertion)(p);
}

/* WebAuthNFreeCredentialAttestation with sub-allocations at +0x38, +0x48, +0x68 */
static void *mk_att(int a, int b, int c) {
    unsigned char *p = (unsigned char *)LocalAlloc(LPTR, 0x100);
    if (!p) return NULL;
    if (a) *(void **)(p + 0x38) = LocalAlloc(LPTR, 24);
    if (b) *(void **)(p + 0x48) = LocalAlloc(LPTR, 48);
    if (c) *(void **)(p + 0x68) = LocalAlloc(LPTR, 96);
    return p;
}
TEST(free_attestation_empty_block) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    void *p = mk_att(0, 0, 0); CHECK(p != NULL);
    if (p) F(WebAuthNFreeCredentialAttestation)(p);
}
TEST(free_attestation_all_subs) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    void *p = mk_att(1, 1, 1); CHECK(p != NULL);
    if (p) F(WebAuthNFreeCredentialAttestation)(p);
}
TEST(free_attestation_subset_combinations) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    for (int m = 0; m < 8; m++) {
        void *p = mk_att(m & 1, m & 2, m & 4); CHECK(p != NULL);
        if (p) F(WebAuthNFreeCredentialAttestation)(p);
    }
}
TEST(free_attestation_repeated_cycles) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    for (int i = 0; i < 2000; i++) { void *p = mk_att(1, i & 1, 1); if (!p) { CHECK(0); return; } F(WebAuthNFreeCredentialAttestation)(p); }
    CHECK(1);
}
TEST(free_attestation_other_fields_ignored) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    /* only +0x38/+0x48/+0x68 are freed; stray values elsewhere (here the address of a static) must be left alone */
    unsigned char *p = (unsigned char *)LocalAlloc(LPTR, 0x100);
    CHECK(p != NULL); if (!p) return;
    static int dummy;
    *(void **)(p + 0x08) = &dummy; *(void **)(p + 0x20) = &dummy; *(void **)(p + 0x30) = &dummy;
    *(void **)(p + 0x40) = &dummy; *(void **)(p + 0x50) = &dummy; *(void **)(p + 0x60) = &dummy;
    *(void **)(p + 0x70) = &dummy; *(void **)(p + 0x78) = &dummy;
    F(WebAuthNFreeCredentialAttestation)(p);
    CHECK(1);
}

/* WebAuthNFreePlatformCredentials: { DWORD count; ...; void **items at +8 } */
static void *mk_list(unsigned count, int with_array, int null_slots) {
    unsigned char *p = (unsigned char *)LocalAlloc(LPTR, 16);
    if (!p) return NULL;
    *(DWORD *)p = count;
    if (with_array) {
        void **arr = (void **)LocalAlloc(LPTR, (count ? count : 1) * sizeof(void *));
        for (unsigned i = 0; i < count; i++) arr[i] = (null_slots && (i & 1)) ? NULL : LocalAlloc(LPTR, 32);
        *(void ***)(p + 8) = arr;
    }
    return p;
}
TEST(free_platform_creds_zero_count) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    void *p = mk_list(0, 0, 0); CHECK(p != NULL); if (p) F(WebAuthNFreePlatformCredentials)(p);
}
TEST(free_platform_creds_count_without_array) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    /* array pointer NULL: the loop is skipped even with nonzero count */
    void *p = mk_list(5, 0, 0); CHECK(p != NULL); if (p) F(WebAuthNFreePlatformCredentials)(p);
}
TEST(free_platform_creds_items) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    unsigned counts[] = {1, 2, 3, 10, 100};
    for (unsigned i = 0; i < 5; i++) {
        unsigned char *p = (unsigned char *)mk_list(counts[i], 1, 0); CHECK(p != NULL); if (!p) continue;
        void **arr = *(void ***)(p + 8);
        F(WebAuthNFreePlatformCredentials)(p);
        /* the array block itself is not freed by the routine per the decomp: release it here */
        LocalFree(arr);
    }
}
TEST(free_platform_creds_null_slots_skipped) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    unsigned char *p = (unsigned char *)mk_list(6, 1, 1); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    F(WebAuthNFreePlatformCredentials)(p);
    LocalFree(arr);
}
TEST(free_display_credentials_alias_same_semantics) {
    REQUIRE(F(WebAuthNCtapManageFreeDisplayCredentials));
    unsigned char *p = (unsigned char *)mk_list(4, 1, 0); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    F(WebAuthNCtapManageFreeDisplayCredentials)(p);
    LocalFree(arr);
}
TEST(free_from_worker_thread) {
    REQUIRE(F(WebAuthNFreeAssertion));
    /* memory allocated here, freed by the routine on another thread via the process heap */
    extern DWORD WINAPI free_thr(LPVOID);
    void *p = LocalAlloc(LPTR, 128);
    HANDLE h = CreateThread(NULL, 0, free_thr, p, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
}
DWORD WINAPI free_thr(LPVOID p) { F(WebAuthNFreeAssertion)(p); F(WebAuthNFreeUserEntityList)(NULL); return 0; }

CHILD(free_null_child) {
    if (!F(WebAuthNFreeAssertion) || !F(WebAuthNFreeCredentialAttestation) || !F(WebAuthNFreePlatformCredentials) || !F(WebAuthNFreeUserEntityList)) return 90;
    F(WebAuthNFreeAssertion)(NULL);
    F(WebAuthNFreeCredentialAttestation)(NULL);
    F(WebAuthNFreePlatformCredentials)(NULL);
    F(WebAuthNFreeUserEntityList)(NULL);
    return 0;
}
TEST(free_null_in_fresh_process) {
    REQUIRE(F(WebAuthNFreeAssertion));
    EXPECT_EQ(t_run_child("free_null_child", "", 20000), 0);
}

TEST(free_platform_creds_count_zero_array_untouched) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    /* count 0: no item is freed even though the array holds live blocks; we free them ourselves afterwards */
    unsigned char *p = (unsigned char *)mk_list(3, 1, 0); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    void *keep[3] = { arr[0], arr[1], arr[2] };
    *(DWORD *)p = 0;
    F(WebAuthNFreePlatformCredentials)(p);
    for (int i = 0; i < 3; i++) { memset(keep[i], 0xEE, 32); LocalFree(keep[i]); }
    LocalFree(arr);
}
TEST(free_platform_creds_count_less_than_array) {
    REQUIRE(F(WebAuthNFreePlatformCredentials));
    /* only the first `count` entries are released; later entries remain owned by the caller */
    unsigned char *p = (unsigned char *)mk_list(4, 1, 0); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    void *l2 = arr[2], *l3 = arr[3];
    *(DWORD *)p = 2;
    F(WebAuthNFreePlatformCredentials)(p);
    memset(l2, 0xEE, 32); memset(l3, 0xEE, 32);
    LocalFree(l2); LocalFree(l3); LocalFree(arr);
}
TEST(free_display_credentials_count_less_than_array) {
    REQUIRE(F(WebAuthNCtapManageFreeDisplayCredentials));
    unsigned char *p = (unsigned char *)mk_list(3, 1, 0); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    void *l1 = arr[1], *l2 = arr[2];
    *(DWORD *)p = 1;
    F(WebAuthNCtapManageFreeDisplayCredentials)(p);
    memset(l1, 0xEE, 32); memset(l2, 0xEE, 32);
    LocalFree(l1); LocalFree(l2); LocalFree(arr);
}
TEST(free_display_credentials_null_slots) {
    REQUIRE(F(WebAuthNCtapManageFreeDisplayCredentials));
    unsigned char *p = (unsigned char *)mk_list(5, 1, 1); CHECK(p != NULL); if (!p) return;
    void **arr = *(void ***)(p + 8);
    F(WebAuthNCtapManageFreeDisplayCredentials)(p);
    LocalFree(arr);
}
TEST(free_display_credentials_count_without_array) {
    REQUIRE(F(WebAuthNCtapManageFreeDisplayCredentials));
    void *p = mk_list(7, 0, 0); CHECK(p != NULL); if (p) F(WebAuthNCtapManageFreeDisplayCredentials)(p);
}
TEST(free_attestation_sub_alone_each) {
    REQUIRE(F(WebAuthNFreeCredentialAttestation));
    for (int m = 1; m <= 4; m <<= 1) {
        for (int i = 0; i < 50; i++) { void *p = mk_att(m & 1, m & 2, m & 4); if (!p) { CHECK(0); return; } F(WebAuthNFreeCredentialAttestation)(p); }
    }
}
TEST(free_does_not_touch_caller_other_allocations) {
    REQUIRE(F(WebAuthNFreeAssertion));
    /* neighbouring live blocks must survive: write and verify after the free */
    unsigned char *a = (unsigned char *)LocalAlloc(LPTR, 64), *b = (unsigned char *)LocalAlloc(LPTR, 64), *c = (unsigned char *)LocalAlloc(LPTR, 64);
    CHECK(a && b && c);
    if (a && b && c) {
        memset(a, 0x11, 64); memset(c, 0x33, 64);
        F(WebAuthNFreeAssertion)(b);
        for (int i = 0; i < 64; i++) { CHECK(a[i] == 0x11); CHECK(c[i] == 0x33); }
    }
    if (a) LocalFree(a);
    if (c) LocalFree(c);
}
TEST(free_each_export_resolves_in_module_image) {
    REQUIRE(F(WebAuthNFreeAssertion));
    HMODULE m = t_module(CID_MOD);
    static const char *n[] = {"WebAuthNFreeAssertion","WebAuthNFreeCredentialAttestation","WebAuthNFreePlatformCredentials",
        "WebAuthNFreeUserEntityList","WebAuthNFreeDecodedAccountInformation","WebAuthNFreeEncodedAccountInformation",
        "WebAuthNCtapFreeSelectedDeviceInformation","WebAuthNCtapManageFreeDisplayCredentials"};
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++) {
        FARPROC p = t_proc_in(CID_MOD, n[i]);
        CHECKF(p != NULL && m != NULL && cid_in_image((const char *)m, (void *)p), "%s", n[i]);
    }
}
