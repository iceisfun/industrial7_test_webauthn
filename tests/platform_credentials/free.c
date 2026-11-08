#include "pc.h"
/* WebAuthNFreePlatformCredentials / WebAuthNFreeUserEntityList.
 *
 * Decomp: FreePlatformCredentials (same code as WebAuthNCtapManageFreeDisplayCredentials) is
 *   if (p) { if (p->ppItems && p->cItems) for i<cItems: if (ppItems[i]) LocalFree(ppItems[i]); LocalFree(p); }
 * FreeUserEntityList (same code as FreeAssertion / FreeDecodedAccountInformation /
 * FreeEncodedAccountInformation / CtapFreeSelectedDeviceInformation) is  if (p) LocalFree(p).
 * Neither returns a value or validates anything else. */

TEST(pc_free_alias_manage_free_display) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreePlatformCredentials"); REQUIRE(a);
    FARPROC b = t_proc_in("webauthn.dll", "WebAuthNCtapManageFreeDisplayCredentials"); REQUIRE(b);
    EXPECT_EQ(a, b);
}
TEST(pc_freeue_alias_free_assertion) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"); REQUIRE(a);
    EXPECT_EQ(a, t_proc_in("webauthn.dll", "WebAuthNFreeAssertion"));
}
TEST(pc_freeue_alias_free_decoded_account) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"); REQUIRE(a);
    EXPECT_EQ(a, t_proc_in("webauthn.dll", "WebAuthNFreeDecodedAccountInformation"));
}
TEST(pc_freeue_alias_free_encoded_account) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"); REQUIRE(a);
    EXPECT_EQ(a, t_proc_in("webauthn.dll", "WebAuthNFreeEncodedAccountInformation"));
}
TEST(pc_freeue_alias_free_selected_device) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"); REQUIRE(a);
    EXPECT_EQ(a, t_proc_in("webauthn.dll", "WebAuthNCtapFreeSelectedDeviceInformation"));
}
TEST(pc_free_and_freeue_are_distinct) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNFreeUserEntityList"); REQUIRE(a);
    FARPROC b = t_proc_in("webauthn.dll", "WebAuthNFreePlatformCredentials"); REQUIRE(b);
    EXPECT_NE(a, b);
}

TEST(pc_free_null) { pc_free_fn f = pc_freepc(); REQUIRE(f); f(NULL); CHECK(1); }
TEST(pc_freeue_null) { pc_free_fn f = pc_freeue(); REQUIRE(f); f(NULL); CHECK(1); }
TEST(pc_free_null_repeated) { pc_free_fn f = pc_freepc(); REQUIRE(f); for (int i = 0; i < 1000; i++) f(NULL); CHECK(1); }
TEST(pc_freeue_null_repeated) { pc_free_fn f = pc_freeue(); REQUIRE(f); for (int i = 0; i < 1000; i++) f(NULL); CHECK(1); }
TEST(pc_free_null_preserves_last_error) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    SET_ERR(0x2468); f(NULL); EXPECT_EQ(GetLastError(), 0x2468);
}
TEST(pc_freeue_null_preserves_last_error) {
    pc_free_fn f = pc_freeue(); REQUIRE(f);
    SET_ERR(0x2468); f(NULL); EXPECT_EQ(GetLastError(), 0x2468);
}

/* empty list header only: count 0, items pointer NULL */
TEST(pc_free_count0_items_null) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)LocalAlloc(LPTR, sizeof *h); REQUIRE(h);
    f(h); CHECK(1);
}
/* count 0 with a non-NULL items array: array is NOT freed by the call (owned by the caller here) */
TEST(pc_free_count0_items_not_freed) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)LocalAlloc(LPTR, sizeof *h); REQUIRE(h);
    PVOID *arr = (PVOID *)LocalAlloc(LPTR, 64); REQUIRE(arr);
    h->cItems = 0; h->ppItems = arr;
    f(h);
    CHECK(LocalSize(arr) >= 64);
    LocalFree(arr);
}
/* count N with NULL items array: nothing dereferenced */
TEST(pc_free_count_nonzero_items_null) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)LocalAlloc(LPTR, sizeof *h); REQUIRE(h);
    h->cItems = 5; h->ppItems = NULL;
    f(h); CHECK(1);
}
/* the items array itself is not separately freed: it belongs to the list block (+0x10) */
TEST(pc_free_inline_array_single_block) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    void *l = pc_make_list(3, 24); REQUIRE(l);
    f(l); CHECK(1);
}
TEST(pc_free_null_entries_skipped) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)pc_make_list(6, 16); REQUIRE(h);
    LocalFree(h->ppItems[1]); h->ppItems[1] = NULL;
    LocalFree(h->ppItems[4]); h->ppItems[4] = NULL;
    f(h); CHECK(1);
}
TEST(pc_free_all_null_entries) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)pc_make_list(4, 16); REQUIRE(h);
    for (int i = 0; i < 4; i++) { LocalFree(h->ppItems[i]); h->ppItems[i] = NULL; }
    f(h); CHECK(1);
}
/* items beyond cItems are untouched */
TEST(pc_free_only_cItems_entries_freed) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)pc_make_list(4, 16); REQUIRE(h);
    PVOID extra = h->ppItems[3];
    h->cItems = 3;
    f(h);
    CHECK(LocalSize(extra) >= 16);
    LocalFree(extra);
}
TEST(pc_free_external_items_array) {
    /* ppItems may point anywhere: the entries are freed, the array is not */
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)LocalAlloc(LPTR, sizeof *h); REQUIRE(h);
    PVOID *arr = (PVOID *)LocalAlloc(LPTR, 3 * sizeof(PVOID)); REQUIRE(arr);
    for (int i = 0; i < 3; i++) arr[i] = LocalAlloc(LPTR, 40);
    h->cItems = 3; h->ppItems = arr;
    f(h);
    CHECK(LocalSize(arr) >= 3 * sizeof(PVOID));
    LocalFree(arr);
}

#define FREELIST_TEST(n, sz) \
    TEST(pc_free_list_##n##_items_size##sz) { pc_free_fn f = pc_freepc(); REQUIRE(f); \
        void *l = pc_make_list(n, sz); REQUIRE(l); f(l); CHECK(1); }
FREELIST_TEST(1, 1)
FREELIST_TEST(1, 16)
FREELIST_TEST(1, 256)
FREELIST_TEST(2, 8)
FREELIST_TEST(2, 100)
FREELIST_TEST(3, 33)
FREELIST_TEST(7, 64)
FREELIST_TEST(16, 128)
FREELIST_TEST(64, 256)
FREELIST_TEST(255, 32)
FREELIST_TEST(1000, 48)
FREELIST_TEST(4096, 16)

TEST(pc_free_many_cycles) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    for (int i = 0; i < 2000; i++) { void *l = pc_make_list((DWORD)(i % 9), 8 + (i % 50)); REQUIRE(l); f(l); }
    CHECK(1);
}
static pc_free_fn tf; static void *tl;
static DWORD WINAPI th2(LPVOID p) { tf(tl); return 0; }
TEST(pc_free_from_other_thread) {
    pc_free_fn f = pc_freepc(); REQUIRE(f);
    /* ownership is plain process-heap LocalAlloc memory: any thread may free it */
    tf = f; tl = pc_make_list(5, 32); REQUIRE(tl);
    HANDLE h = CreateThread(NULL, 0, th2, NULL, 0, NULL); REQUIRE(h);
    EXPECT_EQ(WaitForSingleObject(h, 10000), WAIT_OBJECT_0); CloseHandle(h);
}

/* ---- FreeUserEntityList: a plain LocalFree --------------------------------- */
#define FREEUE_TEST(sz) \
    TEST(pc_freeue_block_##sz) { pc_free_fn f = pc_freeue(); REQUIRE(f); \
        void *p = LocalAlloc(LPTR, sz); REQUIRE(p); f(p); CHECK(1); }
FREEUE_TEST(1)
FREEUE_TEST(8)
FREEUE_TEST(16)
FREEUE_TEST(64)
FREEUE_TEST(1000)
FREEUE_TEST(65536)

TEST(pc_freeue_does_not_follow_pointers) {
    /* Unlike the credential list free, nested pointers are NOT freed. */
    pc_free_fn f = pc_freeue(); REQUIRE(f);
    pc_list_hdr *h = (pc_list_hdr *)pc_make_list(2, 16); REQUIRE(h);
    PVOID a = h->ppItems[0], b = h->ppItems[1];
    f(h);
    CHECK(LocalSize(a) >= 16); CHECK(LocalSize(b) >= 16);
    LocalFree(a); LocalFree(b);
}
TEST(pc_freeue_many_cycles) {
    pc_free_fn f = pc_freeue(); REQUIRE(f);
    for (int i = 0; i < 5000; i++) { void *p = LocalAlloc(LPTR, 1 + (i % 200)); REQUIRE(p); f(p); }
    CHECK(1);
}
TEST(pc_freeue_movable_fixed_block) {
    pc_free_fn f = pc_freeue(); REQUIRE(f);
    void *p = LocalAlloc(LMEM_FIXED, 24); REQUIRE(p); f(p); CHECK(1);
}
TEST(pc_freeue_result_of_getlasterror_untouched) {
    pc_free_fn f = pc_freeue(); REQUIRE(f);
    void *p = LocalAlloc(LPTR, 12); REQUIRE(p);
    SET_ERR(0x4242); f(p); 
    DWORD e = GetLastError();
    if (e != 0x4242) t_note("FreeUserEntityList changed last error to %lu", e);
    CHECK(1);
}
