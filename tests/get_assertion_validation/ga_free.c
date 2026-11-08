#include "ga.h"

UDECL(void, WebAuthNFreeAssertion, (void *));
UDECL(void, WebAuthNFreeCredentialAttestation, (void *));

/* Decomp: WebAuthNFreeAssertion is LocalFree(p) when p != NULL (it shares its code with
 * WebAuthNFreeUserEntityList and the account-information free functions). WebAuthNFreeCredentialAttestation
 * additionally LocalFree()s the blocks at offsets 0x38, 0x48 and 0x68 of the structure (when non-NULL) and
 * then the structure itself. Blocks referenced from any other field are left alone. */

TEST(get_assertion_validation_free_assertion_null)
{
    REQUIRE(UN(WebAuthNFreeAssertion));
    UN(WebAuthNFreeAssertion)(NULL);
    CHECK(1);
}

TEST(get_assertion_validation_free_attestation_null)
{
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    UN(WebAuthNFreeCredentialAttestation)(NULL);
    CHECK(1);
}

TEST(get_assertion_validation_free_assertion_localalloc_sizes)
{
    REQUIRE(UN(WebAuthNFreeAssertion));
    static const SIZE_T sizes[] = { 1, 8, 16, 0x58, 0x100, 4096, 65536 };
    HANDLE heap = GetProcessHeap();
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        void *p = LocalAlloc(LPTR, sizes[i]);
        CHECK(p != NULL);
        if (!p) continue;
        UN(WebAuthNFreeAssertion)(p);
        CHECKF(HeapValidate(heap, 0, NULL), "process heap corrupt after freeing %zu bytes", sizes[i]);
    }
}

TEST(get_assertion_validation_free_assertion_leaves_inner_blocks)
{
    REQUIRE(UN(WebAuthNFreeAssertion));
    /* an assertion is one block; pointers stored in it are not owned by it */
    void **blk = (void **)LocalAlloc(LPTR, 0x58);
    void *inner = LocalAlloc(LPTR, 64);
    CHECK(blk != NULL && inner != NULL);
    if (!blk || !inner) return;
    memset(inner, 0x5C, 64);
    blk[1] = inner; blk[3] = inner; blk[5] = inner;
    UN(WebAuthNFreeAssertion)(blk);
    CHECK(LocalSize(inner) == 64);
    CHECK(((unsigned char *)inner)[0] == 0x5C && ((unsigned char *)inner)[63] == 0x5C);
    CHECK(LocalFree(inner) == NULL);
}

TEST(get_assertion_validation_free_assertion_repeated_distinct_blocks)
{
    REQUIRE(UN(WebAuthNFreeAssertion));
    for (int i = 0; i < 1000; i++) {
        void *p = LocalAlloc(LPTR, 32 + (i & 63));
        CHECK(p != NULL);
        UN(WebAuthNFreeAssertion)(p);
    }
    CHECK(HeapValidate(GetProcessHeap(), 0, NULL));
}

TEST(get_assertion_validation_free_attestation_empty_struct)
{
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    void *a = LocalAlloc(LPTR, 0x100);
    CHECK(a != NULL);
    if (!a) return;
    UN(WebAuthNFreeCredentialAttestation)(a);   /* all inner pointers NULL: only the block is released */
    CHECK(HeapValidate(GetProcessHeap(), 0, NULL));
}

TEST(get_assertion_validation_free_attestation_owned_blocks)
{
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    unsigned char *a = (unsigned char *)LocalAlloc(LPTR, 0x100);
    void *own38 = LocalAlloc(LPTR, 40), *own48 = LocalAlloc(LPTR, 48), *own68 = LocalAlloc(LPTR, 56);
    CHECK(a && own38 && own48 && own68);
    if (!a || !own38 || !own48 || !own68) return;
    *(void **)(a + 0x38) = own38; *(void **)(a + 0x48) = own48; *(void **)(a + 0x68) = own68;
    UN(WebAuthNFreeCredentialAttestation)(a);
    CHECK(HeapValidate(GetProcessHeap(), 0, NULL));
    t_note("blocks at +0x38/+0x48/+0x68 released with the structure (not re-probed: use-after-free)");
}

TEST(get_assertion_validation_free_attestation_other_fields_not_freed)
{
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    static const unsigned offs[] = { 0x08, 0x18, 0x28, 0x58 };
    unsigned char *a = (unsigned char *)LocalAlloc(LPTR, 0x100);
    void *keep[4] = { 0 };
    CHECK(a != NULL);
    if (!a) return;
    for (int i = 0; i < 4; i++) { keep[i] = LocalAlloc(LPTR, 32); memset(keep[i], 0x40 + i, 32); *(void **)(a + offs[i]) = keep[i]; }
    UN(WebAuthNFreeCredentialAttestation)(a);
    for (int i = 0; i < 4; i++) {
        CHECK(keep[i] && LocalSize(keep[i]) == 32);
        CHECK(((unsigned char *)keep[i])[31] == 0x40 + i);
        CHECK(LocalFree(keep[i]) == NULL);
    }
}

TEST(get_assertion_validation_free_attestation_partial_owned)
{
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    for (int mask = 1; mask < 8; mask++) {
        unsigned char *a = (unsigned char *)LocalAlloc(LPTR, 0x100);
        CHECK(a != NULL);
        if (!a) return;
        if (mask & 1) *(void **)(a + 0x38) = LocalAlloc(LPTR, 16);
        if (mask & 2) *(void **)(a + 0x48) = LocalAlloc(LPTR, 16);
        if (mask & 4) *(void **)(a + 0x68) = LocalAlloc(LPTR, 16);
        UN(WebAuthNFreeCredentialAttestation)(a);
    }
    CHECK(HeapValidate(GetProcessHeap(), 0, NULL));
}

TEST(get_assertion_validation_free_export_aliases)
{
    REQUIRE(UN(WebAuthNFreeAssertion));
    HMODULE m = t_module("webauthn.dll");
    FARPROC a = GetProcAddress(m, "WebAuthNFreeAssertion");
    FARPROC b = GetProcAddress(m, "WebAuthNFreeUserEntityList");
    FARPROC c = GetProcAddress(m, "WebAuthNFreeDecodedAccountInformation");
    FARPROC d = GetProcAddress(m, "WebAuthNFreeEncodedAccountInformation");
    t_note("FreeAssertion shares code with FreeUserEntityList=%d FreeDecodedAccountInformation=%d FreeEncodedAccountInformation=%d",
           a == b, a == c, a == d);
    CHECK(a != NULL);
}
