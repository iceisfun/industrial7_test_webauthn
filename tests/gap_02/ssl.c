/* SSL protocol provider interface exported by ncrypt.dll (Ssl*).
 * Objects are plain structures with a (size, magic) header. The Windows 10 reference decompilation shows
 * that argument and handle validation happens in ncrypt.dll before anything is dispatched to the
 * provider, so a number of exact status codes can be reproduced with hand built handles that are rejected
 * (or that pass validation and are rejected on a later argument) without ever reaching provider code.
 * Provider-backed tests use the system "Microsoft SSL Protocol Provider". */
#include "g2.h"

/* Wine's ncrypt.dll exports these as aborting stubs: skip them there. */
#undef REQUIRE
#define REQUIRE(ptr) do { if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; } if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)

#define NEED() do { if (t_is_wine()) { t_skip("needs the real SSL protocol provider"); return; } } while (0)

/* ---------------- SslChangeNotify ---------------- */
TEST(gap2_ssl_change_notify_not_supported) {
    REQUIRE(UN(SslChangeNotify));
    G2_EQ(UN(SslChangeNotify)(), G2_NTE_NOT_SUPPORTED);
    G2_EQ(UN(SslChangeNotify)(), G2_NTE_NOT_SUPPORTED);
}

/* ---------------- SslEnumProtocolProviders ---------------- */
TEST(gap2_ssl_enum_providers_null_args) {
    REQUIRE(UN(SslEnumProtocolProviders));
    DWORD n = 0x55; void *list = (void *)0x66;
    G2_EQ(UN(SslEnumProtocolProviders)(NULL, &list, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslEnumProtocolProviders)(&n, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslEnumProtocolProviders)(NULL, NULL, 0), G2_NTE_INVALID_PARAM);
    /* NULL checks precede the flags check */
    G2_EQ(UN(SslEnumProtocolProviders)(NULL, &list, 1), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslEnumProtocolProviders)(&n, NULL, 0xFFFFFFFF), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(n, 0x55); EXPECT_EQ(list, 0x66);
}
TEST(gap2_ssl_enum_providers_bad_flags) {
    REQUIRE(UN(SslEnumProtocolProviders));
    static const DWORD f[] = { 1, 2, 4, 0x10, 0x100, 0x80000000u, 0xFFFFFFFFu };
    for (unsigned i = 0; i < sizeof f / sizeof f[0]; i++) {
        DWORD n = 0x55; void *list = (void *)0x66;
        LONG r = UN(SslEnumProtocolProviders)(&n, &list, f[i]);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%lx -> 0x%08lx", (unsigned long)f[i], (unsigned long)r);
        EXPECT_EQ(n, 0x55); EXPECT_EQ(list, 0x66);   /* outputs untouched */
    }
}
TEST(gap2_ssl_enum_providers_list) {
    REQUIRE(UN(SslEnumProtocolProviders)); NEED();
    DWORD n = 0; NCryptProviderName *list = NULL;
    LONG r = UN(SslEnumProtocolProviders)(&n, (void **)&list, 0);
    G2_EQ(r, 0);
    if (r != 0) return;
    CHECK(n >= 1 && list != NULL);
    int found = 0;
    for (DWORD i = 0; list && i < n && i < 1000; i++) {
        CHECK(list[i].pszName != NULL && list[i].pszName[0] != 0);
        if (list[i].pszName && !lstrcmpW(list[i].pszName, L"Microsoft SSL Protocol Provider")) found = 1;
        /* names are stored in the same allocation, after the array */
        CHECK((BYTE *)list[i].pszName > (BYTE *)&list[n - 1]);
        EXPECT_EQ(list[i].pszComment, NULL);
        /* names are unique: duplicates reported by the registry resolver are collapsed */
        for (DWORD j = 0; j < i; j++) CHECK(lstrcmpW(list[i].pszName, list[j].pszName) != 0);
    }
    CHECK(found);
    if (U(NCryptFreeBuffer)) G2_EQ(U(NCryptFreeBuffer)(list), 0);
}
TEST(gap2_ssl_enum_providers_repeatable) {
    REQUIRE(UN(SslEnumProtocolProviders)); NEED();
    DWORD n1 = 0, n2 = 0; void *l1 = NULL, *l2 = NULL;
    G2_EQ(UN(SslEnumProtocolProviders)(&n1, &l1, 0), 0);
    G2_EQ(UN(SslEnumProtocolProviders)(&n2, &l2, 0), 0);
    EXPECT_EQ(n1, n2);
    CHECK(l1 != l2);        /* each call allocates a fresh block */
    if (l1 && U(NCryptFreeBuffer)) U(NCryptFreeBuffer)(l1);
    if (l2 && U(NCryptFreeBuffer)) U(NCryptFreeBuffer)(l2);
}

/* ---------------- SslFreeBuffer ---------------- */
TEST(gap2_ssl_free_buffer_foreign_and_null) {
    REQUIRE(UN(SslFreeBuffer));
    /* a pointer the provider layer never handed out is released with the process heap */
    void *p = HeapAlloc(GetProcessHeap(), 0, 64);
    CHECK(p != NULL);
    G2_EQ(UN(SslFreeBuffer)(p), 0);
    G2_EQ(UN(SslFreeBuffer)(NULL), 0);
}

/* ---------------- SslFreeObject ---------------- */
TEST(gap2_ssl_free_object_invalid) {
    REQUIRE(UN(SslFreeObject));
    G2_EQ(UN(SslFreeObject)(0), G2_NTE_INVALID_HANDLE);
    g2_fobj o;
    static const DWORD m[] = { 0, 1, 0x44440001, 0x44440002, 0x44444440, 0x44444444, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof m / sizeof m[0]; i++) {
        g2_fake(&o, 0x178, m[i], 0);
        LONG r = UN(SslFreeObject)(G2_HND(&o));
        CHECKF(r == G2_NTE_INVALID_HANDLE, "magic 0x%lx -> 0x%08lx", (unsigned long)m[i], (unsigned long)r);
    }
}
TEST(gap2_ssl_free_object_too_small) {
    REQUIRE(UN(SslFreeObject));
    g2_fobj o;
    /* key and hash objects need a header of at least 0x20 bytes, provider objects at least 0x178 */
    g2_fake(&o, 0x1F, G2_SSLK, 0);  G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
    g2_fake(&o, 0, G2_SSLK, 0);     G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
    g2_fake(&o, 0x1F, G2_SSLH, 0);  G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
    g2_fake(&o, 0x177, G2_SSLP, 0); G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
    g2_fake(&o, 0, G2_SSLP, 0);     G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
    /* provider object whose "client" word at +0xC is non-zero is a different object kind */
    g2_fake(&o, 0x178, G2_SSLP, 0); o.w[3] = 1;
    G2_EQ(UN(SslFreeObject)(G2_HND(&o)), G2_NTE_INVALID_HANDLE);
}

/* ---------------- SslDecrementProviderReferenceCount ---------------- */
TEST(gap2_ssl_decrement_invalid_provider) {
    REQUIRE(UN(SslDecrementProviderReferenceCount));
    g2_fobj o;
    /* returns a raw NTSTATUS (not mapped to NTE_*) when the header is not a provider */
    g2_fake(&o, 0x177, G2_SSLP, 0); G2_EQ(UN(SslDecrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0, G2_SSLP, 0);     G2_EQ(UN(SslDecrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x178, 0, 0);       G2_EQ(UN(SslDecrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x178, G2_SSLK, 0); G2_EQ(UN(SslDecrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x178, 0x44444440, 0); G2_EQ(UN(SslDecrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
}
TEST(gap2_ssl_increment_invalid_provider) {
    REQUIRE(UN(SslIncrementProviderReferenceCount));
    g2_fobj o;
    G2_EQ(UN(SslIncrementProviderReferenceCount)(0), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x178, G2_SSLK, 0); G2_EQ(UN(SslIncrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x177, G2_SSLP, 0); G2_EQ(UN(SslIncrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
    g2_fake(&o, 0x178, G2_SSLP, 0); o.w[3] = 1;
    G2_EQ(UN(SslIncrementProviderReferenceCount)(G2_HND(&o)), G2_STATUS_INVALID_HANDLE);
}

/* ---------------- handshake hash family: provider validation ---------------- */
TEST(gap2_ssl_create_handshake_hash_validation) {
    REQUIRE(UN(SslCreateHandshakeHash));
    g2_fobj p; G2_HANDLE h = 0x1234;
    G2_EQ(UN(SslCreateHandshakeHash)(0, &h, 0x303, 0xC02F, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    p.w[0] = 0x177; G2_EQ(UN(SslCreateHandshakeHash)(G2_HND(&p), &h, 0x303, 0xC02F, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[1] = G2_SSLK;
    G2_EQ(UN(SslCreateHandshakeHash)(G2_HND(&p), &h, 0x303, 0xC02F, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[3] = 1;
    G2_EQ(UN(SslCreateHandshakeHash)(G2_HND(&p), &h, 0x303, 0xC02F, 0), G2_NTE_INVALID_HANDLE);
    EXPECT_EQ(h, 0x1234);
    /* valid provider header, no output slot: handle check wins when both are wrong, parameter check otherwise */
    G2_EQ(UN(SslCreateHandshakeHash)(0, NULL, 0x303, 0xC02F, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    G2_EQ(UN(SslCreateHandshakeHash)(G2_HND(&p), NULL, 0x303, 0xC02F, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslCreateHandshakeHash)(G2_HND(&p), NULL, 0, 0, 0), G2_NTE_INVALID_PARAM);
}
TEST(gap2_ssl_hash_handshake_validation) {
    REQUIRE(UN(SslHashHandshake));
    g2_fobj p, k, h; BYTE d[4] = {1,2,3,4};
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslHashHandshake)(0, 0, d, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslHashHandshake)(0, G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), 0, d, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), G2_HND(&k), d, 4, 0), G2_NTE_INVALID_HANDLE);   /* key where a hash is required */
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), G2_HND(&p), d, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslHashHandshake)(G2_HND(&h), G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);   /* hash where a provider is required */
    G2_EQ(UN(SslHashHandshake)(G2_HND(&k), G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);
    h.w[0] = 0x1F;
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);   /* hash header too small */
    G2_FAKE_HASH(h); p.w[0] = 0x177;
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[3] = 5;
    G2_EQ(UN(SslHashHandshake)(G2_HND(&p), G2_HND(&h), d, 4, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_compute_finished_hash_validation) {
    REQUIRE(UN(SslComputeFinishedHash));
    g2_fobj p, k, h; BYTE out[12];
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslComputeFinishedHash)(0, 0, 0, out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(0, G2_HND(&k), G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), 0, G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&k), 0, out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&h), G2_HND(&k), out, 12, 1), G2_NTE_INVALID_HANDLE);   /* swapped key and hash */
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&k), G2_HND(&k), out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&h), G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&k), G2_HND(&k), G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
    k.w[0] = 0x1F; G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&k), G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
    G2_FAKE_KEY(k); h.w[0] = 0x1F; G2_EQ(UN(SslComputeFinishedHash)(G2_HND(&p), G2_HND(&k), G2_HND(&h), out, 12, 1), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_create_client_auth_hash_validation) {
    REQUIRE(UN(SslCreateClientAuthHash));
    g2_fobj p; G2_HANDLE h = 0x99;
    G2_EQ(UN(SslCreateClientAuthHash)(0, &h, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslCreateClientAuthHash)(0, NULL, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[3] = 1;
    G2_EQ(UN(SslCreateClientAuthHash)(G2_HND(&p), &h, 0, 0, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    G2_EQ(UN(SslCreateClientAuthHash)(G2_HND(&p), NULL, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_INVALID_PARAM);
    /* the interface version gate: providers older than version 2 do not implement it */
    G2_FAKE_PROV(p, 0); G2_EQ(UN(SslCreateClientAuthHash)(G2_HND(&p), &h, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 1); G2_EQ(UN(SslCreateClientAuthHash)(G2_HND(&p), &h, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 0); G2_EQ(UN(SslCreateClientAuthHash)(G2_HND(&p), NULL, 0x303, 0xC02F, L"SHA256", 0), G2_NTE_INVALID_PARAM);   /* NULL check precedes the version gate */
    EXPECT_EQ(h, 0x99);
}
TEST(gap2_ssl_compute_client_auth_hash_validation) {
    REQUIRE(UN(SslComputeClientAuthHash));
    g2_fobj p, k, h; BYTE out[64]; DWORD cb = 0;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslComputeClientAuthHash)(0, G2_HND(&k), G2_HND(&h), L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeClientAuthHash)(G2_HND(&p), 0, G2_HND(&h), L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeClientAuthHash)(G2_HND(&p), G2_HND(&k), 0, L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeClientAuthHash)(G2_HND(&p), G2_HND(&h), G2_HND(&k), L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeClientAuthHash)(G2_HND(&p), G2_HND(&k), G2_HND(&p), L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    p.w[3] = 1;
    G2_EQ(UN(SslComputeClientAuthHash)(G2_HND(&p), G2_HND(&k), G2_HND(&h), L"SHA256", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_compute_eap_key_block_validation) {
    REQUIRE(UN(SslComputeEapKeyBlock));
    g2_fobj p, k; BYTE out[64]; DWORD cb = 0;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k);
    G2_EQ(UN(SslComputeEapKeyBlock)(0, G2_HND(&k), NULL, 0, NULL, 0, NULL, 0, out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeEapKeyBlock)(G2_HND(&p), 0, NULL, 0, NULL, 0, NULL, 0, out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslComputeEapKeyBlock)(G2_HND(&k), G2_HND(&p), NULL, 0, NULL, 0, NULL, 0, out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    k.w[0] = 0x1F;
    G2_EQ(UN(SslComputeEapKeyBlock)(G2_HND(&p), G2_HND(&k), NULL, 0, NULL, 0, NULL, 0, out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
}

/* ---------------- key family: validation ---------------- */
TEST(gap2_ssl_create_ephemeral_key_validation) {
    REQUIRE(UN(SslCreateEphemeralKey));
    g2_fobj p; G2_HANDLE k = 0x99;
    G2_EQ(UN(SslCreateEphemeralKey)(0, &k, 0x303, 0xC02F, 0, 0, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslCreateEphemeralKey)(0, NULL, 0x303, 0xC02F, 0, 0, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[1] = G2_SSLH;
    G2_EQ(UN(SslCreateEphemeralKey)(G2_HND(&p), &k, 0, 0, 0, 0, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); p.w[0] = 0x100;
    G2_EQ(UN(SslCreateEphemeralKey)(G2_HND(&p), &k, 0, 0, 0, 0, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    G2_EQ(UN(SslCreateEphemeralKey)(G2_HND(&p), NULL, 0x303, 0xC02F, 0, 0, NULL, 0, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(k, 0x99);
}
TEST(gap2_ssl_generate_master_key_validation) {
    REQUIRE(UN(SslGenerateMasterKey));
    g2_fobj p, k; G2_HANDLE m = 0x99;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k);
    G2_EQ(UN(SslGenerateMasterKey)(0, G2_HND(&k), G2_HND(&k), &m, 0x303, 0xC02F, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    p.w[3] = 1;
    G2_EQ(UN(SslGenerateMasterKey)(G2_HND(&p), G2_HND(&k), G2_HND(&k), &m, 0x303, 0xC02F, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    /* phMasterKey is checked after the provider; the private/public key handles are not validated here
     * (an invalid one is silently treated as absent) */
    G2_EQ(UN(SslGenerateMasterKey)(G2_HND(&p), 0, 0, NULL, 0x303, 0xC02F, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGenerateMasterKey)(G2_HND(&p), G2_HND(&k), G2_HND(&k), NULL, 0x303, 0xC02F, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGenerateMasterKey)(G2_HND(&p), 0x1000, 0x2000, NULL, 0x303, 0xC02F, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGenerateMasterKey)(G2_HND(&p), G2_HND(&p), G2_HND(&p), NULL, 0, 0, 0, NULL, NULL, 0, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(m, 0x99);
}
TEST(gap2_ssl_generate_session_keys_validation) {
    REQUIRE(UN(SslGenerateSessionKeys));
    g2_fobj p, k, h; G2_HANDLE r = 0x1, w = 0x2;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslGenerateSessionKeys)(0, G2_HND(&k), &r, &w, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), 0, &r, &w, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), G2_HND(&h), &r, &w, NULL, 0), G2_NTE_INVALID_HANDLE);   /* hash is not a key */
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&k), G2_HND(&k), &r, &w, NULL, 0), G2_NTE_INVALID_HANDLE);
    k.w[0] = 0x10;
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), G2_HND(&k), &r, &w, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_KEY(k);
    /* handle checks precede the output-slot checks; with valid handles NULL slots are NTE_INVALID_PARAMETER */
    G2_EQ(UN(SslGenerateSessionKeys)(0, 0, NULL, NULL, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), G2_HND(&k), NULL, &w, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), G2_HND(&k), &r, NULL, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGenerateSessionKeys)(G2_HND(&p), G2_HND(&k), NULL, NULL, NULL, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(r, 1); EXPECT_EQ(w, 2);
}
TEST(gap2_ssl_export_key_validation) {
    REQUIRE(UN(SslExportKey));
    g2_fobj p, k; BYTE out[64]; DWORD cb = 0;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k);
    G2_EQ(UN(SslExportKey)(0, G2_HND(&k), L"ECCPUBLICBLOB", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    /* despite the documentation, a NULL key handle is not accepted */
    G2_EQ(UN(SslExportKey)(G2_HND(&p), 0, L"ECCPUBLICBLOB", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslExportKey)(G2_HND(&p), G2_HND(&p), L"ECCPUBLICBLOB", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    p.w[3] = 1;
    G2_EQ(UN(SslExportKey)(G2_HND(&p), G2_HND(&k), L"ECCPUBLICBLOB", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3); k.w[0] = 0x1F;
    G2_EQ(UN(SslExportKey)(G2_HND(&p), G2_HND(&k), L"ECCPUBLICBLOB", out, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_encrypt_packet_validation) {
    REQUIRE(UN(SslEncryptPacket));
    g2_fobj p, k, h; BYTE in[16] = {0}, out[64]; DWORD cb = 0;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslEncryptPacket)(0, G2_HND(&k), in, 16, out, 64, &cb, 0, 23, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslEncryptPacket)(G2_HND(&p), 0, in, 16, out, 64, &cb, 0, 23, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslEncryptPacket)(G2_HND(&p), G2_HND(&h), in, 16, out, 64, &cb, 0, 23, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslEncryptPacket)(G2_HND(&k), G2_HND(&k), in, 16, out, 64, &cb, 0, 23, 0), G2_NTE_INVALID_HANDLE);
    p.w[3] = 1; G2_EQ(UN(SslEncryptPacket)(G2_HND(&p), G2_HND(&k), in, 16, out, 64, &cb, 0, 23, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_decrypt_packet_validation) {
    REQUIRE(UN(SslDecryptPacket));
    g2_fobj p, k, h; BYTE in[16] = {0}, out[64]; DWORD cb = 0;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k); G2_FAKE_HASH(h);
    G2_EQ(UN(SslDecryptPacket)(0, G2_HND(&k), in, 16, out, 64, &cb, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslDecryptPacket)(G2_HND(&p), 0, in, 16, out, 64, &cb, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslDecryptPacket)(G2_HND(&p), G2_HND(&h), in, 16, out, 64, &cb, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslDecryptPacket)(G2_HND(&k), G2_HND(&p), in, 16, out, 64, &cb, 0, 0), G2_NTE_INVALID_HANDLE);
    k.w[0] = 0x1F; G2_EQ(UN(SslDecryptPacket)(G2_HND(&p), G2_HND(&k), in, 16, out, 64, &cb, 0, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_export_keying_material_validation) {
    REQUIRE(UN(SslExportKeyingMaterial));
    g2_fobj p, k; BYTE out[32]; DWORD cb = 0;
    G2_FAKE_PROV(p, 2); G2_FAKE_KEY(k);
    G2_EQ(UN(SslExportKeyingMaterial)(0, G2_HND(&k), L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslExportKeyingMaterial)(G2_HND(&p), 0, L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslExportKeyingMaterial)(0, 0, L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_INVALID_HANDLE);
    /* interface version gate: exporting keying material needs a version 3 provider */
    G2_FAKE_PROV(p, 0); G2_EQ(UN(SslExportKeyingMaterial)(G2_HND(&p), G2_HND(&k), L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 1); G2_EQ(UN(SslExportKeyingMaterial)(G2_HND(&p), G2_HND(&k), L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 2); G2_EQ(UN(SslExportKeyingMaterial)(G2_HND(&p), G2_HND(&k), L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_NOT_SUPPORTED);
    /* handle errors win over the version gate */
    G2_FAKE_PROV(p, 0); G2_EQ(UN(SslExportKeyingMaterial)(G2_HND(&p), 0, L"label", 5, NULL, 0, FALSE, out, 32, &cb, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_get_cipher_suite_prf_hash_validation) {
    REQUIRE(UN(SslGetCipherSuitePRFHashAlgorithm));
    g2_fobj p; WCHAR buf[64];
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(0, 0x303, 0xC02F, 0, buf, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(0, 0x303, 0xC02F, 0, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(G2_HND(&p), 0x303, 0xC02F, 0, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_FAKE_PROV(p, 0);
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(G2_HND(&p), 0x303, 0xC02F, 0, NULL, 0), G2_NTE_INVALID_PARAM);   /* NULL output precedes the version gate */
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(G2_HND(&p), 0x303, 0xC02F, 0, buf, 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 1);
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(G2_HND(&p), 0x303, 0xC02F, 0, buf, 0), G2_NTE_NOT_SUPPORTED);
    G2_FAKE_PROV(p, 3); p.w[3] = 1;
    G2_EQ(UN(SslGetCipherSuitePRFHashAlgorithm)(G2_HND(&p), 0x303, 0xC02F, 0, buf, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_ssl_enum_cipher_suites_validation) {
    REQUIRE(UN(SslEnumCipherSuites));
    g2_fobj p, k; void *suite = (void *)0x1, *state = NULL;
    G2_FAKE_PROV(p, 3); G2_FAKE_KEY(k);
    G2_EQ(UN(SslEnumCipherSuites)(0, 0, &suite, &state, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslEnumCipherSuites)(0, G2_HND(&k), &suite, &state, 0), G2_NTE_INVALID_HANDLE);
    /* a non-NULL private key must be an SSL key object */
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), G2_HND(&p), &suite, &state, 0), G2_NTE_INVALID_HANDLE);
    k.w[1] = G2_SSLH;
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), G2_HND(&k), &suite, &state, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_KEY(k); k.w[0] = 0x1F;
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), G2_HND(&k), &suite, &state, 0), G2_NTE_INVALID_HANDLE);
    /* output slots */
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), 0, NULL, &state, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), 0, &suite, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslEnumCipherSuites)(G2_HND(&p), 0, NULL, NULL, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(suite, 1); EXPECT_EQ(state, NULL);
}
TEST(gap2_ssl_get_provider_property_validation) {
    REQUIRE(UN(SslGetProviderProperty));
    g2_fobj p; PBYTE out = (PBYTE)0x1; DWORD cb = 0x2; void *st = NULL;
    G2_EQ(UN(SslGetProviderProperty)(0, L"Name", &out, &cb, &st, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGetProviderProperty)(0, NULL, NULL, NULL, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_PROV(p, 3);
    G2_EQ(UN(SslGetProviderProperty)(G2_HND(&p), NULL, &out, &cb, &st, 0), G2_NTE_INVALID_PARAM);   /* property name required */
    G2_EQ(UN(SslGetProviderProperty)(G2_HND(&p), L"Name", NULL, &cb, &st, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGetProviderProperty)(G2_HND(&p), L"Name", &out, NULL, &st, 0), G2_NTE_INVALID_PARAM);
    WCHAR n[100];
    for (int len = 65; len <= 99; len += 17) {
        for (int i = 0; i < len; i++) { n[i] = L'a'; }
        n[len] = 0;
        LONG r = UN(SslGetProviderProperty)(G2_HND(&p), n, &out, &cb, &st, 0);
        CHECKF(r == G2_NTE_INVALID_PARAM, "name length %d -> 0x%08lx", len, (unsigned long)r);
    }
    EXPECT_EQ(out, 1); EXPECT_EQ(cb, 2);
}
TEST(gap2_ssl_get_key_property_validation) {
    REQUIRE(UN(SslGetKeyProperty));
    g2_fobj k, p, h; PBYTE out = (PBYTE)0x1; DWORD cb = 0x2;
    G2_FAKE_KEY(k); G2_FAKE_PROV(p, 3); G2_FAKE_HASH(h);
    G2_EQ(UN(SslGetKeyProperty)(0, L"Length", &out, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGetKeyProperty)(G2_HND(&p), L"Length", &out, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(SslGetKeyProperty)(G2_HND(&h), L"Length", &out, &cb, 0), G2_NTE_INVALID_HANDLE);
    k.w[0] = 0x1F; G2_EQ(UN(SslGetKeyProperty)(G2_HND(&k), L"Length", &out, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_FAKE_KEY(k);
    G2_EQ(UN(SslGetKeyProperty)(G2_HND(&k), NULL, &out, &cb, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGetKeyProperty)(G2_HND(&k), L"Length", NULL, &cb, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(SslGetKeyProperty)(G2_HND(&k), L"Length", &out, NULL, 0), G2_NTE_INVALID_PARAM);
    WCHAR n[100];
    for (int len = 65; len <= 99; len += 17) {
        for (int i = 0; i < len; i++) { n[i] = L'a'; }
        n[len] = 0;
        LONG r = UN(SslGetKeyProperty)(G2_HND(&k), n, &out, &cb, 0);
        CHECKF(r == G2_NTE_INVALID_PARAM, "name length %d -> 0x%08lx", len, (unsigned long)r);
    }
    EXPECT_EQ(out, 1); EXPECT_EQ(cb, 2);
}

/* ---------------- provider-backed tests ---------------- */
static G2_HANDLE open_ssl(void) {
    G2_HANDLE h = 0;
    if (!UN(SslOpenProvider) || t_is_wine()) return 0;
    LONG r = UN(SslOpenProvider)(&h, L"Microsoft SSL Protocol Provider", 0);
    if (r != 0) { t_note("SslOpenProvider -> 0x%08lx", (unsigned long)r); return 0; }
    return h;
}
TEST(gap2_ssl_provider_refcount_pair) {
    REQUIRE(UN(SslIncrementProviderReferenceCount)); REQUIRE(UN(SslDecrementProviderReferenceCount)); REQUIRE(UN(SslFreeObject));
    G2_HANDLE h = open_ssl(); if (!h) { t_skip("no SSL protocol provider"); return; }
    volatile DWORD *hd = (volatile DWORD *)(ULONG_PTR)h;
    EXPECT_EQ(hd[1], G2_SSLP);
    CHECK(hd[0] >= 0x178);
    DWORD before = hd[4];
    G2_EQ(UN(SslIncrementProviderReferenceCount)(h), 0);
    EXPECT_EQ(hd[4], before + 1);
    G2_EQ(UN(SslIncrementProviderReferenceCount)(h), 0);
    EXPECT_EQ(hd[4], before + 2);
    G2_EQ(UN(SslDecrementProviderReferenceCount)(h), 0);
    G2_EQ(UN(SslDecrementProviderReferenceCount)(h), 0);
    EXPECT_EQ(hd[4], before);
    G2_EQ(UN(SslFreeObject)(h), 0);
}
TEST(gap2_ssl_enum_cipher_suites_full) {
    REQUIRE(UN(SslEnumCipherSuites)); REQUIRE(UN(SslFreeBuffer)); REQUIRE(UN(SslFreeObject));
    G2_HANDLE h = open_ssl(); if (!h) { t_skip("no SSL protocol provider"); return; }
    void *state = NULL; int n = 0; LONG r = 0;
    for (; n < 2000; n++) {
        void *c = NULL;
        r = UN(SslEnumCipherSuites)(h, 0, &c, &state, 0);
        if (r != 0) break;
        CHECK(c != NULL);
        if (c) UN(SslFreeBuffer)(c);
    }
    t_note("cipher suites enumerated: %d, final status 0x%08lx", n, (unsigned long)r);
    CHECK(n > 0 && n < 2000);
    G2_EQ(r, G2_NTE_NO_MORE_ITEMS);
    UN(SslFreeObject)(h);
}
TEST(gap2_ssl_create_handshake_hash_roundtrip) {
    REQUIRE(UN(SslCreateHandshakeHash)); REQUIRE(UN(SslHashHandshake)); REQUIRE(UN(SslFreeObject));
    G2_HANDLE h = open_ssl(); if (!h) { t_skip("no SSL protocol provider"); return; }
    volatile DWORD *hd = (volatile DWORD *)(ULONG_PTR)h;
    G2_HANDLE hh = 0xDEAD;
    DWORD before = hd[4];
    LONG r = UN(SslCreateHandshakeHash)(h, &hh, 0x0303, 0xC02F, 0);
    t_note("SslCreateHandshakeHash(TLS1.2, ECDHE_RSA_AES128_GCM_SHA256) -> 0x%08lx", (unsigned long)r);
    if (r == 0) {
        volatile DWORD *o = (volatile DWORD *)(ULONG_PTR)hh;
        EXPECT_EQ(o[0], 0x20); EXPECT_EQ(o[1], G2_SSLH);
        EXPECT_EQ(hd[4], before + 1);      /* the hash holds a reference on its provider */
        BYTE msg[7] = { 1, 0, 0, 3, 'a', 'b', 'c' };
        G2_EQ(UN(SslHashHandshake)(h, hh, msg, sizeof msg, 0), 0);
        G2_EQ(UN(SslHashHandshake)(h, hh, msg, 0, 0), 0);
        /* a hash is not a key: key-only entry points refuse it */
        G2_EQ(UN(SslExportKey)(h, hh, L"ECCPUBLICBLOB", NULL, 0, NULL, 0), G2_NTE_INVALID_HANDLE);
        G2_EQ(UN(SslFreeObject)(hh), 0);
        EXPECT_EQ(hd[4], before);
    } else {
        EXPECT_EQ(hh, 0xDEAD);             /* untouched on failure */
    }
    G2_EQ(UN(SslFreeObject)(h), 0);
}
TEST(gap2_ssl_get_cipher_suite_prf_hash_real) {
    REQUIRE(UN(SslGetCipherSuitePRFHashAlgorithm));
    G2_HANDLE h = open_ssl(); if (!h) { t_skip("no SSL protocol provider"); return; }
    static const struct { DWORD proto, suite, keytype; const WCHAR *name; } t[] = {
        { 0x0303, 0xC02F, 0, L"SHA256" }, { 0x0303, 0xC030, 0, L"SHA384" }, { 0x0303, 0x009C, 0, L"SHA256" }, { 0x0303, 0x009D, 0, L"SHA384" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        WCHAR buf[64]; memset(buf, 0xFF, sizeof buf);
        LONG r = UN(SslGetCipherSuitePRFHashAlgorithm)(h, t[i].proto, t[i].suite, t[i].keytype, buf, 0);
        t_note("PRF hash for suite 0x%04lx -> 0x%08lx \"%ls\"", (unsigned long)t[i].suite, (unsigned long)r, r == 0 ? buf : L"");
        if (r == 0) CHECKF(!lstrcmpW(buf, t[i].name), "suite 0x%04lx expected %ls", (unsigned long)t[i].suite, t[i].name);
    }
    UN(SslFreeObject)(h);
}
TEST(gap2_ssl_provider_rejects_ncrypt_handles) {
    REQUIRE(UN(SslFreeObject)); REQUIRE(UN(SslGetProviderProperty));
    G2_HANDLE h = open_ssl(); if (!h) { t_skip("no SSL protocol provider"); return; }
    /* An SSL provider handle is not an NCrypt provider handle and vice versa. */
    NCRYPT_PROV_HANDLE kp = g2_ksp();
    if (kp) {
        PBYTE out = NULL; DWORD cb = 0; void *st = NULL;
        G2_EQ(UN(SslGetProviderProperty)(kp, L"Name", &out, &cb, &st, 0), G2_NTE_INVALID_HANDLE);
        G2_EQ(UN(SslFreeObject)(kp), G2_NTE_INVALID_HANDLE);
        DWORD len = 0;
        CHECK(U(NCryptGetProperty)(h, NCRYPT_NAME_PROPERTY, NULL, 0, &len, 0) != 0);
        U(NCryptFreeObject)(kp);
    }
    UN(SslFreeObject)(h);
}
