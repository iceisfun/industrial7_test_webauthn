/* ncrypt.dll key lifecycle on ephemeral (unnamed, never stored) software-KSP keys: create, finalize,
 * property reads, export / import, encrypt / decrypt, secret agreement + derivation, claims,
 * key derivation argument checks. Nothing is persisted; every handle is released. */
#define GAP1_NCRYPT_FILE 1
#include "gap1.h"

#define SENT_K ((NCRYPT_KEY_HANDLE)0x1234)

/* ---- NCryptCreatePersistedKey (ephemeral) / NCryptFinalizeKey -------------------------------- */
TEST(gap1_cpk_null_phkey_checked_first) {
    REQUIRE(U(NCryptCreatePersistedKey));
    G_EQ(U(NCryptCreatePersistedKey)(0, NULL, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), G_NTE_INVALID_PARAM);
    NEED_KSP(p);
    G_EQ(U(NCryptCreatePersistedKey)(p, NULL, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), G_NTE_INVALID_PARAM);
    g_free(p);
}

TEST(gap1_cpk_invalid_provider) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NCRYPT_KEY_HANDLE k = SENT_K;
    G_EQ(U(NCryptCreatePersistedKey)(0, &k, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), G_NTE_INVALID_HANDLE);
    EXPECT_EQ(k, SENT_K);
}

TEST(gap1_cpk_unknown_algorithm) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = SENT_K;
    DWORD st = U(NCryptCreatePersistedKey)(p, &k, L"gap1NoSuchAlgorithm", NULL, 0, 0);
    CHECKF(st != 0, "unknown algorithm accepted");
    EXPECT_EQ(k, SENT_K);                                    /* handle only written on success */
    t_note("CreatePersistedKey(unknown alg) -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

TEST(gap1_cpk_symmetric_algorithm_rejected) {
    REQUIRE(U(NCryptCreatePersistedKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = SENT_K;
    DWORD st = U(NCryptCreatePersistedKey)(p, &k, L"AES", NULL, 0, 0);
    /* Windows 10 22H2: the software KSP creates an (unfinalized, unnamed) AES key: status 0 and a new handle. */
    G_EQ(st, 0);
    CHECK(k != SENT_K && k != 0);
    if (st == 0 && k != SENT_K) g_free(k);
    g_free(p);
}

TEST(gap1_cpk_ephemeral_algorithms) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptFinalizeKey)); REQUIRE(U(NCryptIsKeyHandle));
    NEED_KSP(p);
    static const LPCWSTR algs[] = { NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_ECDSA_P384_ALGORITHM, NCRYPT_ECDSA_P521_ALGORITHM,
                                    NCRYPT_ECDH_P256_ALGORITHM, NCRYPT_ECDH_P384_ALGORITHM, NCRYPT_ECDH_P521_ALGORITHM };
    for (size_t i = 0; i < sizeof algs / sizeof *algs; i++) {
        NCRYPT_KEY_HANDLE k = 0;
        DWORD st = U(NCryptCreatePersistedKey)(p, &k, algs[i], NULL, 0, 0);
        CHECKF(st == 0, "%ls create st=0x%08lx", algs[i], (unsigned long)st);
        if (st != 0) continue;
        CHECK(k != 0);
        EXPECT_EQ(U(NCryptIsKeyHandle)(k), TRUE);
        st = U(NCryptFinalizeKey)(k, 0);
        CHECKF(st == 0, "%ls finalize st=0x%08lx", algs[i], (unsigned long)st);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_cpk_two_ephemeral_keys_distinct) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1), b = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!a || !b) { g_free(a); g_free(b); g_free(p); t_skip("key unavailable"); return; }
    CHECK(a != b);
    BYTE x[80], y[80]; DWORD cx = 0, cy = 0;
    G_EQ(U(NCryptExportKey)(a, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, x, sizeof x, &cx, 0), 0);
    G_EQ(U(NCryptExportKey)(b, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, y, sizeof y, &cy, 0), 0);
    EXPECT_EQ(cx, cy);
    CHECK(cx == cy && memcmp(x, y, cx) != 0);
    g_free(a); g_free(b); g_free(p);
}

TEST(gap1_fin_invalid_handles) {
    REQUIRE(U(NCryptFinalizeKey));
    G_EQ(U(NCryptFinalizeKey)(0, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptFinalizeKey)(0, 0xFFFFFFFF), G_NTE_INVALID_HANDLE);
    NEED_KSP(p);
    G_EQ(U(NCryptFinalizeKey)(p, 0), G_NTE_INVALID_HANDLE);   /* provider handle is not a key */
    g_free(p);
}

TEST(gap1_fin_twice) {
    REQUIRE(U(NCryptFinalizeKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    DWORD st = U(NCryptFinalizeKey)(k, 0);
    CHECKF(st != 0, "finalizing a finalized key succeeded");
    t_note("second NCryptFinalizeKey -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_fin_property_locked_after_finalize) {
    REQUIRE(U(NCryptSetProperty)); REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 1);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    DWORD len = 2048, cur = 0, cb = 0;
    DWORD st = U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof len, 0);
    /* Windows 10 22H2 accepts the write after finalization and the property then reads back the new value (status 0, 2048). */
    G_EQ(st, 0);
    t_note("SetProperty(Length) after finalize -> 0x%08lx", (unsigned long)st);
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&cur, sizeof cur, &cb, 0), 0);
    EXPECT_EQ(cur, 2048);
    g_free(k); g_free(p);
}

/* ---- NCryptGetProperty on keys ------------------------------------------------------------------ */
static void getstr(NCRYPT_KEY_HANDLE k, LPCWSTR prop, LPCWSTR want) {
    WCHAR buf[64] = { 0 }; DWORD cb = 0;
    DWORD st = U(NCryptGetProperty)(k, prop, (PBYTE)buf, sizeof buf, &cb, 0);
    CHECKF(st == 0, "%ls st=0x%08lx", prop, (unsigned long)st);
    if (st == 0) { EXPECT_WSTR(buf, want); EXPECT_EQ(cb, (lstrlenW(want) + 1) * sizeof(WCHAR)); }
}

TEST(gap1_keyprop_algorithm_name_and_group) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    static const struct { LPCWSTR alg, name, group; DWORD len; } t[] = {
        { NCRYPT_RSA_ALGORITHM, L"RSA", L"RSA", 1024 },
        { NCRYPT_ECDSA_P256_ALGORITHM, L"ECDSA_P256", L"ECDSA", 0 },
        { NCRYPT_ECDSA_P384_ALGORITHM, L"ECDSA_P384", L"ECDSA", 0 },
        { NCRYPT_ECDH_P256_ALGORITHM, L"ECDH_P256", L"ECDH", 0 },
        { NCRYPT_ECDH_P521_ALGORITHM, L"ECDH_P521", L"ECDH", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        NCRYPT_KEY_HANDLE k = g_ekey(p, t[i].alg, t[i].len, 0, 1);
        if (!k) { t_note("%ls key unavailable", t[i].alg); continue; }
        getstr(k, NCRYPT_ALGORITHM_PROPERTY, t[i].name);
        getstr(k, NCRYPT_ALGORITHM_GROUP_PROPERTY, t[i].group);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_keyprop_length_values) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    static const struct { LPCWSTR alg; DWORD want; } t[] = { { NCRYPT_ECDSA_P256_ALGORITHM, 256 }, { NCRYPT_ECDSA_P384_ALGORITHM, 384 }, { NCRYPT_ECDSA_P521_ALGORITHM, 521 },
                                                          { NCRYPT_ECDH_P256_ALGORITHM, 256 }, { NCRYPT_ECDH_P384_ALGORITHM, 384 }, { NCRYPT_ECDH_P521_ALGORITHM, 521 } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        NCRYPT_KEY_HANDLE k = g_ekey(p, t[i].alg, 0, 0, 1);
        if (!k) { t_note("%ls key unavailable", t[i].alg); continue; }
        DWORD v = 0, cb = 0;
        G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0), 0);
        CHECKF(v == t[i].want, "%ls length %lu want %lu", t[i].alg, (unsigned long)v, (unsigned long)t[i].want);
        EXPECT_EQ(cb, 4);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_keyprop_rsa_length_settable_before_finalize) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    static const DWORD lens[] = { 1024, 1536, 2048 };
    for (size_t i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, lens[i], 0, 1);
        if (!k) { t_note("RSA %lu unavailable", (unsigned long)lens[i]); continue; }
        DWORD v = 0, cb = 0;
        G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0), 0);
        EXPECT_EQ(v, lens[i]);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_keyprop_default_rsa_length) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, NCRYPT_RSA_ALGORITHM, NULL, 0, 0) != 0) { g_free(p); t_skip("RSA key unavailable"); return; }
    DWORD v = 0, cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0), 0);
    t_note("default RSA key length before finalize = %lu", (unsigned long)v);
    CHECK(v >= 1024);
    g_free(k); g_free(p);
}

TEST(gap1_keyprop_buffer_protocol) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    const DWORD need = 11 * sizeof(WCHAR);                    /* L"ECDSA_P256" + NUL */
    WCHAR buf[32]; DWORD cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)buf, need - 1, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)buf, 0, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    DWORD v = 0; cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 3, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 4);
    cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 4);
    g_free(k); g_free(p);
}

TEST(gap1_keyprop_argument_errors) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    DWORD cb = 0x77; BYTE b[8];
    G_EQ(U(NCryptGetProperty)(k, NULL, b, sizeof b, &cb, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, b, sizeof b, NULL, 0), G_NTE_INVALID_PARAM);
    WCHAR n65[66]; g_wfill(n65, 65, L'A');
    G_EQ(U(NCryptGetProperty)(k, n65, b, sizeof b, &cb, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, 0x77);
    DWORD st = U(NCryptGetProperty)(k, L"gap1NoSuchProperty", b, sizeof b, &cb, 0);
    CHECKF(st != 0, "unknown property accepted");
    t_note("GetProperty(key, unknown) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_keyprop_provider_handle) {
    REQUIRE(U(NCryptGetProperty)); REQUIRE(U(NCryptIsKeyHandle));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    NCRYPT_PROV_HANDLE ph = 0; DWORD cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_PROVIDER_HANDLE_PROPERTY, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(NCRYPT_PROV_HANDLE));
    cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&ph, 4, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, sizeof(NCRYPT_PROV_HANDLE));
    cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&ph, sizeof ph, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof ph);
    CHECK(ph != 0);
    if (ph) {
        EXPECT_EQ(U(NCryptIsKeyHandle)(ph), FALSE);
        WCHAR name[64] = { 0 }; DWORD c2 = 0;
        G_EQ(U(NCryptGetProperty)(ph, NCRYPT_NAME_PROPERTY, (PBYTE)name, sizeof name, &c2, 0), 0);
        EXPECT_WSTR(name, MS_KEY_STORAGE_PROVIDER);
        t_note("'Provider Handle' returns the key's own provider handle value: %s", ph == p ? "yes" : "no");
        G_EQ(U(NCryptFreeObject)(ph), 0);                       /* the returned handle is an extra reference the caller owns */
    }
    g_free(k); g_free(p);
}

TEST(gap1_keyprop_export_policy) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1), b = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 1, 1);
    if (!a || !b) { g_free(a); g_free(b); g_free(p); t_skip("key unavailable"); return; }
    DWORD va = 0xFF, vb = 0xFF, cb = 0;
    G_EQ(U(NCryptGetProperty)(a, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&va, sizeof va, &cb, 0), 0);
    G_EQ(U(NCryptGetProperty)(b, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&vb, sizeof vb, &cb, 0), 0);
    CHECK(!(va & NCRYPT_ALLOW_EXPORT_FLAG));
    CHECK(vb & NCRYPT_ALLOW_EXPORT_FLAG);
    g_free(a); g_free(b); g_free(p);
}

/* ---- NCryptExportKey ------------------------------------------------------------------------- */
TEST(gap1_export_null_blobtype_first) {
    REQUIRE(U(NCryptExportKey));
    DWORD cb = 0x77;
    G_EQ(U(NCryptExportKey)(0, 0, NULL, NULL, NULL, 0, &cb, 0), G_NTE_INVALID_PARAM);   /* blob type is checked before the handle */
    EXPECT_EQ(cb, 0x77);
}

TEST(gap1_export_invalid_handles) {
    REQUIRE(U(NCryptExportKey));
    DWORD cb = 0x77; BYTE b[8];
    G_EQ(U(NCryptExportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), G_NTE_INVALID_HANDLE);
    NEED_KSP(p);
    G_EQ(U(NCryptExportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), G_NTE_INVALID_HANDLE);   /* provider handle */
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (k) {
        G_EQ(U(NCryptExportKey)(k, p, BCRYPT_ECCPUBLIC_BLOB, NULL, b, sizeof b, &cb, 0), G_NTE_INVALID_HANDLE);  /* wrapping key must be a key */
        EXPECT_EQ(cb, 0x77);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_export_ecc_public_blob) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    static const struct { LPCWSTR alg; DWORD magic, cbKey; } t[] = {
        { NCRYPT_ECDSA_P256_ALGORITHM, 0x31534345, 32 }, { NCRYPT_ECDSA_P384_ALGORITHM, 0x33534345, 48 }, { NCRYPT_ECDSA_P521_ALGORITHM, 0x35534345, 66 },
        { NCRYPT_ECDH_P256_ALGORITHM, 0x314B4345, 32 }, { NCRYPT_ECDH_P384_ALGORITHM, 0x334B4345, 48 }, { NCRYPT_ECDH_P521_ALGORITHM, 0x354B4345, 66 } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        NCRYPT_KEY_HANDLE k = g_ekey(p, t[i].alg, 0, 0, 1);
        if (!k) { t_note("%ls unavailable", t[i].alg); continue; }
        const DWORD want = 8 + 2 * t[i].cbKey;
        BYTE blob[256]; DWORD cb = 0;
        G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cb, 0), 0);        /* size query */
        CHECKF(cb == want, "%ls size %lu want %lu", t[i].alg, (unsigned long)cb, (unsigned long)want);
        cb = 0;
        /* Windows 10 22H2 does not reject a buffer one byte short for an ECC public blob (status 0, cb = full size). */
        DWORD sh = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, want - 1, &cb, 0);
        t_note("%ls export into want-1 bytes -> 0x%08lx cb=%lu", t[i].alg, (unsigned long)sh, (unsigned long)cb);
        cb = 0;
        G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, 4, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, want);
        cb = 0; memset(blob, 0xCC, sizeof blob);
        G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, want, &cb, 0), 0);
        EXPECT_EQ(cb, want);
        BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)blob;
        CHECKF(h->dwMagic == t[i].magic, "%ls magic 0x%08lx", t[i].alg, (unsigned long)h->dwMagic);
        EXPECT_EQ(h->cbKey, t[i].cbKey);
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_export_rsa_public_blob) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 1);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE blob[512]; DWORD cb = 0;
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0), 0);
    EXPECT_EQ(cb, sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 128);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
    EXPECT_EQ(h->BitLength, 1024);
    EXPECT_EQ(h->cbPublicExp, 3);
    EXPECT_EQ(h->cbModulus, 128);
    EXPECT_EQ(h->cbPrime1, 0); EXPECT_EQ(h->cbPrime2, 0);
    CHECK(blob[sizeof *h] == 0x01 && blob[sizeof *h + 1] == 0x00 && blob[sizeof *h + 2] == 0x01);   /* e = 65537, big endian */
    CHECK(blob[sizeof *h + 3] & 0x80);                                                                  /* modulus has its top bit set */
    g_free(k); g_free(p);
}

TEST(gap1_export_wrong_blob_type_for_algorithm) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE r = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 1), e = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    BYTE blob[512]; DWORD cb = 0x77;
    if (r) { DWORD st = U(NCryptExportKey)(r, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0); CHECKF(st != 0, "RSA key exported as ECC blob"); t_note("Export(RSA, ECCPUBLICBLOB) -> 0x%08lx", (unsigned long)st); }
    if (e) { DWORD st = U(NCryptExportKey)(e, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0); CHECKF(st != 0, "ECC key exported as RSA blob"); t_note("Export(ECDSA, RSAPUBLICBLOB) -> 0x%08lx", (unsigned long)st); }
    if (e) { DWORD st = U(NCryptExportKey)(e, 0, L"gap1BogusBlob", NULL, blob, sizeof blob, &cb, 0); CHECKF(st != 0, "bogus blob type accepted"); t_note("Export(bogus blob type) -> 0x%08lx", (unsigned long)st); }
    g_free(r); g_free(e); g_free(p);
}

TEST(gap1_export_private_requires_policy) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1), b = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 1, 1);
    if (!a || !b) { g_free(a); g_free(b); g_free(p); t_skip("key unavailable"); return; }
    BYTE blob[256]; DWORD cb = 0;
    DWORD st = U(NCryptExportKey)(a, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, blob, sizeof blob, &cb, 0);
    CHECKF(st != 0, "non-exportable private key exported");
    t_note("Export(non-exportable, ECCPRIVATEBLOB) -> 0x%08lx", (unsigned long)st);
    cb = 0;
    G_EQ(U(NCryptExportKey)(b, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, blob, sizeof blob, &cb, 0), 0);
    EXPECT_EQ(cb, 8 + 3 * 32);
    BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)blob;
    EXPECT_EQ(h->dwMagic, G_ECDSA_PRV_P256);
    EXPECT_EQ(h->cbKey, 32);
    g_free(a); g_free(b); g_free(p);
}

TEST(gap1_export_unfinalized_key) {
    REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 0);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE blob[256]; DWORD cb = 0;
    DWORD st = U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0);
    CHECKF(st != 0, "unfinalized key exported");
    t_note("Export(unfinalized) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

/* ---- NCryptImportKey ---------------------------------------------------------------------------- */
TEST(gap1_import_null_args_first) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_KEY_HANDLE k = SENT_K; BYTE b[32] = { 0 };
    G_EQ(U(NCryptImportKey)(0, 0, NULL, NULL, &k, b, sizeof b, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptImportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, b, sizeof b, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(k, SENT_K);
    NEED_KSP(p);
    G_EQ(U(NCryptImportKey)(p, 0, NULL, NULL, &k, b, sizeof b, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, b, sizeof b, 0), G_NTE_INVALID_PARAM);
    g_free(p);
}

TEST(gap1_import_invalid_provider_and_import_key) {
    REQUIRE(U(NCryptImportKey));
    NCRYPT_KEY_HANDLE k = SENT_K; BYTE b[32] = { 0 };
    G_EQ(U(NCryptImportKey)(0, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, sizeof b, 0), G_NTE_INVALID_HANDLE);
    EXPECT_EQ(k, SENT_K);
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE other = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    G_EQ(U(NCryptImportKey)(other, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, sizeof b, 0), G_NTE_INVALID_HANDLE);    /* key handle as provider */
    G_EQ(U(NCryptImportKey)(p, p, BCRYPT_ECCPUBLIC_BLOB, NULL, &k, b, sizeof b, 0), G_NTE_INVALID_HANDLE);        /* provider handle as unwrapping key */
    EXPECT_EQ(k, SENT_K);
    g_free(other); g_free(p);
}

TEST(gap1_import_short_generic_public_blob) {
    REQUIRE(U(NCryptImportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = SENT_K; BYTE b[0x20] = { 0 };
    /* "PUBLICBLOB" needs at least 0x14 bytes; the check happens before the data is read */
    for (DWORD cb = 0; cb < 0x14; cb += 5) G_EQ(U(NCryptImportKey)(p, 0, L"PUBLICBLOB", NULL, &k, cb ? b : NULL, cb, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptImportKey)(p, 0, L"PUBLICBLOB", NULL, &k, NULL, 0, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptImportKey)(p, 0, L"PUBLICBLOB", NULL, &k, b, 0x13, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(k, SENT_K);
    g_free(p);
}

TEST(gap1_import_ecc_public_roundtrip) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    static const struct { LPCWSTR alg, name; } t[] = { { NCRYPT_ECDSA_P256_ALGORITHM, L"ECDSA_P256" }, { NCRYPT_ECDH_P384_ALGORITHM, L"ECDH_P384" }, { NCRYPT_ECDSA_P521_ALGORITHM, L"ECDSA_P521" } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        NCRYPT_KEY_HANDLE k = g_ekey(p, t[i].alg, 0, 0, 1);
        if (!k) { t_note("%ls unavailable", t[i].alg); continue; }
        BYTE blob[256], again[256]; DWORD cb = 0, c2 = 0;
        G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0), 0);
        NCRYPT_KEY_HANDLE imp = 0;
        DWORD st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imp, blob, cb, 0);
        CHECKF(st == 0, "%ls import st=0x%08lx", t[i].alg, (unsigned long)st);
        if (st == 0) {
            CHECK(imp != 0 && imp != k);
            G_EQ(U(NCryptExportKey)(imp, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, again, sizeof again, &c2, 0), 0);
            CHECK(c2 == cb && !memcmp(blob, again, cb));
            getstr(imp, NCRYPT_ALGORITHM_PROPERTY, t[i].name);
            g_free(imp);
        }
        g_free(k);
    }
    g_free(p);
}

TEST(gap1_import_ecc_private_roundtrip) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 1, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE prv[256], pub1[256], pub2[256]; DWORD cp = 0, c1 = 0, c2 = 0;
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, prv, sizeof prv, &cp, 0), 0);
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, pub1, sizeof pub1, &c1, 0), 0);
    NCRYPT_KEY_HANDLE imp = 0;
    DWORD st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, &imp, prv, cp, 0);
    CHECKF(st == 0, "private import st=0x%08lx", (unsigned long)st);
    if (st == 0) {
        G_EQ(U(NCryptExportKey)(imp, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, pub2, sizeof pub2, &c2, 0), 0);
        CHECK(c1 == c2 && !memcmp(pub1, pub2, c1));
        /* an imported private key is not exportable unless the import said so */
        BYTE tmp[256]; DWORD ct = 0;
        DWORD ex = U(NCryptExportKey)(imp, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, tmp, sizeof tmp, &ct, 0);
        t_note("re-export of imported private key -> 0x%08lx", (unsigned long)ex);
        g_free(imp);
    }
    g_free(k); g_free(p);
}

TEST(gap1_import_truncated_and_corrupt_ecc_blobs) {
    REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE blob[256]; DWORD cb = 0;
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, &cb, 0), 0);
    NCRYPT_KEY_HANDLE imp = SENT_K;
    DWORD st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imp, blob, cb - 1, 0);
    CHECKF(st != 0, "truncated blob accepted");
    EXPECT_EQ(imp, SENT_K);
    st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imp, blob, 4, 0);
    CHECKF(st != 0, "4-byte blob accepted");
    BYTE bad[256]; memcpy(bad, blob, cb); bad[0] ^= 0xFF;            /* wrong magic */
    st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imp, bad, cb, 0);
    CHECKF(st != 0, "wrong-magic blob accepted");
    t_note("Import(wrong magic) -> 0x%08lx", (unsigned long)st);
    memcpy(bad, blob, cb); bad[cb - 1] ^= 0x01;                       /* point no longer on the curve (overwhelmingly) */
    st = U(NCryptImportKey)(p, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, &imp, bad, cb, 0);
    CHECKF(st != 0 || imp != SENT_K, "inconsistent result");
    t_note("Import(point off curve) -> 0x%08lx", (unsigned long)st);
    if (st == 0 && imp != SENT_K) g_free(imp);
    g_free(k); g_free(p);
}

TEST(gap1_import_unknown_blob_type) {
    REQUIRE(U(NCryptImportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE imp = SENT_K; BYTE b[128] = { 0 };
    DWORD st = U(NCryptImportKey)(p, 0, L"gap1BogusBlob", NULL, &imp, b, sizeof b, 0);
    CHECKF(st != 0, "bogus blob type accepted");
    EXPECT_EQ(imp, SENT_K);
    t_note("Import(bogus blob type) -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

/* ---- NCryptEncrypt / NCryptDecrypt (RSA) ----------------------------------------------------------- */
static NCRYPT_KEY_HANDLE rsa_key(NCRYPT_PROV_HANDLE p) { return g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 1); }

TEST(gap1_crypt_invalid_handles) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    BYTE in[16] = { 0 }, out[128]; DWORD cb = 0x77;
    G_EQ(U(NCryptEncrypt)(0, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptDecrypt)(0, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptEncrypt)(0, NULL, 0, NULL, NULL, 0, &cb, 0), G_NTE_INVALID_HANDLE);
    EXPECT_EQ(cb, 0x77);
    NEED_KSP(p);
    G_EQ(U(NCryptEncrypt)(p, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptDecrypt)(p, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_INVALID_HANDLE);
    g_free(p);
}

TEST(gap1_crypt_pkcs1_roundtrip_and_sizes) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE msg[16]; for (int i = 0; i < 16; i++) msg[i] = (BYTE)(0xA0 + i);
    BYTE ct[128], ct2[128], pt[128]; DWORD cb = 0, c2 = 0, cp = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);        /* size query */
    EXPECT_EQ(cb, 128);
    cb = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct, 127, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 128);
    cb = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct, 0, &cb, NCRYPT_PAD_PKCS1_FLAG), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 128);
    cb = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct, sizeof ct, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb, 128);
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct2, sizeof ct2, &c2, NCRYPT_PAD_PKCS1_FLAG), 0);
    CHECK(memcmp(ct, ct2, 128) != 0);                                  /* type-2 padding is randomized */
    G_EQ(U(NCryptDecrypt)(k, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cp, 16);
    CHECK(cp == 16 && !memcmp(pt, msg, 16));
    cp = 0;
    G_EQ(U(NCryptDecrypt)(k, ct2, c2, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG), 0);
    CHECK(cp == 16 && !memcmp(pt, msg, 16));
    g_free(k); g_free(p);
}

TEST(gap1_crypt_pkcs1_length_limit) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE msg[128], ct[128], pt[128]; DWORD cb = 0, cp = 0;
    for (int i = 0; i < 128; i++) msg[i] = (BYTE)(i + 1);
    G_EQ(U(NCryptEncrypt)(k, msg, 117, NULL, ct, sizeof ct, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);        /* k - 11 */
    G_EQ(U(NCryptDecrypt)(k, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG), 0);
    CHECK(cp == 117 && !memcmp(pt, msg, 117));
    cb = 0;
    DWORD st = U(NCryptEncrypt)(k, msg, 118, NULL, ct, sizeof ct, &cb, NCRYPT_PAD_PKCS1_FLAG);        /* k - 10 */
    CHECKF(st != 0, "118 bytes fit in a 1024-bit PKCS#1 type-2 block");
    t_note("Encrypt(PKCS1, 118 bytes, 1024-bit key) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_crypt_oaep_roundtrip_sha1_sha256) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    static const struct { LPCWSTR hash; DWORD maxlen; } t[] = { { BCRYPT_SHA1_ALGORITHM, 86 }, { BCRYPT_SHA256_ALGORITHM, 62 } };   /* k - 2 - 2*hLen */
    for (size_t i = 0; i < 2; i++) {
        BCRYPT_OAEP_PADDING_INFO pi = { (LPWSTR)t[i].hash, NULL, 0 };
        BYTE msg[128], ct[128], pt[128]; DWORD cb = 0, cp = 0;
        for (int j = 0; j < 128; j++) msg[j] = (BYTE)(j * 3 + 1);
        G_EQ(U(NCryptEncrypt)(k, msg, t[i].maxlen, &pi, ct, sizeof ct, &cb, NCRYPT_PAD_OAEP_FLAG), 0);
        EXPECT_EQ(cb, 128);
        G_EQ(U(NCryptDecrypt)(k, ct, cb, &pi, pt, sizeof pt, &cp, NCRYPT_PAD_OAEP_FLAG), 0);
        CHECKF(cp == t[i].maxlen && !memcmp(pt, msg, cp), "%ls cp=%lu", t[i].hash, (unsigned long)cp);
        cb = 0;
        DWORD st = U(NCryptEncrypt)(k, msg, t[i].maxlen + 1, &pi, ct, sizeof ct, &cb, NCRYPT_PAD_OAEP_FLAG);
        CHECKF(st != 0, "%ls: %lu bytes accepted", t[i].hash, (unsigned long)t[i].maxlen + 1);
        t_note("Encrypt(OAEP %ls, max+1) -> 0x%08lx", t[i].hash, (unsigned long)st);
    }
    g_free(k); g_free(p);
}

TEST(gap1_crypt_oaep_label_must_match) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE l1[] = "label-one", l2[] = "label-two";
    BCRYPT_OAEP_PADDING_INFO p1 = { (LPWSTR)BCRYPT_SHA1_ALGORITHM, l1, sizeof l1 }, p2 = { (LPWSTR)BCRYPT_SHA1_ALGORITHM, l2, sizeof l2 };
    BYTE msg[8] = { 1,2,3,4,5,6,7,8 }, ct[128], pt[128]; DWORD cb = 0, cp = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, &p1, ct, sizeof ct, &cb, NCRYPT_PAD_OAEP_FLAG), 0);
    G_EQ(U(NCryptDecrypt)(k, ct, cb, &p1, pt, sizeof pt, &cp, NCRYPT_PAD_OAEP_FLAG), 0);
    DWORD st = U(NCryptDecrypt)(k, ct, cb, &p2, pt, sizeof pt, &cp, NCRYPT_PAD_OAEP_FLAG);
    CHECKF(st != 0, "decrypt with a different OAEP label succeeded");
    t_note("Decrypt(OAEP wrong label) -> 0x%08lx", (unsigned long)st);
    BCRYPT_OAEP_PADDING_INFO p3 = { (LPWSTR)BCRYPT_SHA256_ALGORITHM, l1, sizeof l1 };
    st = U(NCryptDecrypt)(k, ct, cb, &p3, pt, sizeof pt, &cp, NCRYPT_PAD_OAEP_FLAG);
    CHECKF(st != 0, "decrypt with a different OAEP hash succeeded");
    g_free(k); g_free(p);
}

TEST(gap1_crypt_oaep_tamper_detected) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BCRYPT_OAEP_PADDING_INFO pi = { (LPWSTR)BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    BYTE msg[8] = { 9,8,7,6,5,4,3,2 }, ct[128], pt[128]; DWORD cb = 0, cp = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, &pi, ct, sizeof ct, &cb, NCRYPT_PAD_OAEP_FLAG), 0);
    ct[60] ^= 0x40;
    DWORD st = U(NCryptDecrypt)(k, ct, cb, &pi, pt, sizeof pt, &cp, NCRYPT_PAD_OAEP_FLAG);
    CHECKF(st != 0, "tampered OAEP block decrypted");
    t_note("Decrypt(tampered OAEP) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_crypt_no_padding_roundtrip) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE msg[128], ct[128], pt[128]; DWORD cb = 0, cp = 0;
    msg[0] = 0;                                            /* keep the value below the modulus */
    for (int i = 1; i < 128; i++) msg[i] = (BYTE)(i ^ 0x5A);
    G_EQ(U(NCryptEncrypt)(k, msg, 128, NULL, ct, sizeof ct, &cb, NCRYPT_NO_PADDING_FLAG), 0);
    EXPECT_EQ(cb, 128);
    CHECK(memcmp(ct, msg, 128) != 0);
    G_EQ(U(NCryptDecrypt)(k, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_NO_PADDING_FLAG), 0);
    CHECK(cp == 128 && !memcmp(pt, msg, 128));
    /* raw RSA is deterministic */
    BYTE ct2[128]; DWORD c2 = 0;
    G_EQ(U(NCryptEncrypt)(k, msg, 128, NULL, ct2, sizeof ct2, &c2, NCRYPT_NO_PADDING_FLAG), 0);
    CHECK(c2 == 128 && !memcmp(ct, ct2, 128));
    /* raw RSA needs a full-size block */
    DWORD st = U(NCryptEncrypt)(k, msg, 64, NULL, ct, sizeof ct, &cb, NCRYPT_NO_PADDING_FLAG);
    t_note("Encrypt(NO_PADDING, 64 bytes) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_crypt_flags_zero) {
    REQUIRE(U(NCryptEncrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE msg[8] = { 0 }, ct[128]; DWORD cb = 0;
    DWORD st = U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct, sizeof ct, &cb, 0);
    t_note("Encrypt(RSA, flags=0) -> 0x%08lx", (unsigned long)st);
    CHECKF(st != 0, "RSA encryption without a padding flag succeeded");
    g_free(k); g_free(p);
}

TEST(gap1_crypt_public_only_key) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt)); REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE blob[512]; DWORD cbb = 0;
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, blob, sizeof blob, &cbb, 0), 0);
    NCRYPT_KEY_HANDLE pub = 0;
    G_EQ(U(NCryptImportKey)(p, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &pub, blob, cbb, 0), 0);
    if (pub) {
        BYTE msg[12] = "hello world", ct[128], pt[128]; DWORD cb = 0, cp = 0;
        G_EQ(U(NCryptEncrypt)(pub, msg, sizeof msg, NULL, ct, sizeof ct, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
        G_EQ(U(NCryptDecrypt)(k, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG), 0);
        CHECK(cp == sizeof msg && !memcmp(pt, msg, cp));
        DWORD st = U(NCryptDecrypt)(pub, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG);
        CHECKF(st != 0, "public-only key decrypted");
        t_note("Decrypt(public-only key) -> 0x%08lx", (unsigned long)st);
        g_free(pub);
    }
    g_free(k); g_free(p);
}

TEST(gap1_crypt_private_export_import_interoperates) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt)); REQUIRE(U(NCryptImportKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 1, 1);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE blob[1024]; DWORD cbb = 0;
    G_EQ(U(NCryptExportKey)(k, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, blob, sizeof blob, &cbb, 0), 0);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPRIVATE_MAGIC);
    EXPECT_EQ(h->cbPrime1, 64); EXPECT_EQ(h->cbPrime2, 64);
    EXPECT_EQ(cbb, sizeof *h + 3 + 128 + 64 + 64);
    NCRYPT_KEY_HANDLE k2 = 0;
    G_EQ(U(NCryptImportKey)(p, 0, BCRYPT_RSAPRIVATE_BLOB, NULL, &k2, blob, cbb, 0), 0);
    if (k2) {
        BYTE msg[10] = "interop!!", ct[128], pt[128]; DWORD cb = 0, cp = 0;
        G_EQ(U(NCryptEncrypt)(k, msg, sizeof msg, NULL, ct, sizeof ct, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
        G_EQ(U(NCryptDecrypt)(k2, ct, cb, NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG), 0);
        CHECK(cp == sizeof msg && !memcmp(pt, msg, cp));
        g_free(k2);
    }
    g_free(k); g_free(p);
}

TEST(gap1_crypt_ecc_key_rejected) {
    REQUIRE(U(NCryptEncrypt)); REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE in[16] = { 0 }, out[128]; DWORD cb = 0;
    DWORD st = U(NCryptEncrypt)(k, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    CHECKF(st != 0, "ECDSA key encrypted");
    t_note("Encrypt(ECDSA key) -> 0x%08lx", (unsigned long)st);
    st = U(NCryptDecrypt)(k, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    CHECKF(st != 0, "ECDSA key decrypted");
    g_free(k); g_free(p);
}

TEST(gap1_crypt_unfinalized_key) {
    REQUIRE(U(NCryptEncrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 0);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE in[8] = { 0 }, out[128]; DWORD cb = 0;
    DWORD st = U(NCryptEncrypt)(k, in, sizeof in, NULL, out, sizeof out, &cb, NCRYPT_PAD_PKCS1_FLAG);
    CHECKF(st != 0, "unfinalized key encrypted");
    t_note("Encrypt(unfinalized) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_crypt_decrypt_wrong_size_ciphertext) {
    REQUIRE(U(NCryptDecrypt));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = rsa_key(p);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    BYTE ct[200] = { 0 }, pt[200]; DWORD cp = 0;
    static const DWORD sizes[] = { 0, 1, 64, 127, 129, 200 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        DWORD st = U(NCryptDecrypt)(k, ct, sizes[i], NULL, pt, sizeof pt, &cp, NCRYPT_PAD_PKCS1_FLAG);
        CHECKF(st != 0, "ciphertext of %lu bytes decrypted", (unsigned long)sizes[i]);
    }
    g_free(k); g_free(p);
}

/* ---- NCryptSecretAgreement + NCryptDeriveKey ------------------------------------------------------------ */
static int sa_pair(NCRYPT_PROV_HANDLE p, LPCWSTR alg, NCRYPT_KEY_HANDLE *a, NCRYPT_KEY_HANDLE *b, NCRYPT_SECRET_HANDLE *s1, NCRYPT_SECRET_HANDLE *s2) {
    *a = g_ekey(p, alg, 0, 0, 1); *b = g_ekey(p, alg, 0, 0, 1); *s1 = *s2 = 0;
    if (!*a || !*b) return 0;
    if (U(NCryptSecretAgreement)(*a, *b, s1, 0) != 0) return 0;
    if (U(NCryptSecretAgreement)(*b, *a, s2, 0) != 0) return 0;
    return 1;
}
static void sa_free(NCRYPT_KEY_HANDLE a, NCRYPT_KEY_HANDLE b, NCRYPT_SECRET_HANDLE s1, NCRYPT_SECRET_HANDLE s2) { g_free(s1); g_free(s2); g_free(a); g_free(b); }

TEST(gap1_derive_invalid_handles) {
    REQUIRE(U(NCryptDeriveKey));
    BYTE out[32]; DWORD cb = 0x77;
    G_EQ(U(NCryptDeriveKey)(0, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1);
    G_EQ(U(NCryptDeriveKey)(p, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);   /* provider */
    if (k) G_EQ(U(NCryptDeriveKey)(k, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);   /* key, not a secret */
    EXPECT_EQ(cb, 0x77);
    g_free(k); g_free(p);
}

TEST(gap1_derive_raw_secret_matches_on_both_sides) {
    REQUIRE(U(NCryptDeriveKey)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a, b; NCRYPT_SECRET_HANDLE s1, s2;
    if (!sa_pair(p, NCRYPT_ECDH_P256_ALGORITHM, &a, &b, &s1, &s2)) { sa_free(a, b, s1, s2); g_free(p); t_skip("ECDH unavailable"); return; }
    BYTE r1[64] = { 0 }, r2[64] = { 0 }; DWORD c1 = 0, c2 = 0;
    G_EQ(U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &c1, 0), 0);          /* size query */
    EXPECT_EQ(c1, 32);
    G_EQ(U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof r1, &c1, 0), 0);
    G_EQ(U(NCryptDeriveKey)(s2, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof r2, &c2, 0), 0);
    EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
    CHECK(c1 == c2 && !memcmp(r1, r2, c1));
    sa_free(a, b, s1, s2); g_free(p);
}

TEST(gap1_derive_hash_kdf_sizes) {
    REQUIRE(U(NCryptDeriveKey)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a, b; NCRYPT_SECRET_HANDLE s1, s2;
    if (!sa_pair(p, NCRYPT_ECDH_P256_ALGORITHM, &a, &b, &s1, &s2)) { sa_free(a, b, s1, s2); g_free(p); t_skip("ECDH unavailable"); return; }
    static const struct { LPCWSTR hash; DWORD len; } t[] = { { BCRYPT_SHA1_ALGORITHM, 20 }, { BCRYPT_SHA256_ALGORITHM, 32 }, { BCRYPT_SHA384_ALGORITHM, 48 }, { BCRYPT_SHA512_ALGORITHM, 64 } };
    for (size_t i = 0; i < 4; i++) {
        NCryptBuffer nb = { (ULONG)((lstrlenW(t[i].hash) + 1) * 2), KDF_HASH_ALGORITHM, (PVOID)t[i].hash };
        NCryptBufferDesc d = { NCRYPTBUFFER_VERSION, 1, &nb };
        BYTE k1[64], k2[64]; DWORD c1 = 0, c2 = 0, q = 0;
        G_EQ(U(NCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &d, NULL, 0, &q, 0), 0);
        CHECKF(q == t[i].len, "%ls query %lu", t[i].hash, (unsigned long)q);
        G_EQ(U(NCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &d, k1, sizeof k1, &c1, 0), 0);
        G_EQ(U(NCryptDeriveKey)(s2, BCRYPT_KDF_HASH, &d, k2, sizeof k2, &c2, 0), 0);
        CHECKF(c1 == t[i].len && c2 == t[i].len && !memcmp(k1, k2, c1), "%ls", t[i].hash);
    }
    sa_free(a, b, s1, s2); g_free(p);
}

TEST(gap1_derive_unknown_kdf) {
    REQUIRE(U(NCryptDeriveKey)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a, b; NCRYPT_SECRET_HANDLE s1, s2;
    if (!sa_pair(p, NCRYPT_ECDH_P256_ALGORITHM, &a, &b, &s1, &s2)) { sa_free(a, b, s1, s2); g_free(p); t_skip("ECDH unavailable"); return; }
    BYTE out[64]; DWORD cb = 0x77;
    DWORD st = U(NCryptDeriveKey)(s1, L"GAP1_NO_SUCH_KDF", NULL, out, sizeof out, &cb, 0);
    CHECKF(st != 0, "unknown KDF accepted");
    t_note("DeriveKey(unknown KDF) -> 0x%08lx", (unsigned long)st);
    st = U(NCryptDeriveKey)(s1, BCRYPT_KDF_HASH, NULL, out, sizeof out, &cb, 0);       /* HASH without the algorithm parameter */
    t_note("DeriveKey(HASH, no parameters) -> 0x%08lx cb=%lu", (unsigned long)st, (unsigned long)cb);
    sa_free(a, b, s1, s2); g_free(p);
}

TEST(gap1_derive_buffer_too_small) {
    REQUIRE(U(NCryptDeriveKey)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a, b; NCRYPT_SECRET_HANDLE s1, s2;
    if (!sa_pair(p, NCRYPT_ECDH_P256_ALGORITHM, &a, &b, &s1, &s2)) { sa_free(a, b, s1, s2); g_free(p); t_skip("ECDH unavailable"); return; }
    BYTE out[64]; DWORD cb = 0x77;
    DWORD st = U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, out, 16, &cb, 0);
    /* Windows 10 22H2: a short output buffer is not an error; the secret is truncated (status 0, cb = buffer size). */
    CHECKF(st == 0 && cb == 16, "16-byte buffer: st=0x%08lx cb=%lu", (unsigned long)st, (unsigned long)cb);
    t_note("DeriveKey(RAW, 16-byte buffer) -> 0x%08lx cb=%lu", (unsigned long)st, (unsigned long)cb);
    sa_free(a, b, s1, s2); g_free(p);
}

TEST(gap1_secret_agreement_basic_args) {
    REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1);
    if (!a) { g_free(p); t_skip("ECDH unavailable"); return; }
    NCRYPT_SECRET_HANDLE s = (NCRYPT_SECRET_HANDLE)0x1234;
    G_EQ(U(NCryptSecretAgreement)(0, a, &s, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptSecretAgreement)(a, 0, &s, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptSecretAgreement)(p, a, &s, 0), G_NTE_INVALID_HANDLE);
    EXPECT_EQ(s, 0x1234);
    g_free(a); g_free(p);
}

/* ---- NCryptKeyDerivation / NCryptCreateClaim / NCryptDeleteKey (argument checks only) ------------------------ */
TEST(gap1_kd_zero_args_checked_before_handle) {
    REQUIRE(U(NCryptKeyDerivation));
    BYTE out[32]; DWORD cb = 0x77;
    G_EQ(U(NCryptKeyDerivation)(0, NULL, NULL, sizeof out, &cb, 0), G_NTE_INVALID_PARAM);     /* no output buffer */
    G_EQ(U(NCryptKeyDerivation)(0, NULL, out, 0, &cb, 0), G_NTE_INVALID_PARAM);                /* zero length */
    G_EQ(U(NCryptKeyDerivation)(0, NULL, out, sizeof out, NULL, 0), G_NTE_INVALID_PARAM);      /* no result pointer */
    EXPECT_EQ(cb, 0x77);
}

TEST(gap1_kd_invalid_handle) {
    REQUIRE(U(NCryptKeyDerivation));
    BYTE out[32]; DWORD cb = 0x77;
    G_EQ(U(NCryptKeyDerivation)(0, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);
    NEED_KSP(p);
    G_EQ(U(NCryptKeyDerivation)(p, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);
    g_free(p);
}

TEST(gap1_kd_on_asymmetric_key) {
    REQUIRE(U(NCryptKeyDerivation));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE out[32]; DWORD cb = 0;
    DWORD st = U(NCryptKeyDerivation)(k, NULL, out, sizeof out, &cb, 0);
    CHECKF(st != 0, "an ECDH key is not a key-derivation key");
    t_note("KeyDerivation(ECDH key) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_claim_invalid_handles) {
    REQUIRE(U(NCryptCreateClaim));
    BYTE out[64]; DWORD cb = 0x77;
    G_EQ(U(NCryptCreateClaim)(0, 0, 1, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);   /* neither handle supplied */
    NEED_KSP(p);
    G_EQ(U(NCryptCreateClaim)(p, 0, 1, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptCreateClaim)(0, p, 1, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (k) {
        G_EQ(U(NCryptCreateClaim)(k, p, 1, NULL, out, sizeof out, &cb, 0), G_NTE_INVALID_HANDLE);   /* authority handle must be a key */
        g_free(k);
    }
    EXPECT_EQ(cb, 0x77);
    g_free(p);
}

TEST(gap1_claim_software_provider_unsupported) {
    REQUIRE(U(NCryptCreateClaim));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    BYTE out[256]; DWORD cb = 0;
    DWORD st = U(NCryptCreateClaim)(k, 0, 1 /* NCRYPT_CLAIM_AUTHORITY_ONLY */, NULL, out, sizeof out, &cb, 0);
    CHECKF(st != 0, "claims are a platform-provider feature");
    t_note("CreateClaim(software KSP key) -> 0x%08lx", (unsigned long)st);
    g_free(k); g_free(p);
}

TEST(gap1_delete_invalid_handles) {
    REQUIRE(U(NCryptDeleteKey));
    G_EQ(U(NCryptDeleteKey)(0, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptDeleteKey)(0, 0xFFFFFFFF), G_NTE_INVALID_HANDLE);
    NEED_KSP(p);
    G_EQ(U(NCryptDeleteKey)(p, 0), G_NTE_INVALID_HANDLE);              /* a provider handle is not a key handle, and is not consumed */
    EXPECT_EQ(U(NCryptIsKeyHandle)(p), FALSE);
    DWORD cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), 0);
    g_free(p);
}

TEST(gap1_delete_secret_handle_invalid) {
    REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a, b; NCRYPT_SECRET_HANDLE s1, s2;
    if (!sa_pair(p, NCRYPT_ECDH_P256_ALGORITHM, &a, &b, &s1, &s2)) { sa_free(a, b, s1, s2); g_free(p); t_skip("ECDH unavailable"); return; }
    G_EQ(U(NCryptDeleteKey)(s1, 0), G_NTE_INVALID_HANDLE);
    BYTE out[32]; DWORD cb = 0;
    G_EQ(U(NCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, out, sizeof out, &cb, 0), 0);    /* secret still usable */
    sa_free(a, b, s1, s2); g_free(p);
}

/* ---- NCryptOpenKey (read only) ------------------------------------------------------------------------------ */
TEST(gap1_openkey_null_phkey_first) {
    REQUIRE(U(NCryptOpenKey));
    G_EQ(U(NCryptOpenKey)(0, NULL, L"gap1_key", 0, 0), G_NTE_INVALID_PARAM);
    NEED_KSP(p);
    G_EQ(U(NCryptOpenKey)(p, NULL, L"gap1_key", 0, 0), G_NTE_INVALID_PARAM);
    g_free(p);
}

TEST(gap1_openkey_nonexistent) {
    REQUIRE(U(NCryptOpenKey));
    NEED_KSP(p);
    WCHAR name[64]; wsprintfW(name, L"gap1_nonexistent_%lu_%lu", (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    NCRYPT_KEY_HANDLE k = SENT_K;
    G_EQ(U(NCryptOpenKey)(p, &k, name, 0, 0), G_NTE_BAD_KEYSET);
    EXPECT_EQ(k, SENT_K);
    g_free(p);
}

TEST(gap1_openkey_nonexistent_with_silent_flag) {
    REQUIRE(U(NCryptOpenKey));
    NEED_KSP(p);
    WCHAR name[64]; wsprintfW(name, L"gap1_nonexistent_s_%lu", (unsigned long)GetCurrentProcessId());
    NCRYPT_KEY_HANDLE k = SENT_K;
    DWORD st = U(NCryptOpenKey)(p, &k, name, 0, NCRYPT_SILENT_FLAG);
    CHECKF(st == G_NTE_BAD_KEYSET, "st=0x%08lx", (unsigned long)st);
    EXPECT_EQ(k, SENT_K);
    g_free(p);
}
