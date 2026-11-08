#include "gap0.h"

/* ---- BCryptDeriveKeyPBKDF2 --------------------------------------------- */
TEST(gap0_pbkdf2_rfc6070_sha1) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    static const struct { const char *p, *s; ULONGLONG c; ULONG n; const char *hex; } v[] = {
        { "password", "salt", 1,    20, "0c60c80f961f0e71f3a9b524af6012062fe037a6" },
        { "password", "salt", 2,    20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" },
        { "password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1" },
        { "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
          "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038" },
    };
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA1", G0_ALG_HMAC));
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        unsigned char d[32] = {0};
        G0_OKST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)v[i].p, (ULONG)strlen(v[i].p), (PUCHAR)v[i].s, (ULONG)strlen(v[i].s), v[i].c, d, v[i].n, 0));
        CHECK(g0_eqhex(d, v[i].n, v[i].hex));
    }
    g0_close(a);
}
TEST(gap0_pbkdf2_sha256_vectors) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char d[32];
    G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    G0_OKST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, d, 32, 0));
    G0_CHECK_HEX(d, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    G0_OKST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 2, d, 32, 0));
    G0_CHECK_HEX(d, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    g0_close(a);
}
TEST(gap0_pbkdf2_output_prefix_property) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char full[64], part[13]; G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    G0_OKST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"pw", 2, (PUCHAR)"na", 2, 10, full, 64, 0));
    G0_OKST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"pw", 2, (PUCHAR)"na", 2, 10, part, 13, 0));
    CHECK(!memcmp(full, part, 13));                        /* longer output extends the shorter one */
    g0_close(a);
}
TEST(gap0_pbkdf2_pbkdf2_pseudo_handle_hmac_sha1) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2));
    unsigned char d[20];
    /* BCRYPT_HMAC_SHA1_ALG_HANDLE */
    G0_OKST(U(BCryptDeriveKeyPBKDF2)((BCRYPT_ALG_HANDLE)(ULONG_PTR)0xa1, (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, d, 20, 0));
    G0_CHECK_HEX(d, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
}
TEST(gap0_pbkdf2_parameter_validation) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char d[32]; G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 0, d, 32, 0), G0_INVALID_PARAMETER);        /* zero iterations */
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, d, 32, 1), G0_INVALID_PARAMETER);        /* flags must be 0 */
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, d, 32, 0x80000000), G0_INVALID_PARAMETER);
    ST(U(BCryptDeriveKeyPBKDF2)(a, NULL, 1, (PUCHAR)"s", 1, 1, d, 32, 0), G0_INVALID_PARAMETER);                /* NULL password, cb != 0 */
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, NULL, 1, 1, d, 32, 0), G0_INVALID_PARAMETER);                /* NULL salt, cb != 0 */
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, NULL, 32, 0), G0_INVALID_PARAMETER);      /* NULL output */
    ST(U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, d, 0, 0), G0_INVALID_PARAMETER);          /* zero-length output */
    g0_close(a);
}
TEST(gap0_pbkdf2_validation_precedes_handle_check) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2));
    unsigned char d[8];
    /* parameter errors are reported before the PRF handle is examined */
    ST(U(BCryptDeriveKeyPBKDF2)(NULL, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 0, d, 8, 0), G0_INVALID_PARAMETER);
    NTSTATUS s = U(BCryptDeriveKeyPBKDF2)(NULL, (PUCHAR)"p", 1, (PUCHAR)"s", 1, 1, d, 8, 0);
    CHECK(s < 0); t_note("PBKDF2 with NULL PRF handle -> 0x%08lx", (unsigned long)s);
}
TEST(gap0_pbkdf2_prf_must_be_hmac_note) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char d[20]; G0_OKST(g0_open(&a, L"SHA1", 0));   /* plain hash, no HMAC flag */
    NTSTATUS s = U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"password", 8, (PUCHAR)"salt", 4, 1, d, 20, 0);
    t_note("PBKDF2 with non-HMAC SHA1 provider -> 0x%08lx", (unsigned long)s);
    g0_close(a);
}
TEST(gap0_pbkdf2_empty_password_and_salt_note) {
    REQUIRE(U(BCryptDeriveKeyPBKDF2)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char d[20]; G0_OKST(g0_open(&a, L"SHA1", G0_ALG_HMAC));
    NTSTATUS s1 = U(BCryptDeriveKeyPBKDF2)(a, NULL, 0, (PUCHAR)"s", 1, 1, d, 20, 0);
    NTSTATUS s2 = U(BCryptDeriveKeyPBKDF2)(a, (PUCHAR)"p", 1, NULL, 0, 1, d, 20, 0);
    t_note("empty password -> 0x%08lx ; empty salt -> 0x%08lx", (unsigned long)s1, (unsigned long)s2);
    g0_close(a);
}

/* ---- BCryptDeriveKeyCapi ------------------------------------------------- */
TEST(gap0_derivekeycapi_parameter_validation) {
    REQUIRE(U(BCryptDeriveKeyCapi)); REQUIRE(U(BCryptCreateHash));
    unsigned char d[16]; BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA1, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    ST(U(BCryptDeriveKeyCapi)(h, NULL, d, 16, 1), G0_INVALID_PARAMETER);       /* flags must be 0 */
    ST(U(BCryptDeriveKeyCapi)(h, NULL, NULL, 16, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDeriveKeyCapi)(h, NULL, d, 0, 0), G0_INVALID_PARAMETER);
    /* these three fail before the hash handle is looked at */
    ST(U(BCryptDeriveKeyCapi)(NULL, NULL, d, 0, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDeriveKeyCapi)(NULL, NULL, NULL, 16, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDeriveKeyCapi)(NULL, NULL, d, 16, 2), G0_INVALID_PARAMETER);
    U(BCryptDestroyHash)(h);
}
TEST(gap0_derivekeycapi_digest_prefix) {
    REQUIRE(U(BCryptDeriveKeyCapi)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL; unsigned char d[16] = {0};
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA1, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    NTSTATUS s = U(BCryptDeriveKeyCapi)(h, NULL, d, 16, 0);
    t_note("DeriveKeyCapi(SHA1 'abc', 16 bytes) -> 0x%08lx", (unsigned long)s);
    if (s == 0) { g0_dump("derived", d, 16); CHECKF(g0_eqhex(d, 16, "a9993e364706816aba3e25717850c26c"), "CryptDeriveKey semantics: output is the digest prefix"); }
    U(BCryptDestroyHash)(h);
}

/* ---- ECDH: SecretAgreement -> DeriveKey -> DestroySecret ---------------- */
static int g0_ecdh_pair(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE *ka, BCRYPT_KEY_HANDLE *kb) {
    *ka = *kb = NULL;
    if (U(BCryptGenerateKeyPair)(a, ka, 256, 0) < 0 || U(BCryptFinalizeKeyPair)(*ka, 0) < 0) return 0;
    if (U(BCryptGenerateKeyPair)(a, kb, 256, 0) < 0 || U(BCryptFinalizeKeyPair)(*kb, 0) < 0) return 0;
    return 1;
}
static int g0_pub_import(BCRYPT_ALG_HANDLE a, BCRYPT_KEY_HANDLE k, BCRYPT_KEY_HANDLE *pub) {
    unsigned char blob[256]; ULONG cb = 0;
    *pub = NULL;
    if (U(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &cb, 0) < 0) return 0;
    return U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, pub, blob, cb, 0) >= 0;
}
TEST(gap0_derivekey_ecdh_both_sides_agree) {
    REQUIRE(U(BCryptDeriveKey)); REQUIRE(U(BCryptSecretAgreement)); REQUIRE(U(BCryptDestroySecret));
    REQUIRE(U(BCryptGenerateKeyPair)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE ka, kb, pa, pb; BCRYPT_SECRET_HANDLE s1 = NULL, s2 = NULL;
    if (g0_open(&a, L"ECDH_P256", 0) < 0) { t_skip("ECDH_P256 unavailable"); return; }
    if (!g0_ecdh_pair(a, &ka, &kb) || !g0_pub_import(a, ka, &pa) || !g0_pub_import(a, kb, &pb)) { t_skip("ECDH key setup failed"); return; }
    G0_OKST(U(BCryptSecretAgreement)(ka, pb, &s1, 0));
    G0_OKST(U(BCryptSecretAgreement)(kb, pa, &s2, 0));
    wchar_t sha256[] = L"SHA256"; BCryptBuffer buf = { sizeof sha256, KDF_HASH_ALGORITHM, sha256 };
    BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, 1, &buf };
    unsigned char d1[64] = {0}, d2[64] = {0}; ULONG c1 = 0, c2 = 0;
    G0_OKST(U(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &desc, NULL, 0, &c1, 0));          /* size query */
    EXPECT_EQ(c1, 32);
    G0_OKST(U(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &desc, d1, sizeof d1, &c1, 0));
    G0_OKST(U(BCryptDeriveKey)(s2, BCRYPT_KDF_HASH, &desc, d2, sizeof d2, &c2, 0));
    EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
    CHECK(!memcmp(d1, d2, 32));
    /* raw secret: 32 bytes for P-256, identical on both sides, and not the hash of itself */
    unsigned char r1[64] = {0}, r2[64] = {0}; ULONG rc1 = 0, rc2 = 0;
    G0_OKST(U(BCryptDeriveKey)(s1, BCRYPT_KDF_RAW_SECRET, NULL, r1, sizeof r1, &rc1, 0));
    G0_OKST(U(BCryptDeriveKey)(s2, BCRYPT_KDF_RAW_SECRET, NULL, r2, sizeof r2, &rc2, 0));
    EXPECT_EQ(rc1, 32); EXPECT_EQ(rc2, 32); CHECK(!memcmp(r1, r2, 32));
    CHECK(memcmp(r1, d1, 32) != 0);
    /* the secret handle can be used repeatedly */
    unsigned char d3[64] = {0}; ULONG c3 = 0;
    G0_OKST(U(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &desc, d3, sizeof d3, &c3, 0));
    CHECK(c3 == 32 && !memcmp(d1, d3, 32));
    G0_OKST(U(BCryptDestroySecret)(s1)); G0_OKST(U(BCryptDestroySecret)(s2));
    U(BCryptDestroyKey)(ka); U(BCryptDestroyKey)(kb); U(BCryptDestroyKey)(pa); U(BCryptDestroyKey)(pb); g0_close(a);
}
TEST(gap0_derivekey_hash_kdf_digest_sizes) {
    REQUIRE(U(BCryptDeriveKey)); REQUIRE(U(BCryptSecretAgreement)); REQUIRE(U(BCryptDestroySecret));
    REQUIRE(U(BCryptGenerateKeyPair)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE ka, kb, pb; BCRYPT_SECRET_HANDLE s = NULL;
    if (g0_open(&a, L"ECDH_P256", 0) < 0) { t_skip("ECDH_P256 unavailable"); return; }
    if (!g0_ecdh_pair(a, &ka, &kb) || !g0_pub_import(a, kb, &pb)) { t_skip("ECDH key setup failed"); return; }
    G0_OKST(U(BCryptSecretAgreement)(ka, pb, &s, 0));
    static const struct { wchar_t id[8]; ULONG n; } h[] = { {L"SHA1", 20}, {L"SHA256", 32}, {L"SHA384", 48}, {L"SHA512", 64} };
    for (int i = 0; i < 4; i++) {
        BCryptBuffer buf = { (ULONG)((lstrlenW(h[i].id) + 1) * 2), KDF_HASH_ALGORITHM, (PVOID)h[i].id };
        BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, 1, &buf };
        unsigned char d[64]; ULONG c = 0;
        G0_OKST(U(BCryptDeriveKey)(s, BCRYPT_KDF_HASH, &desc, d, sizeof d, &c, 0));
        EXPECT_EQ(c, h[i].n);
        c = 0; G0_OKST(U(BCryptDeriveKey)(s, BCRYPT_KDF_HASH, &desc, NULL, 0, &c, 0));
        EXPECT_EQ(c, h[i].n);
    }
    U(BCryptDestroySecret)(s); U(BCryptDestroyKey)(ka); U(BCryptDestroyKey)(kb); U(BCryptDestroyKey)(pb); g0_close(a);
}
TEST(gap0_derivekey_hmac_kdf_depends_on_key) {
    REQUIRE(U(BCryptDeriveKey)); REQUIRE(U(BCryptSecretAgreement)); REQUIRE(U(BCryptDestroySecret));
    REQUIRE(U(BCryptGenerateKeyPair)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE ka, kb, pb; BCRYPT_SECRET_HANDLE s = NULL;
    if (g0_open(&a, L"ECDH_P256", 0) < 0) { t_skip("ECDH_P256 unavailable"); return; }
    if (!g0_ecdh_pair(a, &ka, &kb) || !g0_pub_import(a, kb, &pb)) { t_skip("ECDH key setup failed"); return; }
    G0_OKST(U(BCryptSecretAgreement)(ka, pb, &s, 0));
    wchar_t sha256[] = L"SHA256";
    BCryptBuffer b1[2] = { { sizeof sha256, KDF_HASH_ALGORITHM, sha256 }, { 4, 3 /* KDF_HMAC_KEY */, (PVOID)"key1" } };
    BCryptBuffer b2[2] = { { sizeof sha256, KDF_HASH_ALGORITHM, sha256 }, { 4, 3, (PVOID)"key2" } };
    BCryptBufferDesc d1 = { BCRYPTBUFFER_VERSION, 2, b1 }, d2 = { BCRYPTBUFFER_VERSION, 2, b2 };
    unsigned char o1[32], o2[32], o3[32]; ULONG c;
    NTSTATUS s1 = U(BCryptDeriveKey)(s, BCRYPT_KDF_HMAC, &d1, o1, 32, &c, 0);
    NTSTATUS s2 = U(BCryptDeriveKey)(s, BCRYPT_KDF_HMAC, &d2, o2, 32, &c, 0);
    NTSTATUS s3 = U(BCryptDeriveKey)(s, BCRYPT_KDF_HMAC, &d1, o3, 32, &c, 0);
    t_note("KDF_HMAC statuses 0x%08lx 0x%08lx 0x%08lx", (unsigned long)s1, (unsigned long)s2, (unsigned long)s3);
    if (s1 == 0 && s2 == 0 && s3 == 0) { CHECK(memcmp(o1, o2, 32) != 0); CHECK(!memcmp(o1, o3, 32)); }
    U(BCryptDestroySecret)(s); U(BCryptDestroyKey)(ka); U(BCryptDestroyKey)(kb); U(BCryptDestroyKey)(pb); g0_close(a);
}
TEST(gap0_derivekey_small_buffer_and_unknown_kdf_note) {
    REQUIRE(U(BCryptDeriveKey)); REQUIRE(U(BCryptSecretAgreement)); REQUIRE(U(BCryptDestroySecret));
    REQUIRE(U(BCryptGenerateKeyPair)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE ka, kb, pb; BCRYPT_SECRET_HANDLE s = NULL;
    if (g0_open(&a, L"ECDH_P256", 0) < 0) { t_skip("ECDH_P256 unavailable"); return; }
    if (!g0_ecdh_pair(a, &ka, &kb) || !g0_pub_import(a, kb, &pb)) { t_skip("ECDH key setup failed"); return; }
    G0_OKST(U(BCryptSecretAgreement)(ka, pb, &s, 0));
    wchar_t sha256[] = L"SHA256"; BCryptBuffer buf = { sizeof sha256, KDF_HASH_ALGORITHM, sha256 };
    BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, 1, &buf };
    unsigned char d[64]; ULONG c = 0;
    NTSTATUS st = U(BCryptDeriveKey)(s, BCRYPT_KDF_HASH, &desc, d, 8, &c, 0);
    t_note("DeriveKey(cb=8) -> 0x%08lx, cbResult=%lu", (unsigned long)st, (unsigned long)c);
    /* Windows 10 22H2: a smaller output buffer is not an error; the result is truncated to cb (status 0, cbResult 8). */
    ST(st, 0); EXPECT_EQ(c, 8);
    st = U(BCryptDeriveKey)(s, L"NO_SUCH_KDF", NULL, d, sizeof d, &c, 0);
    t_note("DeriveKey(unknown KDF) -> 0x%08lx", (unsigned long)st);
    U(BCryptDestroySecret)(s); U(BCryptDestroyKey)(ka); U(BCryptDestroyKey)(kb); U(BCryptDestroyKey)(pb); g0_close(a);
}
TEST(gap0_derivekey_handle_validation) {
    REQUIRE(U(BCryptDeriveKey)); REQUIRE(U(BCryptDestroySecret)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    unsigned char d[32]; ULONG c = 5;
    ST(U(BCryptDeriveKey)(NULL, BCRYPT_KDF_HASH, NULL, d, sizeof d, NULL, 0), G0_INVALID_PARAMETER);   /* pcbResult first */
    ST(U(BCryptDeriveKey)(NULL, BCRYPT_KDF_HASH, NULL, d, sizeof d, &c, 0), G0_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"ECDH_P256", 0));
    ST(U(BCryptDeriveKey)(a, BCRYPT_KDF_HASH, NULL, d, sizeof d, &c, 0), G0_INVALID_HANDLE);           /* algorithm is not a secret */
    ST(U(BCryptDestroySecret)(NULL), G0_INVALID_HANDLE);
    ST(U(BCryptDestroySecret)(a), G0_INVALID_HANDLE);
    BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ST(U(BCryptDestroySecret)(h), G0_INVALID_HANDLE);                                                   /* hash is not a secret */
    ST(U(BCryptDeriveKey)(h, BCRYPT_KDF_HASH, NULL, d, sizeof d, &c, 0), G0_INVALID_HANDLE);
    U(BCryptDestroyHash)(h); g0_close(a);
}

/* ---- BCryptKeyDerivation (SP800-108) ---------------------------------- */
TEST(gap0_keyderivation_parameter_checks_precede_handle) {
    REQUIRE(U(BCryptKeyDerivation));
    unsigned char d[32]; ULONG c = 0; BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, 0, NULL };
    ST(U(BCryptKeyDerivation)(NULL, &desc, NULL, 32, &c, 0), G0_INVALID_PARAMETER);   /* NULL output */
    ST(U(BCryptKeyDerivation)(NULL, &desc, d, 0, &c, 0), G0_INVALID_PARAMETER);       /* zero length */
    ST(U(BCryptKeyDerivation)(NULL, &desc, d, 32, NULL, 0), G0_INVALID_PARAMETER);    /* NULL pcbResult */
    ST(U(BCryptKeyDerivation)(NULL, &desc, d, 32, &c, 0), G0_INVALID_HANDLE);
}
TEST(gap0_keyderivation_requires_kdf_key) {
    REQUIRE(U(BCryptKeyDerivation)); REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char key[16] = {0}, d[32]; ULONG c = 0;
    BCryptBufferDesc desc = { BCRYPTBUFFER_VERSION, 0, NULL };
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, 16, 0));
    ST(U(BCryptKeyDerivation)(k, &desc, d, 32, &c, 0), G0_NOT_SUPPORTED);            /* cipher key: wrong algorithm class */
    BCRYPT_ALG_HANDLE h; G0_OKST(g0_open(&h, L"SHA256", 0));
    ST(U(BCryptKeyDerivation)(h, &desc, d, 32, &c, 0), G0_INVALID_HANDLE);            /* algorithm handle is not a key */
    U(BCryptDestroyKey)(k); g0_close(a); g0_close(h);
}
TEST(gap0_keyderivation_sp800_108_ctr_properties) {
    REQUIRE(U(BCryptKeyDerivation)); REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char secret[32], o1[48], o2[48], o3[48], o4[16]; ULONG c;
    NTSTATUS st = g0_open(&a, L"SP800_108_CTR_HMAC", 0);
    if (st < 0) { t_skip("SP800_108_CTR_HMAC unavailable: 0x%08lx", (unsigned long)st); return; }
    for (int i = 0; i < 32; i++) secret[i] = (unsigned char)(i + 1);
    G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, 32, 0));
    wchar_t sha256[] = L"SHA256";
    BCryptBuffer b1[3] = { { sizeof sha256, KDF_HASH_ALGORITHM, sha256 }, { 5, KDF_LABEL, (PVOID)"label" }, { 3, KDF_CONTEXT, (PVOID)"ctx" } };
    BCryptBuffer b2[3] = { { sizeof sha256, KDF_HASH_ALGORITHM, sha256 }, { 6, KDF_LABEL, (PVOID)"label2" }, { 3, KDF_CONTEXT, (PVOID)"ctx" } };
    BCryptBufferDesc d1 = { BCRYPTBUFFER_VERSION, 3, b1 }, d2 = { BCRYPTBUFFER_VERSION, 3, b2 };
    c = 0; G0_OKST(U(BCryptKeyDerivation)(k, &d1, o1, 48, &c, 0)); EXPECT_EQ(c, 48);
    c = 0; G0_OKST(U(BCryptKeyDerivation)(k, &d1, o2, 48, &c, 0)); EXPECT_EQ(c, 48);
    c = 0; G0_OKST(U(BCryptKeyDerivation)(k, &d2, o3, 48, &c, 0)); EXPECT_EQ(c, 48);
    c = 0; G0_OKST(U(BCryptKeyDerivation)(k, &d1, o4, 16, &c, 0)); EXPECT_EQ(c, 16);
    CHECK(!memcmp(o1, o2, 48));                    /* deterministic */
    CHECK(memcmp(o1, o3, 48) != 0);                /* label is an input */
    /* The requested length is part of the PRF input (SP800-108 [L]), so Windows 10 does not return a prefix. */
    CHECK(memcmp(o1, o4, 16) != 0);
    U(BCryptDestroyKey)(k); g0_close(a);
}
