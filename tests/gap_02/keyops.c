/* NCryptSignHash / NCryptVerifySignature / NCryptSecretAgreement / NCryptSetProperty /
 * NCryptTranslateHandle / NCryptVerifyClaim.
 * Handle validation (header magic) is visible in the reference decompilation; the cryptographic
 * round trips use unnamed in-memory keys of the Microsoft software key storage provider. */
#include "g2.h"

/* Wine's ncrypt.dll exports several of these as aborting stubs: skip them there. */
#undef REQUIRE
#define REQUIRE(ptr) do { if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; } if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)

#define NEED_CRYPTO() do { if (t_is_wine()) { t_skip("needs real CNG key storage"); return; } } while (0)

/* A readable fake NCrypt object with an arbitrary first DWORD. */
typedef struct { DWORD magic; DWORD pad[63]; } __attribute__((aligned(16))) g2_nobj;
static void nobj(g2_nobj *o, DWORD magic) { memset(o, 0, sizeof *o); o->magic = magic; }

static const DWORD bad_magics[] = { 0, 1, 0x44440001, 0x44440003, 0x44440000, 0x44440004, 0x44444442, 0xFFFFFFFF, 0x20000000 };
#define NBAD (sizeof bad_magics / sizeof bad_magics[0])

/* ---------------- NCryptSignHash: handle validation ---------------- */
TEST(gap2_sign_null_handle) {
    REQUIRE(U(NCryptSignHash));
    BYTE h[32] = {0}, s[256]; DWORD cb = 0;
    G2_EQ(U(NCryptSignHash)(0, NULL, h, 32, s, sizeof s, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSignHash)(0, NULL, NULL, 0, NULL, 0, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSignHash)(0, NULL, h, 32, s, sizeof s, &cb, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSignHash)(0, NULL, h, 32, s, sizeof s, &cb, NCRYPT_SILENT_FLAG), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_sign_wrong_object_type) {
    REQUIRE(U(NCryptSignHash));
    BYTE h[32] = {0}, s[256]; DWORD cb = 0;
    for (unsigned i = 0; i < NBAD; i++) {
        g2_nobj o; nobj(&o, bad_magics[i]);
        cb = 0x1234;
        SECURITY_STATUS r = U(NCryptSignHash)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&o, NULL, h, 32, s, sizeof s, &cb, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
        EXPECT_EQ(cb, 0x1234);   /* pcbResult untouched on a rejected handle */
    }
}
TEST(gap2_sign_invalid_handle_ignores_other_args) {
    REQUIRE(U(NCryptSignHash));
    /* The handle is validated before any other argument is looked at, so NULL pcbResult/hash is fine. */
    G2_EQ(U(NCryptSignHash)(0, NULL, NULL, 0, NULL, 0, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSignHash)(0, NULL, NULL, 0, NULL, 0, NULL, 0xFFFFFFFF), G2_NTE_INVALID_HANDLE);
}

/* ---------------- NCryptVerifySignature: handle validation ---------------- */
TEST(gap2_verify_null_handle) {
    REQUIRE(U(NCryptVerifySignature));
    BYTE h[32] = {0}, s[64] = {0};
    G2_EQ(U(NCryptVerifySignature)(0, NULL, h, 32, s, sizeof s, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptVerifySignature)(0, NULL, NULL, 0, NULL, 0, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptVerifySignature)(0, NULL, h, 32, s, sizeof s, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_verify_wrong_object_type) {
    REQUIRE(U(NCryptVerifySignature));
    BYTE h[32] = {0}, s[64] = {0};
    for (unsigned i = 0; i < NBAD; i++) {
        g2_nobj o; nobj(&o, bad_magics[i]);
        SECURITY_STATUS r = U(NCryptVerifySignature)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&o, NULL, h, 32, s, sizeof s, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
    }
}

/* ---------------- NCryptSecretAgreement: handle validation ---------------- */
TEST(gap2_secret_agreement_null_handles) {
    REQUIRE(U(NCryptSecretAgreement));
    NCRYPT_SECRET_HANDLE s = 0x1234;
    G2_EQ(U(NCryptSecretAgreement)(0, 0, &s, 0), G2_NTE_INVALID_HANDLE);
    EXPECT_EQ(s, 0x1234);
    G2_EQ(U(NCryptSecretAgreement)(0, 0, NULL, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSecretAgreement)(0, 0, &s, NCRYPT_SILENT_FLAG), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_secret_agreement_wrong_object_type) {
    REQUIRE(U(NCryptSecretAgreement));
    for (unsigned i = 0; i < NBAD; i++) {
        g2_nobj a, b; nobj(&a, bad_magics[i]); nobj(&b, 0x44440002);
        NCRYPT_SECRET_HANDLE s = 0x77;
        /* bad private handle: rejected before the public handle matters */
        SECURITY_STATUS r = U(NCryptSecretAgreement)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&a, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&b, &s, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "priv magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
        EXPECT_EQ(s, 0x77);
        /* bad public handle */
        r = U(NCryptSecretAgreement)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&b, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&a, &s, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "pub magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
        EXPECT_EQ(s, 0x77);
    }
}

/* ---------------- NCryptVerifyClaim: handle / parameter validation ---------------- */
TEST(gap2_verify_claim_null_subject) {
    REQUIRE(U(NCryptVerifyClaim));
    NCryptBufferDesc out; memset(&out, 0, sizeof out);
    G2_EQ(U(NCryptVerifyClaim)(0, 0, 0, NULL, NULL, 0, &out, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptVerifyClaim)(0, 0, 1, NULL, NULL, 0, NULL, 0), G2_NTE_INVALID_HANDLE);   /* handle is checked before pOutput */
    G2_EQ(U(NCryptVerifyClaim)(0, 0, 2, NULL, NULL, 0, &out, 0), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_verify_claim_wrong_object_type) {
    REQUIRE(U(NCryptVerifyClaim));
    NCryptBufferDesc out; memset(&out, 0, sizeof out);
    for (unsigned i = 0; i < NBAD; i++) {
        g2_nobj o; nobj(&o, bad_magics[i]);
        SECURITY_STATUS r = U(NCryptVerifyClaim)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&o, 0, 1, NULL, NULL, 0, &out, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "subject magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
    }
}
TEST(gap2_verify_claim_bad_authority_handle) {
    REQUIRE(U(NCryptVerifyClaim));
    NCryptBufferDesc out; memset(&out, 0, sizeof out);
    g2_nobj good, bad; nobj(&good, 0x44440002);
    /* A non-NULL authority handle that is not a key handle is rejected with the subject check:
     * the subject handle is never used because both are validated first. */
    for (unsigned i = 0; i < NBAD; i++) {
        if (bad_magics[i] == 0x44440002) continue;
        nobj(&bad, bad_magics[i]);
        SECURITY_STATUS r = U(NCryptVerifyClaim)((NCRYPT_KEY_HANDLE)(ULONG_PTR)&good, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&bad, 1, NULL, NULL, 0, &out, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "authority magic 0x%08lx -> 0x%08lx", (unsigned long)bad_magics[i], (unsigned long)r);
    }
}
TEST(gap2_verify_claim_null_output_with_real_key) {
    REQUIRE(U(NCryptVerifyClaim)); NEED_CRYPTO();
    NCRYPT_PROV_HANDLE p = g2_ksp(); if (!p) { t_skip("no KSP"); return; }
    NCRYPT_KEY_HANDLE k = g2_key(p, NCRYPT_RSA_ALGORITHM, 1024);
    if (!k) { U(NCryptFreeObject)(p); t_skip("cannot create key"); return; }
    /* valid subject, NULL pOutput: NTE_INVALID_PARAMETER before the provider is consulted */
    G2_EQ(U(NCryptVerifyClaim)(k, 0, 1, NULL, NULL, 0, NULL, 0), G2_NTE_INVALID_PARAM);
    NCryptBufferDesc out; memset(&out, 0, sizeof out);
    SECURITY_STATUS r = U(NCryptVerifyClaim)(k, 0, 1, NULL, NULL, 0, &out, 0);
    t_note("NCryptVerifyClaim(software KSP key, type 1, no blob) -> 0x%08lx (provider dependent)", (unsigned long)r);
    CHECK(r != 0);   /* an empty claim cannot verify */
    U(NCryptFreeObject)(k); U(NCryptFreeObject)(p);
}

/* ---------------- NCryptTranslateHandle: parameter validation ---------------- */
TEST(gap2_translate_null_key_out) {
    REQUIRE(U(NCryptTranslateHandle));
    NCRYPT_PROV_HANDLE p = 0x55;
    G2_EQ(U(NCryptTranslateHandle)(&p, NULL, 1, 1, 0, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(U(NCryptTranslateHandle)(NULL, NULL, 1, 1, AT_KEYEXCHANGE, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(p, 0x55);
}
TEST(gap2_translate_null_legacy_provider) {
    REQUIRE(U(NCryptTranslateHandle));
    NCRYPT_PROV_HANDLE p = 0x55; NCRYPT_KEY_HANDLE k = 0x66;
    G2_EQ(U(NCryptTranslateHandle)(&p, &k, 0, 0, 0, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(U(NCryptTranslateHandle)(&p, &k, 0, 1, AT_SIGNATURE, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(U(NCryptTranslateHandle)(NULL, &k, 0, 1, AT_KEYEXCHANGE, 0), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(p, 0x55); EXPECT_EQ(k, 0x66);   /* outputs untouched */
}

/* ---------------- NCryptSetProperty: handle validation ---------------- */
TEST(gap2_setprop_null_handle) {
    REQUIRE(U(NCryptSetProperty));
    DWORD v = 1024;
    G2_EQ(U(NCryptSetProperty)(0, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptSetProperty)(0, NULL, NULL, 0, 0), G2_NTE_INVALID_HANDLE);   /* handle precedes property check */
    G2_EQ(U(NCryptSetProperty)(0, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, NCRYPT_SILENT_FLAG), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_setprop_wrong_object_type) {
    REQUIRE(U(NCryptSetProperty));
    DWORD v = 1024;
    static const DWORD m[] = { 0, 1, 0x44440000, 0x44440003, 0x44440004, 0x44444441, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof m / sizeof m[0]; i++) {
        g2_nobj o; nobj(&o, m[i]);
        SECURITY_STATUS r = U(NCryptSetProperty)((NCRYPT_HANDLE)(ULONG_PTR)&o, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "magic 0x%08lx -> 0x%08lx", (unsigned long)m[i], (unsigned long)r);
    }
}

/* ---------------- real-key tests ---------------- */
typedef struct { NCRYPT_PROV_HANDLE p; NCRYPT_KEY_HANDLE k; } kp_t;
static int mk(kp_t *x, LPCWSTR alg, DWORD bits) {
    memset(x, 0, sizeof *x);
    if (t_is_wine()) { t_skip("needs real CNG key storage"); return 0; }
    x->p = g2_ksp(); if (!x->p) { t_skip("no software KSP"); return 0; }
    x->k = g2_key(x->p, alg, bits); if (!x->k) { U(NCryptFreeObject)(x->p); t_skip("cannot create %ls key", alg); return 0; }
    return 1;
}
static void rel(kp_t *x) { if (x->k) U(NCryptFreeObject)(x->k); if (x->p) U(NCryptFreeObject)(x->p); }

static const BYTE HASH32[32] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };

TEST(gap2_sign_rsa_pkcs1_roundtrip) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature)); REQUIRE(U(NCryptCreatePersistedKey));
    kp_t x; if (!mk(&x, NCRYPT_RSA_ALGORITHM, 1024)) return;
    BCRYPT_PKCS1_PADDING_INFO pi = { NCRYPT_SHA256_ALGORITHM };
    BYTE sig[256], sig2[256]; DWORD cb = 0, cb2 = 0;
    /* size query */
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb, 128);
    /* too small */
    cb2 = 0;
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, sig, 127, &cb2, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb2, 128);
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, sig, 1, &cb2, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BUFFER_TOO_SMALL);
    /* exact */
    memset(sig, 0, sizeof sig);
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, sig, 128, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb, 128);
    /* larger buffer: still reports 128 */
    cb2 = 0;
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, sig2, 256, &cb2, NCRYPT_PAD_PKCS1_FLAG), 0);
    EXPECT_EQ(cb2, 128);
    CHECK(!memcmp(sig, sig2, 128));   /* PKCS#1 v1.5 signing is deterministic */
    /* verify */
    G2_EQ(U(NCryptVerifySignature)(x.k, &pi, (PBYTE)HASH32, 32, sig, 128, NCRYPT_PAD_PKCS1_FLAG), 0);
    /* tampered signature */
    sig[10] ^= 0x40;
    G2_EQ(U(NCryptVerifySignature)(x.k, &pi, (PBYTE)HASH32, 32, sig, 128, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BAD_SIGNATURE);
    sig[10] ^= 0x40;
    /* different hash */
    BYTE h2[32]; memcpy(h2, HASH32, 32); h2[31] ^= 1;
    G2_EQ(U(NCryptVerifySignature)(x.k, &pi, h2, 32, sig, 128, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BAD_SIGNATURE);
    /* different hash algorithm in the padding info, same digest length class (SHA384 needs 48) */
    BCRYPT_PKCS1_PADDING_INFO pi1 = { NCRYPT_SHA1_ALGORITHM };
    SECURITY_STATUS r = U(NCryptVerifySignature)(x.k, &pi1, (PBYTE)HASH32, 20, sig, 128, NCRYPT_PAD_PKCS1_FLAG);
    CHECK(r != 0);
    rel(&x);
}
TEST(gap2_sign_rsa_hash_algorithms) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    kp_t x; if (!mk(&x, NCRYPT_RSA_ALGORITHM, 1024)) return;
    static const struct { LPCWSTR alg; DWORD len; } t[] = {
        { NCRYPT_SHA1_ALGORITHM, 20 }, { NCRYPT_SHA256_ALGORITHM, 32 }, { NCRYPT_SHA384_ALGORITHM, 48 }, { NCRYPT_SHA512_ALGORITHM, 64 },
    };
    BYTE h[64]; for (int i = 0; i < 64; i++) h[i] = (BYTE)(i * 7 + 3);
    for (unsigned i = 0; i < 4; i++) {
        BCRYPT_PKCS1_PADDING_INFO pi = { t[i].alg };
        BYTE sig[128]; DWORD cb = 0;
        SECURITY_STATUS r = U(NCryptSignHash)(x.k, &pi, h, t[i].len, sig, sizeof sig, &cb, NCRYPT_PAD_PKCS1_FLAG);
        CHECKF(r == 0, "%ls sign 0x%08lx", t[i].alg, (unsigned long)r);
        if (r) continue;
        EXPECT_EQ(cb, 128);
        r = U(NCryptVerifySignature)(x.k, &pi, h, t[i].len, sig, cb, NCRYPT_PAD_PKCS1_FLAG);
        CHECKF(r == 0, "%ls verify 0x%08lx", t[i].alg, (unsigned long)r);
        /* a hash of the wrong length for the declared algorithm is rejected */
        r = U(NCryptSignHash)(x.k, &pi, h, t[i].len - 1, sig, sizeof sig, &cb, NCRYPT_PAD_PKCS1_FLAG);
        CHECKF(r != 0, "%ls short hash accepted", t[i].alg);
    }
    rel(&x);
}
TEST(gap2_sign_rsa_missing_padding) {
    REQUIRE(U(NCryptSignHash));
    kp_t x; if (!mk(&x, NCRYPT_RSA_ALGORITHM, 1024)) return;
    BYTE sig[128]; DWORD cb = 0;
    SECURITY_STATUS r;
    r = U(NCryptSignHash)(x.k, NULL, (PBYTE)HASH32, 32, sig, sizeof sig, &cb, 0);
    CHECKF(r != 0, "RSA sign with no padding flag/info accepted"); t_note("RSA sign flags=0 pad=NULL -> 0x%08lx", (unsigned long)r);
    r = U(NCryptSignHash)(x.k, NULL, (PBYTE)HASH32, 32, sig, sizeof sig, &cb, NCRYPT_PAD_PKCS1_FLAG);
    CHECKF(r != 0, "PKCS1 flag with NULL padding info accepted"); t_note("RSA sign PKCS1 pad=NULL -> 0x%08lx", (unsigned long)r);
    rel(&x);
}
TEST(gap2_sign_rsa_pss) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    kp_t x; if (!mk(&x, NCRYPT_RSA_ALGORITHM, 1024)) return;
    BCRYPT_PSS_PADDING_INFO pi = { NCRYPT_SHA256_ALGORITHM, 32 };
    BYTE s1[128], s2[128]; DWORD c1 = 0, c2 = 0;
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, s1, sizeof s1, &c1, NCRYPT_PAD_PSS_FLAG), 0);
    G2_EQ(U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, s2, sizeof s2, &c2, NCRYPT_PAD_PSS_FLAG), 0);
    EXPECT_EQ(c1, 128); EXPECT_EQ(c2, 128);
    CHECK(memcmp(s1, s2, 128) != 0);    /* random salt */
    G2_EQ(U(NCryptVerifySignature)(x.k, &pi, (PBYTE)HASH32, 32, s1, c1, NCRYPT_PAD_PSS_FLAG), 0);
    G2_EQ(U(NCryptVerifySignature)(x.k, &pi, (PBYTE)HASH32, 32, s2, c2, NCRYPT_PAD_PSS_FLAG), 0);
    /* a PSS signature does not verify as PKCS#1 */
    BCRYPT_PKCS1_PADDING_INFO p1 = { NCRYPT_SHA256_ALGORITHM };
    G2_EQ(U(NCryptVerifySignature)(x.k, &p1, (PBYTE)HASH32, 32, s1, c1, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BAD_SIGNATURE);
    /* zero salt length is a valid, deterministic PSS configuration */
    BCRYPT_PSS_PADDING_INFO pz = { NCRYPT_SHA256_ALGORITHM, 0 };
    G2_EQ(U(NCryptSignHash)(x.k, &pz, (PBYTE)HASH32, 32, s1, sizeof s1, &c1, NCRYPT_PAD_PSS_FLAG), 0);
    G2_EQ(U(NCryptSignHash)(x.k, &pz, (PBYTE)HASH32, 32, s2, sizeof s2, &c2, NCRYPT_PAD_PSS_FLAG), 0);
    CHECK(c1 == c2 && !memcmp(s1, s2, c1));
    G2_EQ(U(NCryptVerifySignature)(x.k, &pz, (PBYTE)HASH32, 32, s1, c1, NCRYPT_PAD_PSS_FLAG), 0);
    rel(&x);
}
TEST(gap2_verify_rsa_wrong_key_and_length) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    kp_t a, b; if (!mk(&a, NCRYPT_RSA_ALGORITHM, 1024)) return;
    if (!mk(&b, NCRYPT_RSA_ALGORITHM, 1024)) { rel(&a); return; }
    BCRYPT_PKCS1_PADDING_INFO pi = { NCRYPT_SHA256_ALGORITHM };
    BYTE sig[128]; DWORD cb = 0;
    G2_EQ(U(NCryptSignHash)(a.k, &pi, (PBYTE)HASH32, 32, sig, sizeof sig, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    G2_EQ(U(NCryptVerifySignature)(b.k, &pi, (PBYTE)HASH32, 32, sig, cb, NCRYPT_PAD_PKCS1_FLAG), G2_NTE_BAD_SIGNATURE);
    G2_EQ(U(NCryptVerifySignature)(a.k, &pi, (PBYTE)HASH32, 32, sig, cb, NCRYPT_PAD_PKCS1_FLAG), 0);
    SECURITY_STATUS r = U(NCryptVerifySignature)(a.k, &pi, (PBYTE)HASH32, 32, sig, cb - 1, NCRYPT_PAD_PKCS1_FLAG);
    CHECK(r != 0); t_note("verify with signature one byte short -> 0x%08lx", (unsigned long)r);
    r = U(NCryptVerifySignature)(a.k, &pi, (PBYTE)HASH32, 32, sig, 0, NCRYPT_PAD_PKCS1_FLAG);
    CHECK(r != 0); t_note("verify with empty signature -> 0x%08lx", (unsigned long)r);
    rel(&a); rel(&b);
}
TEST(gap2_sign_ecdsa_p256_roundtrip) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    kp_t x; if (!mk(&x, NCRYPT_ECDSA_P256_ALGORITHM, 0)) return;
    BYTE sig[64], s2[64]; DWORD cb = 0, c2 = 0;
    G2_EQ(U(NCryptSignHash)(x.k, NULL, (PBYTE)HASH32, 32, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 64);
    G2_EQ(U(NCryptSignHash)(x.k, NULL, (PBYTE)HASH32, 32, sig, 63, &c2, 0), G2_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(c2, 64);
    G2_EQ(U(NCryptSignHash)(x.k, NULL, (PBYTE)HASH32, 32, sig, 64, &cb, 0), 0);
    EXPECT_EQ(cb, 64);
    G2_EQ(U(NCryptVerifySignature)(x.k, NULL, (PBYTE)HASH32, 32, sig, 64, 0), 0);
    sig[5] ^= 1;
    G2_EQ(U(NCryptVerifySignature)(x.k, NULL, (PBYTE)HASH32, 32, sig, 64, 0), G2_NTE_BAD_SIGNATURE);
    sig[5] ^= 1;
    BYTE h2[32]; memcpy(h2, HASH32, 32); h2[0] ^= 0x80;
    G2_EQ(U(NCryptVerifySignature)(x.k, NULL, h2, 32, sig, 64, 0), G2_NTE_BAD_SIGNATURE);
    /* hashes of other lengths are accepted for ECDSA (truncated / zero-padded per the curve) */
    BYTE h48[48]; for (int i = 0; i < 48; i++) h48[i] = (BYTE)i;
    G2_EQ(U(NCryptSignHash)(x.k, NULL, h48, 48, s2, 64, &c2, 0), 0);
    G2_EQ(U(NCryptVerifySignature)(x.k, NULL, h48, 48, s2, 64, 0), 0);
    /* an ECDSA key does not take PKCS1 padding */
    BCRYPT_PKCS1_PADDING_INFO pi = { NCRYPT_SHA256_ALGORITHM };
    SECURITY_STATUS r = U(NCryptSignHash)(x.k, &pi, (PBYTE)HASH32, 32, sig, 64, &cb, NCRYPT_PAD_PKCS1_FLAG);
    CHECK(r != 0); t_note("ECDSA sign with PKCS1 flag -> 0x%08lx", (unsigned long)r);
    rel(&x);
}
TEST(gap2_sign_ecdsa_curve_sizes) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptVerifySignature));
    static const struct { LPCWSTR alg; DWORD sz; } t[] = { { NCRYPT_ECDSA_P256_ALGORITHM, 64 }, { NCRYPT_ECDSA_P384_ALGORITHM, 96 }, { NCRYPT_ECDSA_P521_ALGORITHM, 132 } };
    for (unsigned i = 0; i < 3; i++) {
        kp_t x; if (!mk(&x, t[i].alg, 0)) return;
        BYTE sig[160], h[64]; DWORD cb = 0; memset(h, 0x5a, sizeof h);
        G2_EQ(U(NCryptSignHash)(x.k, NULL, h, 32, NULL, 0, &cb, 0), 0);
        CHECKF(cb == t[i].sz, "%ls signature size %lu", t[i].alg, (unsigned long)cb);
        G2_EQ(U(NCryptSignHash)(x.k, NULL, h, 32, sig, sizeof sig, &cb, 0), 0);
        EXPECT_EQ(cb, t[i].sz);
        G2_EQ(U(NCryptVerifySignature)(x.k, NULL, h, 32, sig, cb, 0), 0);
        rel(&x);
    }
}
TEST(gap2_sign_after_free_handle) {
    REQUIRE(U(NCryptSignHash)); REQUIRE(U(NCryptFreeObject));
    /* A freed key handle must not be used again: the memory is released, so no call is made here.
     * Only the documented return of NCryptFreeObject on a live key is recorded. */
    kp_t x; if (!mk(&x, NCRYPT_ECDSA_P256_ALGORITHM, 0)) return;
    G2_EQ(U(NCryptFreeObject)(x.k), 0); x.k = 0;
    rel(&x);
}

/* ---------------- NCryptSetProperty with real keys ---------------- */
TEST(gap2_setprop_length_before_finalize) {
    REQUIRE(U(NCryptSetProperty)); REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptFinalizeKey));
    if (t_is_wine()) { t_skip("needs real CNG"); return; }
    NCRYPT_PROV_HANDLE p = g2_ksp(); if (!p) { t_skip("no KSP"); return; }
    static const DWORD lens[] = { 512, 1024, 2048 };
    for (unsigned i = 0; i < 3; i++) {
        NCRYPT_KEY_HANDLE k = 0;
        G2_EQ(U(NCryptCreatePersistedKey)(p, &k, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), 0);
        if (!k) continue;
        DWORD v = lens[i];
        G2_EQ(U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0), 0);
        if (lens[i] == 2048) { U(NCryptFreeObject)(k); continue; }   /* skip generating the larger key */
        G2_EQ(U(NCryptFinalizeKey)(k, 0), 0);
        BCRYPT_PKCS1_PADDING_INFO pi = { NCRYPT_SHA1_ALGORITHM };
        DWORD cb = 0;
        G2_EQ(U(NCryptSignHash)(k, &pi, (PBYTE)HASH32, 20, NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG), 0);
        EXPECT_EQ(cb, lens[i] / 8);
        U(NCryptFreeObject)(k);
    }
    U(NCryptFreeObject)(p);
}
TEST(gap2_setprop_after_finalize) {
    REQUIRE(U(NCryptSetProperty));
    kp_t x; if (!mk(&x, NCRYPT_RSA_ALGORITHM, 1024)) return;
    DWORD v = 2048;
    SECURITY_STATUS r = U(NCryptSetProperty)(x.k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0);
    CHECK(r != 0);   /* length is fixed once the key is finalized */
    t_note("NCryptSetProperty(Length) after finalize -> 0x%08lx", (unsigned long)r);
    rel(&x);
}
TEST(gap2_setprop_null_and_long_name) {
    REQUIRE(U(NCryptSetProperty));
    kp_t x; if (!mk(&x, NCRYPT_ECDSA_P256_ALGORITHM, 0)) return;
    DWORD v = 1;
    G2_EQ(U(NCryptSetProperty)(x.k, NULL, (PBYTE)&v, 4, 0), G2_NTE_INVALID_PARAM);
    WCHAR n[100];
    /* names longer than 64 characters are rejected by ncrypt itself */
    for (int len = 65; len <= 99; len += 17) {
        for (int i = 0; i < len; i++) { n[i] = L'a'; }
        n[len] = 0;
        SECURITY_STATUS r = U(NCryptSetProperty)(x.k, n, (PBYTE)&v, 4, 0);
        CHECKF(r == G2_NTE_INVALID_PARAM, "len %d -> 0x%08lx", len, (unsigned long)r);
    }
    /* 64 characters pass the length check and reach the provider */
    for (int i = 0; i < 64; i++) { n[i] = L'a'; }
    n[64] = 0;
    SECURITY_STATUS r = U(NCryptSetProperty)(x.k, n, (PBYTE)&v, 4, 0);
    t_note("unknown 64-char property -> 0x%08lx (provider decides)", (unsigned long)r);
    CHECK(r != 0);
    rel(&x);
}
TEST(gap2_setprop_security_descriptor_validation) {
    REQUIRE(U(NCryptSetProperty));
    kp_t x; if (!mk(&x, NCRYPT_ECDSA_P256_ALGORITHM, 0)) return;
    BYTE bad[64]; memset(bad, 0, sizeof bad);
    /* an all-zero buffer is not a valid security descriptor (revision 0) */
    G2_EQ(U(NCryptSetProperty)(x.k, L"Security Descr", bad, sizeof bad, 0), G2_NTE_BAD_DATA);
    G2_EQ(U(NCryptSetProperty)(x.k, L"Security Descr", bad, 0, 0), G2_NTE_BAD_DATA);
    /* valid descriptor but declared buffer shorter than its length */
    SECURITY_DESCRIPTOR sd;
    if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        DWORD len = GetSecurityDescriptorLength(&sd);
        G2_EQ(U(NCryptSetProperty)(x.k, L"Security Descr", (PBYTE)&sd, len - 1, 0), G2_NTE_BAD_DATA);
    }
    rel(&x);
}
TEST(gap2_setprop_ui_policy_validation) {
    REQUIRE(U(NCryptSetProperty));
    kp_t x; if (!mk(&x, NCRYPT_ECDSA_P256_ALGORITHM, 0)) return;
    DWORD buf[16]; memset(buf, 0, sizeof buf);
    /* NCRYPT_UI_POLICY_PROPERTY: buffer must be at least 0x20 bytes and dwVersion must be 1 */
    buf[0] = 1;
    G2_EQ(U(NCryptSetProperty)(x.k, L"UI Policy", (PBYTE)buf, 0x1f, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(U(NCryptSetProperty)(x.k, L"UI Policy", (PBYTE)buf, 0, 0), G2_NTE_INVALID_PARAM);
    buf[0] = 0;
    G2_EQ(U(NCryptSetProperty)(x.k, L"UI Policy", (PBYTE)buf, sizeof buf, 0), G2_NTE_INVALID_PARAM);
    buf[0] = 2;
    G2_EQ(U(NCryptSetProperty)(x.k, L"UI Policy", (PBYTE)buf, sizeof buf, 0), G2_NTE_INVALID_PARAM);
    buf[0] = 0xFFFFFFFF;
    G2_EQ(U(NCryptSetProperty)(x.k, L"UI Policy", (PBYTE)buf, sizeof buf, 0), G2_NTE_INVALID_PARAM);
    rel(&x);
}
TEST(gap2_setprop_export_policy) {
    REQUIRE(U(NCryptSetProperty)); REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptExportKey));
    if (t_is_wine()) { t_skip("needs real CNG"); return; }
    NCRYPT_PROV_HANDLE p = g2_ksp(); if (!p) { t_skip("no KSP"); return; }
    NCRYPT_KEY_HANDLE k = 0;
    G2_EQ(U(NCryptCreatePersistedKey)(p, &k, NCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0), 0);
    if (k) {
        DWORD pol = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        G2_EQ(U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, 4, 0), 0);
        G2_EQ(U(NCryptFinalizeKey)(k, 0), 0);
        DWORD cb = 0;
        G2_EQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cb, 0), 0);
        CHECK(cb >= 8 + 96);   /* header + X,Y,d for P-256 */
        U(NCryptFreeObject)(k);
    }
    /* a key whose export policy was never set cannot be exported in plaintext */
    k = g2_key(p, NCRYPT_ECDSA_P256_ALGORITHM, 0);
    if (k) {
        DWORD cb = 0;
        SECURITY_STATUS r = U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cb, 0);
        CHECK(r != 0);
        t_note("export private blob of default-policy key -> 0x%08lx", (unsigned long)r);
        U(NCryptFreeObject)(k);
    }
    U(NCryptFreeObject)(p);
}
TEST(gap2_setprop_on_provider_handle) {
    REQUIRE(U(NCryptSetProperty));
    if (t_is_wine()) { t_skip("needs real CNG"); return; }
    NCRYPT_PROV_HANDLE p = g2_ksp(); if (!p) { t_skip("no KSP"); return; }
    DWORD v = 1;
    /* provider handles are accepted by the handle check; NULL property is still invalid */
    G2_EQ(U(NCryptSetProperty)(p, NULL, (PBYTE)&v, 4, 0), G2_NTE_INVALID_PARAM);
    SECURITY_STATUS r = U(NCryptSetProperty)(p, L"NoSuchProviderProperty", (PBYTE)&v, 4, 0);
    CHECK(r != 0); t_note("provider unknown property -> 0x%08lx", (unsigned long)r);
    U(NCryptFreeObject)(p);
}

/* ---------------- NCryptSecretAgreement with real keys ---------------- */
static NCRYPT_SECRET_HANDLE agree(NCRYPT_KEY_HANDLE priv, NCRYPT_KEY_HANDLE pub, SECURITY_STATUS *rr) {
    NCRYPT_SECRET_HANDLE s = 0;
    *rr = U(NCryptSecretAgreement)(priv, pub, &s, 0);
    return s;
}
static DWORD derive(NCRYPT_SECRET_HANDLE s, BYTE *out, DWORD cap, SECURITY_STATUS *rr) {
    static WCHAR alg[] = L"SHA256";
    BCryptBuffer b = { sizeof alg, 0 /* KDF_HASH_ALGORITHM */, alg };
    BCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 1, &b };
    DWORD cb = 0;
    *rr = U(NCryptDeriveKey)(s, BCRYPT_KDF_HASH, &d, out, cap, &cb, 0);
    return cb;
}
TEST(gap2_secret_agreement_ecdh_symmetry) {
    REQUIRE(U(NCryptSecretAgreement)); REQUIRE(U(NCryptDeriveKey));
    kp_t a, b; if (!mk(&a, NCRYPT_ECDH_P256_ALGORITHM, 0)) return;
    if (!mk(&b, NCRYPT_ECDH_P256_ALGORITHM, 0)) { rel(&a); return; }
    SECURITY_STATUS r1, r2, r3;
    NCRYPT_SECRET_HANDLE s1 = agree(a.k, b.k, &r1), s2 = agree(b.k, a.k, &r2);
    G2_EQ(r1, 0); G2_EQ(r2, 0);
    CHECK(s1 != 0 && s2 != 0 && s1 != s2);
    BYTE d1[32] = {0}, d2[32] = {0};
    DWORD c1 = derive(s1, d1, 32, &r1), c2 = derive(s2, d2, 32, &r2);
    G2_EQ(r1, 0); G2_EQ(r2, 0);
    EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
    CHECK(!memcmp(d1, d2, 32));      /* both sides derive the same key material */
    BYTE zero[32] = {0}; CHECK(memcmp(d1, zero, 32) != 0);
    /* a third party gets a different secret */
    kp_t c; if (mk(&c, NCRYPT_ECDH_P256_ALGORITHM, 0)) {
        NCRYPT_SECRET_HANDLE s3 = agree(c.k, b.k, &r3); G2_EQ(r3, 0);
        BYTE d3[32]; derive(s3, d3, 32, &r3); G2_EQ(r3, 0);
        CHECK(memcmp(d1, d3, 32) != 0);
        G2_EQ(U(NCryptFreeObject)(s3), 0);
        rel(&c);
    }
    /* repeating the agreement yields a distinct handle but the same value */
    NCRYPT_SECRET_HANDLE s4 = agree(a.k, b.k, &r1); G2_EQ(r1, 0);
    CHECK(s4 != s1);
    BYTE d4[32]; derive(s4, d4, 32, &r1); CHECK(!memcmp(d1, d4, 32));
    G2_EQ(U(NCryptFreeObject)(s4), 0);
    G2_EQ(U(NCryptFreeObject)(s1), 0);
    G2_EQ(U(NCryptFreeObject)(s2), 0);
    rel(&a); rel(&b);
}
TEST(gap2_secret_agreement_self) {
    REQUIRE(U(NCryptSecretAgreement));
    kp_t a; if (!mk(&a, NCRYPT_ECDH_P256_ALGORITHM, 0)) return;
    SECURITY_STATUS r; NCRYPT_SECRET_HANDLE s = agree(a.k, a.k, &r);
    t_note("agreement of a key with itself -> 0x%08lx", (unsigned long)r);
    if (r == 0) { CHECK(s != 0); U(NCryptFreeObject)(s); }
    rel(&a);
}
TEST(gap2_secret_agreement_curve_mismatch_and_rsa) {
    REQUIRE(U(NCryptSecretAgreement));
    kp_t a, b; if (!mk(&a, NCRYPT_ECDH_P256_ALGORITHM, 0)) return;
    if (!mk(&b, NCRYPT_ECDH_P384_ALGORITHM, 0)) { rel(&a); return; }
    NCRYPT_SECRET_HANDLE s = 0x1357;
    SECURITY_STATUS r = U(NCryptSecretAgreement)(a.k, b.k, &s, 0);
    CHECK(r != 0); t_note("P-256 x P-384 agreement -> 0x%08lx", (unsigned long)r);
    EXPECT_EQ(s, 0x1357);       /* output handle untouched on failure */
    kp_t c; if (mk(&c, NCRYPT_RSA_ALGORITHM, 1024)) {
        s = 0x1357;
        r = U(NCryptSecretAgreement)(c.k, c.k, &s, 0);
        CHECK(r != 0); t_note("RSA x RSA agreement -> 0x%08lx", (unsigned long)r);
        EXPECT_EQ(s, 0x1357);
        r = U(NCryptSecretAgreement)(a.k, c.k, &s, 0);
        CHECK(r != 0); EXPECT_EQ(s, 0x1357);
        rel(&c);
    }
    rel(&a); rel(&b);
}
TEST(gap2_secret_agreement_bad_flags) {
    REQUIRE(U(NCryptSecretAgreement));
    kp_t a, b; if (!mk(&a, NCRYPT_ECDH_P256_ALGORITHM, 0)) return;
    if (!mk(&b, NCRYPT_ECDH_P256_ALGORITHM, 0)) { rel(&a); return; }
    static const DWORD f[] = { 1, 2, 0x100, 0x80000000u };
    for (unsigned i = 0; i < 4; i++) {
        NCRYPT_SECRET_HANDLE s = 0x42;
        SECURITY_STATUS r = U(NCryptSecretAgreement)(a.k, b.k, &s, f[i]);
        t_note("agreement flags 0x%lx -> 0x%08lx", (unsigned long)f[i], (unsigned long)r);
        if (r != 0) EXPECT_EQ(s, 0x42); else U(NCryptFreeObject)(s);
    }
    rel(&a); rel(&b);
}
TEST(gap2_secret_handle_is_not_a_key) {
    REQUIRE(U(NCryptSecretAgreement)); REQUIRE(U(NCryptSignHash));
    kp_t a, b; if (!mk(&a, NCRYPT_ECDH_P256_ALGORITHM, 0)) return;
    if (!mk(&b, NCRYPT_ECDH_P256_ALGORITHM, 0)) { rel(&a); return; }
    SECURITY_STATUS r; NCRYPT_SECRET_HANDLE s = agree(a.k, b.k, &r);
    if (r == 0) {
        /* secret handles carry magic 0x44440003, so key-only APIs reject them */
        BYTE sig[64]; DWORD cb = 0;
        G2_EQ(U(NCryptSignHash)(s, NULL, (PBYTE)HASH32, 32, sig, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
        G2_EQ(U(NCryptVerifySignature)(s, NULL, (PBYTE)HASH32, 32, sig, 64, 0), G2_NTE_INVALID_HANDLE);
        NCRYPT_SECRET_HANDLE s2 = 0;
        G2_EQ(U(NCryptSecretAgreement)(s, b.k, &s2, 0), G2_NTE_INVALID_HANDLE);
        G2_EQ(U(NCryptSecretAgreement)(a.k, s, &s2, 0), G2_NTE_INVALID_HANDLE);
        DWORD v = 1;
        G2_EQ(U(NCryptSetProperty)(s, NCRYPT_LENGTH_PROPERTY, (PBYTE)&v, 4, 0), G2_NTE_INVALID_HANDLE);
        U(NCryptFreeObject)(s);
    }
    rel(&a); rel(&b);
}
/* ---------------- key-handle-only API cross checks ---------------- */
TEST(gap2_provider_handle_is_not_a_key) {
    REQUIRE(U(NCryptSignHash));
    if (t_is_wine()) { t_skip("needs real CNG"); return; }
    NCRYPT_PROV_HANDLE p = g2_ksp(); if (!p) { t_skip("no KSP"); return; }
    BYTE sig[64]; DWORD cb = 0;
    G2_EQ(U(NCryptSignHash)(p, NULL, (PBYTE)HASH32, 32, sig, 64, &cb, 0), G2_NTE_INVALID_HANDLE);
    G2_EQ(U(NCryptVerifySignature)(p, NULL, (PBYTE)HASH32, 32, sig, 64, 0), G2_NTE_INVALID_HANDLE);
    NCRYPT_SECRET_HANDLE s = 0;
    G2_EQ(U(NCryptSecretAgreement)(p, p, &s, 0), G2_NTE_INVALID_HANDLE);
    NCryptBufferDesc out; memset(&out, 0, sizeof out);
    G2_EQ(U(NCryptVerifyClaim)(p, 0, 1, NULL, NULL, 0, &out, 0), G2_NTE_INVALID_HANDLE);
    U(NCryptFreeObject)(p);
}
