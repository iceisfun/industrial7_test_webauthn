/* BCryptSetProperty and BCryptSecretAgreement: argument validation order, handle-type checks,
 * status values and functional ECDH agreement through the public export surface. */
#include "gap1.h"

#define SENT_H ((BCRYPT_SECRET_HANDLE)(ULONG_PTR)0x1234)

static BCRYPT_ALG_HANDLE open_alg(LPCWSTR id, ULONG flags) {
    BCRYPT_ALG_HANDLE h = NULL;
    if (!B(BCryptOpenAlgorithmProvider) || B(BCryptOpenAlgorithmProvider)(&h, id, NULL, flags) != 0) return NULL;
    return h;
}
static void close_alg(BCRYPT_ALG_HANDLE h) { if (h) B(BCryptCloseAlgorithmProvider)(h, 0); }

/* ---- BCryptSetProperty ---------------------------------------------------------------------- */
TEST(gap1_setprop_null_property) {
    REQUIRE(B(BCryptSetProperty)); REQUIRE(B(BCryptOpenAlgorithmProvider));
    /* the property name is validated before the handle */
    EXPECT_EQ((DWORD)B(BCryptSetProperty)(NULL, NULL, NULL, 0, 0), G_ST_INVALID_PARAMETER);
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    EXPECT_EQ((DWORD)B(BCryptSetProperty)(a, NULL, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof BCRYPT_CHAIN_MODE_CBC, 0), G_ST_INVALID_PARAMETER);
    close_alg(a);
}

TEST(gap1_setprop_null_handle) {
    REQUIRE(B(BCryptSetProperty));
    EXPECT_EQ((DWORD)B(BCryptSetProperty)(NULL, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof BCRYPT_CHAIN_MODE_CBC, 0), G_ST_INVALID_HANDLE);
}

TEST(gap1_setprop_bad_pseudo_handle_index) {
    REQUIRE(B(BCryptSetProperty));
    /* low nibble 1 marks a pseudo handle; indices beyond the table are invalid handles */
    static const ULONG_PTR hs[] = { 0xFFF1, 0x1001, 0x7FFFFFF1 };
    for (size_t i = 0; i < sizeof hs / sizeof *hs; i++)
        EXPECT_EQ((DWORD)B(BCryptSetProperty)((BCRYPT_HANDLE)hs[i], BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof BCRYPT_CHAIN_MODE_CBC, 0), G_ST_INVALID_HANDLE);
}

TEST(gap1_setprop_aes_chaining_modes) {
    REQUIRE(B(BCryptSetProperty)); REQUIRE(B(BCryptGetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    static const WCHAR *modes[] = { BCRYPT_CHAIN_MODE_ECB, BCRYPT_CHAIN_MODE_CBC, BCRYPT_CHAIN_MODE_CFB, BCRYPT_CHAIN_MODE_GCM, BCRYPT_CHAIN_MODE_CCM };
    for (size_t i = 0; i < sizeof modes / sizeof *modes; i++) {
        NTSTATUS st = B(BCryptSetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)modes[i], (lstrlenW(modes[i]) + 1) * 2, 0);
        CHECKF(st == 0, "set %ls -> 0x%08lx", modes[i], (unsigned long)st);
        WCHAR buf[64] = { 0 }; ULONG cb = 0;
        st = B(BCryptGetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)buf, sizeof buf, &cb, 0);
        CHECKF(st == 0, "get -> 0x%08lx", (unsigned long)st);
        if (st == 0) { EXPECT_WSTR(buf, modes[i]); CHECKF(cb >= (ULONG)((lstrlenW(modes[i]) + 1) * 2), "cb %lu", (unsigned long)cb); t_note("chaining mode %ls reads back with cb=%lu (Windows 10 reports the fixed 64-byte property size)", modes[i], (unsigned long)cb); }
    }
    close_alg(a);
}

TEST(gap1_setprop_aes_default_is_cbc) {
    REQUIRE(B(BCryptGetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    WCHAR buf[64] = { 0 }; ULONG cb = 0;
    EXPECT_EQ((DWORD)B(BCryptGetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)buf, sizeof buf, &cb, 0), 0);
    EXPECT_WSTR(buf, BCRYPT_CHAIN_MODE_CBC);
    close_alg(a);
}

TEST(gap1_setprop_invalid_chaining_mode) {
    REQUIRE(B(BCryptSetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    static const WCHAR bad[] = L"ChainingModeXYZ";
    NTSTATUS st = B(BCryptSetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)bad, sizeof bad, 0);
    CHECKF(G_NT_FAIL(st), "st=0x%08lx", (unsigned long)st);
    t_note("SetProperty(ChainingMode=XYZ) -> 0x%08lx", (unsigned long)st);
    /* a failed set leaves the previous mode intact */
    WCHAR buf[64] = { 0 }; ULONG cb = 0;
    EXPECT_EQ((DWORD)B(BCryptGetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)buf, sizeof buf, &cb, 0), 0);
    EXPECT_WSTR(buf, BCRYPT_CHAIN_MODE_CBC);
    close_alg(a);
}

TEST(gap1_setprop_unknown_property) {
    REQUIRE(B(BCryptSetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    DWORD v = 1;
    NTSTATUS st = B(BCryptSetProperty)(a, L"gap1NoSuchProperty", (PUCHAR)&v, sizeof v, 0);
    CHECKF(G_NT_FAIL(st), "st=0x%08lx", (unsigned long)st);
    t_note("SetProperty(unknown property) -> 0x%08lx", (unsigned long)st);
    close_alg(a);
}

TEST(gap1_setprop_readonly_property) {
    REQUIRE(B(BCryptSetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    DWORD v = 32;
    NTSTATUS st = B(BCryptSetProperty)(a, BCRYPT_BLOCK_LENGTH, (PUCHAR)&v, sizeof v, 0);
    CHECKF(G_NT_FAIL(st), "BlockLength is read only; st=0x%08lx", (unsigned long)st);
    t_note("SetProperty(BlockLength) -> 0x%08lx", (unsigned long)st);
    close_alg(a);
}

TEST(gap1_setprop_hash_alg_chaining_mode) {
    REQUIRE(B(BCryptSetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_SHA256_ALGORITHM, 0);
    if (!a) { t_skip("SHA256 provider unavailable"); return; }
    NTSTATUS st = B(BCryptSetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof BCRYPT_CHAIN_MODE_CBC, 0);
    CHECKF(G_NT_FAIL(st), "hash algorithms have no chaining mode; st=0x%08lx", (unsigned long)st);
    t_note("SetProperty(SHA256, ChainingMode) -> 0x%08lx", (unsigned long)st);
    close_alg(a);
}

TEST(gap1_setprop_null_input) {
    REQUIRE(B(BCryptSetProperty));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    NTSTATUS st = B(BCryptSetProperty)(a, BCRYPT_CHAINING_MODE, NULL, 0, 0);
    CHECKF(G_NT_FAIL(st), "st=0x%08lx", (unsigned long)st);
    t_note("SetProperty(ChainingMode, NULL, 0) -> 0x%08lx", (unsigned long)st);
    close_alg(a);
}

TEST(gap1_setprop_on_key_handle) {
    REQUIRE(B(BCryptSetProperty)); REQUIRE(B(BCryptGenerateSymmetricKey)); REQUIRE(B(BCryptDestroyKey));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    UCHAR secret[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
    BCRYPT_KEY_HANDLE k = NULL;
    EXPECT_EQ((DWORD)B(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, sizeof secret, 0), 0);
    if (k) {
        NTSTATUS st = B(BCryptSetProperty)(k, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof BCRYPT_CHAIN_MODE_GCM, 0);
        EXPECT_EQ((DWORD)st, 0);
        WCHAR buf[64] = { 0 }; ULONG cb = 0;
        EXPECT_EQ((DWORD)B(BCryptGetProperty)(k, BCRYPT_CHAINING_MODE, (PUCHAR)buf, sizeof buf, &cb, 0), 0);
        EXPECT_WSTR(buf, BCRYPT_CHAIN_MODE_GCM);
        /* the key's mode does not leak back to the algorithm handle */
        EXPECT_EQ((DWORD)B(BCryptGetProperty)(a, BCRYPT_CHAINING_MODE, (PUCHAR)buf, sizeof buf, &cb, 0), 0);
        EXPECT_WSTR(buf, BCRYPT_CHAIN_MODE_CBC);
        B(BCryptDestroyKey)(k);
    }
    close_alg(a);
}

TEST(gap1_setprop_key_null_property_checked_first) {
    REQUIRE(B(BCryptSetProperty)); REQUIRE(B(BCryptGenerateSymmetricKey)); REQUIRE(B(BCryptDestroyKey));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES provider unavailable"); return; }
    UCHAR secret[16] = { 0 };
    BCRYPT_KEY_HANDLE k = NULL;
    if (B(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, sizeof secret, 0) == 0) {
        EXPECT_EQ((DWORD)B(BCryptSetProperty)(k, NULL, NULL, 0, 0), G_ST_INVALID_PARAMETER);
        B(BCryptDestroyKey)(k);
    }
    close_alg(a);
}

/* ---- BCryptSecretAgreement ------------------------------------------------------------------ */
typedef struct { BCRYPT_ALG_HANDLE alg; BCRYPT_KEY_HANDLE a, b; } ecdh_pair;

static int ecdh_make(ecdh_pair *p, LPCWSTR alg, ULONG bits) {
    memset(p, 0, sizeof *p);
    p->alg = open_alg(alg, 0);
    if (!p->alg) return 0;
    if (B(BCryptGenerateKeyPair)(p->alg, &p->a, bits, 0) != 0 || B(BCryptFinalizeKeyPair)(p->a, 0) != 0) return 0;
    if (B(BCryptGenerateKeyPair)(p->alg, &p->b, bits, 0) != 0 || B(BCryptFinalizeKeyPair)(p->b, 0) != 0) return 0;
    return 1;
}
static void ecdh_free(ecdh_pair *p) {
    if (p->a) B(BCryptDestroyKey)(p->a);
    if (p->b) B(BCryptDestroyKey)(p->b);
    close_alg(p->alg);
}
#define NEED_PAIR(p) ecdh_pair p; if (!B(BCryptGenerateKeyPair) || !ecdh_make(&p, BCRYPT_ECDH_P256_ALGORITHM, 256)) { ecdh_free(&p); t_skip("ECDH_P256 unavailable"); return; }

TEST(gap1_sa_null_handles) {
    REQUIRE(B(BCryptSecretAgreement));
    BCRYPT_SECRET_HANDLE s = SENT_H;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(NULL, NULL, &s, 0), G_ST_INVALID_HANDLE);
    EXPECT_EQ(s, SENT_H);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(NULL, NULL, NULL, 0), G_ST_INVALID_HANDLE);   /* handles before the out pointer */
}

TEST(gap1_sa_one_null_handle) {
    REQUIRE(B(BCryptSecretAgreement));
    NEED_PAIR(p);
    BCRYPT_SECRET_HANDLE s = SENT_H;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(NULL, p.b, &s, 0), G_ST_INVALID_HANDLE);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, NULL, &s, 0), G_ST_INVALID_HANDLE);
    EXPECT_EQ(s, SENT_H);
    ecdh_free(&p);
}

TEST(gap1_sa_null_out_pointer) {
    REQUIRE(B(BCryptSecretAgreement));
    NEED_PAIR(p);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, NULL, 0), G_ST_INVALID_PARAMETER);
    ecdh_free(&p);
}

TEST(gap1_sa_algorithm_handle_is_not_a_key) {
    REQUIRE(B(BCryptSecretAgreement));
    NEED_PAIR(p);
    BCRYPT_SECRET_HANDLE s = SENT_H;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.alg, p.b, &s, 0), G_ST_INVALID_HANDLE);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.alg, &s, 0), G_ST_INVALID_HANDLE);
    EXPECT_EQ(s, SENT_H);
    ecdh_free(&p);
}

TEST(gap1_sa_non_agreement_algorithm) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptGenerateKeyPair));
    /* RSA and ECDSA keys belong to the asymmetric-encryption / signature interfaces: not supported */
    static const struct { LPCWSTR alg; ULONG bits; } t[] = { { BCRYPT_RSA_ALGORITHM, 1024 }, { BCRYPT_ECDSA_P256_ALGORITHM, 256 } };
    for (size_t i = 0; i < 2; i++) {
        BCRYPT_ALG_HANDLE a = open_alg(t[i].alg, 0);
        BCRYPT_KEY_HANDLE k = NULL;
        if (!a || B(BCryptGenerateKeyPair)(a, &k, t[i].bits, 0) != 0 || B(BCryptFinalizeKeyPair)(k, 0) != 0) {
            t_note("%ls key generation unavailable", t[i].alg); if (k) B(BCryptDestroyKey)(k); close_alg(a); continue;
        }
        BCRYPT_SECRET_HANDLE s = SENT_H;
        NTSTATUS st = B(BCryptSecretAgreement)(k, k, &s, 0);
        CHECKF((DWORD)st == G_ST_NOT_SUPPORTED, "%ls st=0x%08lx", t[i].alg, (unsigned long)st);
        EXPECT_EQ(s, SENT_H);
        B(BCryptDestroyKey)(k);
        close_alg(a);
    }
}

TEST(gap1_sa_symmetric_key_rejected) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptGenerateSymmetricKey));
    BCRYPT_ALG_HANDLE a = open_alg(BCRYPT_AES_ALGORITHM, 0);
    if (!a) { t_skip("AES unavailable"); return; }
    UCHAR sec[16] = { 7 };
    BCRYPT_KEY_HANDLE k = NULL;
    if (B(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, sec, sizeof sec, 0) == 0) {
        BCRYPT_SECRET_HANDLE s = SENT_H;
        NTSTATUS st = B(BCryptSecretAgreement)(k, k, &s, 0);
        EXPECT_EQ((DWORD)st, G_ST_NOT_SUPPORTED);
        EXPECT_EQ(s, SENT_H);
        B(BCryptDestroyKey)(k);
    }
    close_alg(a);
}

static NTSTATUS derive_raw(BCRYPT_SECRET_HANDLE s, UCHAR *out, ULONG cap, ULONG *cb) {
    return B(BCryptDeriveKey)(s, BCRYPT_KDF_RAW_SECRET, NULL, out, cap, cb, 0);
}

TEST(gap1_sa_ecdh_p256_symmetric_result) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    NEED_PAIR(p);
    BCRYPT_SECRET_HANDLE s1 = NULL, s2 = NULL;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, &s1, 0), 0);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.b, p.a, &s2, 0), 0);
    CHECK(s1 != NULL && s2 != NULL && s1 != s2);
    if (s1 && s2) {
        UCHAR r1[32] = { 0 }, r2[32] = { 0 }; ULONG c1 = 0, c2 = 0;
        EXPECT_EQ((DWORD)derive_raw(s1, r1, sizeof r1, &c1), 0);
        EXPECT_EQ((DWORD)derive_raw(s2, r2, sizeof r2, &c2), 0);
        EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
        CHECK(!memcmp(r1, r2, 32));
        static const UCHAR zero[32] = { 0 };
        CHECK(memcmp(r1, zero, 32) != 0);
    }
    if (s1) B(BCryptDestroySecret)(s1);
    if (s2) B(BCryptDestroySecret)(s2);
    ecdh_free(&p);
}

TEST(gap1_sa_different_peers_differ) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    NEED_PAIR(p);
    BCRYPT_KEY_HANDLE c = NULL;
    if (B(BCryptGenerateKeyPair)(p.alg, &c, 256, 0) != 0 || B(BCryptFinalizeKeyPair)(c, 0) != 0) { if (c) B(BCryptDestroyKey)(c); ecdh_free(&p); t_skip("keygen"); return; }
    BCRYPT_SECRET_HANDLE sab = NULL, sac = NULL;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, &sab, 0), 0);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, c, &sac, 0), 0);
    if (sab && sac) {
        UCHAR x[32], y[32]; ULONG cx = 0, cy = 0;
        EXPECT_EQ((DWORD)derive_raw(sab, x, 32, &cx), 0);
        EXPECT_EQ((DWORD)derive_raw(sac, y, 32, &cy), 0);
        CHECK(memcmp(x, y, 32) != 0);
    }
    if (sab) B(BCryptDestroySecret)(sab);
    if (sac) B(BCryptDestroySecret)(sac);
    B(BCryptDestroyKey)(c);
    ecdh_free(&p);
}

TEST(gap1_sa_public_only_peer) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptExportKey)); REQUIRE(B(BCryptImportKeyPair)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    NEED_PAIR(p);
    UCHAR blob[256]; ULONG cb = 0;
    EXPECT_EQ((DWORD)B(BCryptExportKey)(p.b, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &cb, 0), 0);
    EXPECT_EQ(cb, 72);                                   /* BCRYPT_ECCKEY_BLOB (8) + X (32) + Y (32) */
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
    EXPECT_EQ(hdr->dwMagic, G_ECDH_PUB_P256);
    EXPECT_EQ(hdr->cbKey, 32);
    BCRYPT_KEY_HANDLE pub = NULL;
    EXPECT_EQ((DWORD)B(BCryptImportKeyPair)(p.alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &pub, blob, cb, 0), 0);
    if (pub) {
        BCRYPT_SECRET_HANDLE s1 = NULL, s2 = NULL;
        EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, pub, &s1, 0), 0);
        EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, &s2, 0), 0);
        if (s1 && s2) {
            UCHAR x[32], y[32]; ULONG cx = 0, cy = 0;
            EXPECT_EQ((DWORD)derive_raw(s1, x, 32, &cx), 0);
            EXPECT_EQ((DWORD)derive_raw(s2, y, 32, &cy), 0);
            CHECK(!memcmp(x, y, 32));
        }
        if (s1) B(BCryptDestroySecret)(s1);
        if (s2) B(BCryptDestroySecret)(s2);
        B(BCryptDestroyKey)(pub);
    }
    ecdh_free(&p);
}

TEST(gap1_sa_secret_outlives_keys) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    NEED_PAIR(p);
    BCRYPT_SECRET_HANDLE s = NULL;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, &s, 0), 0);
    if (s) {
        UCHAR before[32], after[32]; ULONG c1 = 0, c2 = 0;
        EXPECT_EQ((DWORD)derive_raw(s, before, 32, &c1), 0);
        B(BCryptDestroyKey)(p.a); p.a = NULL;
        B(BCryptDestroyKey)(p.b); p.b = NULL;
        close_alg(p.alg); p.alg = NULL;
        EXPECT_EQ((DWORD)derive_raw(s, after, 32, &c2), 0);
        CHECK(!memcmp(before, after, 32));
        B(BCryptDestroySecret)(s);
    }
    ecdh_free(&p);
}

TEST(gap1_sa_derive_hash_kdf) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    NEED_PAIR(p);
    BCRYPT_SECRET_HANDLE s1 = NULL, s2 = NULL;
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.a, p.b, &s1, 0), 0);
    EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(p.b, p.a, &s2, 0), 0);
    if (s1 && s2) {
        BCryptBuffer b = { (ULONG)sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, (PVOID)BCRYPT_SHA256_ALGORITHM };
        BCryptBufferDesc d = { BCRYPTBUFFER_VERSION, 1, &b };
        UCHAR k1[32] = { 0 }, k2[32] = { 0 }; ULONG c1 = 0, c2 = 0;
        EXPECT_EQ((DWORD)B(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &d, NULL, 0, &c1, 0), 0);      /* size query */
        EXPECT_EQ(c1, 32);
        EXPECT_EQ((DWORD)B(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &d, k1, sizeof k1, &c1, 0), 0);
        EXPECT_EQ((DWORD)B(BCryptDeriveKey)(s2, BCRYPT_KDF_HASH, &d, k2, sizeof k2, &c2, 0), 0);
        EXPECT_EQ(c1, 32); EXPECT_EQ(c2, 32);
        CHECK(!memcmp(k1, k2, 32));
        UCHAR raw[32]; ULONG cr = 0;
        EXPECT_EQ((DWORD)derive_raw(s1, raw, 32, &cr), 0);
        CHECK(memcmp(raw, k1, 32) != 0);                           /* hashed secret differs from the raw secret */
        UCHAR small[16]; ULONG cs = 0;
        NTSTATUS st = B(BCryptDeriveKey)(s1, BCRYPT_KDF_HASH, &d, small, sizeof small, &cs, 0);
        CHECKF(G_NT_FAIL(st) || cs <= sizeof small, "small buffer: st=0x%08lx cb=%lu", (unsigned long)st, (unsigned long)cs);
        t_note("DeriveKey(HASH/SHA256, 16-byte buffer) -> 0x%08lx cb=%lu", (unsigned long)st, (unsigned long)cs);
    }
    if (s1) B(BCryptDestroySecret)(s1);
    if (s2) B(BCryptDestroySecret)(s2);
    ecdh_free(&p);
}

TEST(gap1_sa_curve_mismatch) {
    REQUIRE(B(BCryptSecretAgreement));
    NEED_PAIR(p);
    ecdh_pair q;
    if (!ecdh_make(&q, BCRYPT_ECDH_P384_ALGORITHM, 384)) { ecdh_free(&q); ecdh_free(&p); t_skip("ECDH_P384 unavailable"); return; }
    BCRYPT_SECRET_HANDLE s = SENT_H;
    NTSTATUS st = B(BCryptSecretAgreement)(p.a, q.a, &s, 0);
    CHECKF(G_NT_FAIL(st), "P256 private with P384 public; st=0x%08lx", (unsigned long)st);
    t_note("SecretAgreement(P256 priv, P384 pub) -> 0x%08lx", (unsigned long)st);
    if (!G_NT_FAIL(st) && s != SENT_H) B(BCryptDestroySecret)(s);
    ecdh_free(&q); ecdh_free(&p);
}

TEST(gap1_sa_p384_and_p521) {
    REQUIRE(B(BCryptSecretAgreement)); REQUIRE(B(BCryptDeriveKey)); REQUIRE(B(BCryptDestroySecret));
    static const struct { LPCWSTR alg; ULONG bits, bytes; } t[] = { { BCRYPT_ECDH_P384_ALGORITHM, 384, 48 }, { BCRYPT_ECDH_P521_ALGORITHM, 521, 66 } };
    for (size_t i = 0; i < 2; i++) {
        ecdh_pair q;
        if (!ecdh_make(&q, t[i].alg, t[i].bits)) { ecdh_free(&q); t_note("%ls unavailable", t[i].alg); continue; }
        BCRYPT_SECRET_HANDLE s1 = NULL, s2 = NULL;
        EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(q.a, q.b, &s1, 0), 0);
        EXPECT_EQ((DWORD)B(BCryptSecretAgreement)(q.b, q.a, &s2, 0), 0);
        if (s1 && s2) {
            UCHAR x[80] = { 0 }, y[80] = { 0 }; ULONG cx = 0, cy = 0;
            EXPECT_EQ((DWORD)derive_raw(s1, x, sizeof x, &cx), 0);
            EXPECT_EQ((DWORD)derive_raw(s2, y, sizeof y, &cy), 0);
            EXPECT_EQ(cx, t[i].bytes); EXPECT_EQ(cy, t[i].bytes);
            CHECK(cx == cy && !memcmp(x, y, cx));
        }
        if (s1) B(BCryptDestroySecret)(s1);
        if (s2) B(BCryptDestroySecret)(s2);
        ecdh_free(&q);
    }
}
