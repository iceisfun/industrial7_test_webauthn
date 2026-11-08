#include "gap4.h"
/* BCryptOpenAlgorithmProvider / BCryptCloseAlgorithmProvider */

#define OPEN_REQ() BCRYPT_ALG_HANDLE h; do { if (!BC(BCryptOpenAlgorithmProvider)) { t_skip("missing export: BCryptOpenAlgorithmProvider"); return; } } while (0)

TEST(gap4_open_null_phalgorithm) {
    OPEN_REQ(); (void)h;
    EQC(BC(BCryptOpenAlgorithmProvider)(NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0), G4_INVALID_PARAM);
}
TEST(gap4_open_null_algid) {
    OPEN_REQ();
    h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
    EQC(BC(BCryptOpenAlgorithmProvider)(&h, NULL, NULL, 0), G4_INVALID_PARAM);
    /* early parameter rejection does not write the output */
    EXPECT_EQ(h, 0x1234);
}
TEST(gap4_open_both_null) {
    OPEN_REQ(); (void)h;
    EQC(BC(BCryptOpenAlgorithmProvider)(NULL, NULL, NULL, 0), G4_INVALID_PARAM);
}
TEST(gap4_open_flag_bit0_rejected) {
    OPEN_REQ();
    h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
    EQC(BC(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, NULL, 1), G4_INVALID_PARAM);
    EXPECT_EQ(h, 0x1234);
}
TEST(gap4_open_flag_bit0_with_other_bits_rejected) {
    OPEN_REQ();
    h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x1234;
    EQC(BC(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0x9), G4_INVALID_PARAM);
    EQC(BC(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, NULL, 0xFFFFFFFF), G4_INVALID_PARAM);
    EXPECT_EQ(h, 0x1234);
}
TEST(gap4_open_unknown_algorithm_not_found) {
    OPEN_REQ();
    h = NULL;
    NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, L"NoSuchAlgorithm_gap4", NULL, 0);
    EXPECT_EQ(s, G4_NOT_FOUND);
    if (s == 0) g4_close(h);
}
TEST(gap4_open_unknown_algorithm_variants) {
    OPEN_REQ();
    static const wchar_t *bad[] = { L"SHA-256", L"SHA2", L"AES256", L"RSA_", L"X", L"SHA256 ", L" SHA256", L"ECDSA_P257" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        h = NULL;
        NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, bad[i], NULL, 0);
        t_check(s == G4_NOT_FOUND, __FILE__, __LINE__, "unknown alg -> STATUS_NOT_FOUND", "alg %ls got 0x%lx", bad[i], (unsigned long)s);
        if (s == 0) g4_close(h);
    }
}
TEST(gap4_open_unknown_implementation_fails) {
    OPEN_REQ();
    h = NULL;
    NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, L"No Such Provider gap4", 0);
    CHECK(s < 0);
    t_note("unknown implementation name -> 0x%lx", (unsigned long)s);
    if (s == 0) g4_close(h);
}
TEST(gap4_open_primitive_provider_by_name) {
    OPEN_REQ();
    h = NULL;
    NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    EXPECT_EQ(s, 0);
    CHECK(h != NULL);
    if (s == 0) EQC(BC(BCryptCloseAlgorithmProvider)(h, 0), 0);
}

static void open_close_ok(const wchar_t *alg, ULONG fl)
{
    BCRYPT_ALG_HANDLE h = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x77;
    NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, alg, NULL, fl);
    t_check(s == 0, __FILE__, __LINE__, "open == STATUS_SUCCESS", "alg %ls flags 0x%lx got 0x%lx", alg, (unsigned long)fl, (unsigned long)s);
    if (s != 0) return;
    CHECKF(h != NULL && h != (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x77, "alg %ls: handle not set", alg);
    s = BC(BCryptCloseAlgorithmProvider)(h, 0);
    t_check(s == 0, __FILE__, __LINE__, "close == STATUS_SUCCESS", "alg %ls got 0x%lx", alg, (unsigned long)s);
}
#define OC(tname, alg, fl) TEST(gap4_open_close_##tname) { OPEN_REQ(); (void)h; open_close_ok(alg, fl); }
OC(md5, BCRYPT_MD5_ALGORITHM, 0)
OC(sha1, BCRYPT_SHA1_ALGORITHM, 0)
OC(sha256, BCRYPT_SHA256_ALGORITHM, 0)
OC(sha384, BCRYPT_SHA384_ALGORITHM, 0)
OC(sha512, BCRYPT_SHA512_ALGORITHM, 0)
OC(md5_hmac, BCRYPT_MD5_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)
OC(sha1_hmac, BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)
OC(sha256_hmac, BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)
OC(sha384_hmac, BCRYPT_SHA384_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)
OC(sha512_hmac, BCRYPT_SHA512_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG)
OC(sha256_reusable, BCRYPT_SHA256_ALGORITHM, BCRYPT_HASH_REUSABLE_FLAG)
OC(aes, BCRYPT_AES_ALGORITHM, 0)
OC(rsa, BCRYPT_RSA_ALGORITHM, 0)
OC(rsa_sign, BCRYPT_RSA_SIGN_ALGORITHM, 0)
OC(dsa, BCRYPT_DSA_ALGORITHM, 0)
OC(dh, BCRYPT_DH_ALGORITHM, 0)
OC(ecdsa_p256, BCRYPT_ECDSA_P256_ALGORITHM, 0)
OC(ecdsa_p384, BCRYPT_ECDSA_P384_ALGORITHM, 0)
OC(ecdsa_p521, BCRYPT_ECDSA_P521_ALGORITHM, 0)
OC(ecdh_p256, BCRYPT_ECDH_P256_ALGORITHM, 0)
OC(ecdh_p384, BCRYPT_ECDH_P384_ALGORITHM, 0)
OC(ecdh_p521, BCRYPT_ECDH_P521_ALGORITHM, 0)
OC(rng, BCRYPT_RNG_ALGORITHM, 0)
OC(des, BCRYPT_DES_ALGORITHM, 0)
OC(3des, BCRYPT_3DES_ALGORITHM, 0)
OC(rc4, BCRYPT_RC4_ALGORITHM, 0)

TEST(gap4_open_distinct_handles_for_same_algorithm) {
    OPEN_REQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0), b = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    CHECK(a != NULL && b != NULL);
    if (a && b) CHECK(a != b);
    /* closing one leaves the other usable */
    if (a) EQC(BC(BCryptCloseAlgorithmProvider)(a, 0), 0);
    if (b) {
        BYTE out[32];
        EQC(BC(BCryptHash)(b, NULL, 0, (PUCHAR)"abc", 3, out, 32), 0);
        EQC(BC(BCryptCloseAlgorithmProvider)(b, 0), 0);
    }
}
TEST(gap4_open_handle_pointer_is_16_aligned) {
    OPEN_REQ();
    h = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    CHECK(h != NULL);
    /* pseudo handles use low nibble 1; real handles must not */
    if (h) CHECK(((ULONG_PTR)h & 0xF) != 1);
    g4_close(h);
}
TEST(gap4_open_many_open_close_cycles) {
    OPEN_REQ(); (void)h;
    int bad = 0;
    for (int i = 0; i < 200; i++) {
        BCRYPT_ALG_HANDLE x = NULL;
        if (BC(BCryptOpenAlgorithmProvider)(&x, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) { bad++; continue; }
        if (BC(BCryptCloseAlgorithmProvider)(x, 0) != 0) bad++;
    }
    EXPECT_EQ(bad, 0);
}
TEST(gap4_open_many_simultaneously) {
    OPEN_REQ(); (void)h;
    BCRYPT_ALG_HANDLE hs[64]; int n = 0, bad = 0;
    for (int i = 0; i < 64; i++) {
        hs[n] = NULL;
        if (BC(BCryptOpenAlgorithmProvider)(&hs[n], BCRYPT_SHA1_ALGORITHM, NULL, 0) == 0) n++; else bad++;
    }
    EXPECT_EQ(bad, 0);
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++) if (hs[i] == hs[j]) bad++;
    EXPECT_EQ(bad, 0);
    for (int i = 0; i < n; i++) if (BC(BCryptCloseAlgorithmProvider)(hs[i], 0) != 0) bad++;
    EXPECT_EQ(bad, 0);
}

/* ---- close ---- */
TEST(gap4_close_null_handle) {
    REQUIRE(BC(BCryptCloseAlgorithmProvider));
    EQC(BC(BCryptCloseAlgorithmProvider)(NULL, 0), G4_INVALID_HANDLE);
}
TEST(gap4_close_null_handle_flags_ignored) {
    REQUIRE(BC(BCryptCloseAlgorithmProvider));
    EQC(BC(BCryptCloseAlgorithmProvider)(NULL, 0xFFFFFFFF), G4_INVALID_HANDLE);
}
TEST(gap4_close_flags_ignored) {
    OPEN_REQ();
    /* dwFlags is only traced, never consulted */
    h = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    CHECK(h != NULL);
    if (h) EQC(BC(BCryptCloseAlgorithmProvider)(h, 0xFFFFFFFF), 0);
}
TEST(gap4_close_hash_handle_is_wrong_object) {
    OPEN_REQ();
    h = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    REQUIRE(h);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(h, &hh, NULL, 0, NULL, 0, 0), 0);
    if (hh) {
        EQC(BC(BCryptCloseAlgorithmProvider)(hh, 0), G4_INVALID_HANDLE);
        EQC(BC(BCryptDestroyHash)(hh), 0);
    }
    EQC(BC(BCryptCloseAlgorithmProvider)(h, 0), 0);
}
TEST(gap4_close_key_handle_is_wrong_object) {
    OPEN_REQ();
    h = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0);
    REQUIRE(h);
    BCRYPT_KEY_HANDLE k = g4_keypair(h, 256);
    CHECK(k != NULL);
    if (k) {
        EQC(BC(BCryptCloseAlgorithmProvider)(k, 0), G4_INVALID_HANDLE);
        EQC(BC(BCryptDestroyKey)(k), 0);
    }
    EQC(BC(BCryptCloseAlgorithmProvider)(h, 0), 0);
}
TEST(gap4_close_while_hash_outstanding_keeps_hash_usable) {
    OPEN_REQ();
    /* hash and key handles hold a reference on the algorithm object */
    h = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    REQUIRE(h);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(h, &hh, NULL, 0, NULL, 0, 0), 0);
    REQUIRE(hh);
    EQC(BC(BCryptCloseAlgorithmProvider)(h, 0), 0);
    BYTE out[32];
    EQC(BC(BCryptHashData)(hh, (PUCHAR)"abc", 3, 0), 0);
    EQC(BC(BCryptFinishHash)(hh, out, 32, 0), 0);
    CHECK(g4_hex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    EQC(BC(BCryptDestroyHash)(hh), 0);
}
TEST(gap4_close_while_key_outstanding_keeps_key_usable) {
    OPEN_REQ();
    h = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0);
    REQUIRE(h);
    BCRYPT_KEY_HANDLE k = g4_keypair(h, 256);
    REQUIRE(k);
    EQC(BC(BCryptCloseAlgorithmProvider)(h, 0), 0);
    ULONG cb = 0;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cb, 0), 0);
    EXPECT_EQ(cb, 72);
    EQC(BC(BCryptDestroyKey)(k), 0);
}
