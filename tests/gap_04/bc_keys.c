#include "gap4.h"
/* BCryptGenerateKeyPair / BCryptFinalizeKeyPair / BCryptDestroyKey */

#define KREQ() do { if (!BC(BCryptGenerateKeyPair) || !BC(BCryptFinalizeKeyPair) || !BC(BCryptDestroyKey)) { t_skip("missing key-pair exports"); return; } } while (0)

TEST(gap4_genkp_null_algorithm) {
    KREQ();
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x55;
    EQC(BC(BCryptGenerateKeyPair)(NULL, &k, 256, 0), G4_INVALID_HANDLE);
    EXPECT_EQ(k, 0x55);
}
TEST(gap4_genkp_null_algorithm_null_key_pointer) {
    KREQ();
    /* the algorithm handle is validated before the output pointer */
    EQC(BC(BCryptGenerateKeyPair)(NULL, NULL, 256, 0), G4_INVALID_HANDLE);
}
TEST(gap4_genkp_null_key_pointer) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    EQC(BC(BCryptGenerateKeyPair)(a, NULL, 256, 0), G4_INVALID_PARAM);
    g4_close(a);
}
TEST(gap4_genkp_hash_algorithm_not_supported) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x55;
    EQC(BC(BCryptGenerateKeyPair)(a, &k, 256, 0), G4_NOT_SUPPORTED);
    EXPECT_EQ(k, 0x55);
    g4_close(a);
}
TEST(gap4_genkp_symmetric_algorithm_not_supported) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_AES_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = (BCRYPT_KEY_HANDLE)(ULONG_PTR)0x55;
    EQC(BC(BCryptGenerateKeyPair)(a, &k, 128, 0), G4_NOT_SUPPORTED);
    EXPECT_EQ(k, 0x55);
    g4_close(a);
}
TEST(gap4_genkp_rng_algorithm_fails) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RNG_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    NTSTATUS s = BC(BCryptGenerateKeyPair)(a, &k, 256, 0);
    CHECK(s < 0);
    t_note("GenerateKeyPair on RNG -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
TEST(gap4_genkp_key_handle_as_algorithm) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256), k2 = NULL;
    REQUIRE(k);
    EQC(BC(BCryptGenerateKeyPair)(k, &k2, 256, 0), G4_INVALID_HANDLE);
    EXPECT_EQ(k2, 0);
    BC(BCryptDestroyKey)(k);
    g4_close(a);
}

#define GEN_OK(tname, alg, bits) \
TEST(gap4_genkp_##tname) { \
    KREQ(); \
    BCRYPT_ALG_HANDLE a = g4_open(alg, 0); REQUIRE(a); \
    BCRYPT_KEY_HANDLE k = NULL; \
    EQC(BC(BCryptGenerateKeyPair)(a, &k, bits, 0), 0); \
    CHECK(k != NULL); \
    if (k) { EQC(BC(BCryptFinalizeKeyPair)(k, 0), 0); EQC(BC(BCryptDestroyKey)(k), 0); } \
    g4_close(a); \
}
GEN_OK(ecdsa_p256, BCRYPT_ECDSA_P256_ALGORITHM, 256)
GEN_OK(ecdsa_p384, BCRYPT_ECDSA_P384_ALGORITHM, 384)
GEN_OK(ecdsa_p521, BCRYPT_ECDSA_P521_ALGORITHM, 521)
GEN_OK(ecdh_p256, BCRYPT_ECDH_P256_ALGORITHM, 256)
GEN_OK(ecdh_p384, BCRYPT_ECDH_P384_ALGORITHM, 384)
GEN_OK(rsa_1024, BCRYPT_RSA_ALGORITHM, 1024)
GEN_OK(rsa_2048, BCRYPT_RSA_ALGORITHM, 2048)

TEST(gap4_genkp_generic_ecdsa_length_selects_curve) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(L"ECDSA", 0);
    if (!a) { t_skip("generic ECDSA algorithm not available"); return; }
    static const ULONG bits[] = { 256, 384, 521 }, cb[] = { 32, 48, 66 };
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = g4_keypair(a, bits[i]);
        if (!k) { t_note("generic ECDSA with %lu bits not supported", (unsigned long)bits[i]); continue; }
        BYTE blob[256]; ULONG n = 0;
        EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &n, 0), 0);
        EXPECT_EQ(n, 8 + 2 * cb[i]);
        EXPECT_EQ(((BCRYPT_ECCKEY_BLOB *)blob)->cbKey, cb[i]);
        BC(BCryptDestroyKey)(k);
    }
    g4_close(a);
}
TEST(gap4_genkp_two_keys_are_different) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k1 = g4_keypair(a, 256), k2 = g4_keypair(a, 256);
    REQUIRE(k1); REQUIRE(k2);
    CHECK(k1 != k2);
    BYTE b1[72], b2[72]; ULONG n;
    EQC(BC(BCryptExportKey)(k1, NULL, BCRYPT_ECCPUBLIC_BLOB, b1, 72, &n, 0), 0);
    EQC(BC(BCryptExportKey)(k2, NULL, BCRYPT_ECCPUBLIC_BLOB, b2, 72, &n, 0), 0);
    CHECK(memcmp(b1, b2, 72) != 0);
    BC(BCryptDestroyKey)(k1); BC(BCryptDestroyKey)(k2);
    g4_close(a);
}
TEST(gap4_genkp_many_keys_one_algorithm) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE ks[32]; int n = 0, bad = 0;
    for (int i = 0; i < 32; i++) { ks[n] = g4_keypair(a, 256); if (ks[n]) n++; else bad++; }
    EXPECT_EQ(bad, 0);
    for (int i = 0; i < n; i++) if (BC(BCryptDestroyKey)(ks[i]) != 0) bad++;
    EXPECT_EQ(bad, 0);
    EQC(BC(BCryptCloseAlgorithmProvider)(a, 0), 0);
}
TEST(gap4_genkp_unfinalized_destroy_ok) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    EQC(BC(BCryptGenerateKeyPair)(a, &k, 256, 0), 0);
    REQUIRE(k);
    EQC(BC(BCryptDestroyKey)(k), 0);
    g4_close(a);
}

/* ---- finalize ---- */
TEST(gap4_finalize_null_key) {
    KREQ();
    EQC(BC(BCryptFinalizeKeyPair)(NULL, 0), G4_INVALID_HANDLE);
}
TEST(gap4_finalize_null_key_flags_irrelevant) {
    KREQ();
    EQC(BC(BCryptFinalizeKeyPair)(NULL, 0xFFFFFFFF), G4_INVALID_HANDLE);
}
TEST(gap4_finalize_algorithm_handle_is_wrong_object) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    EQC(BC(BCryptFinalizeKeyPair)(a, 0), G4_INVALID_HANDLE);
    g4_close(a);
}
TEST(gap4_finalize_hash_handle_is_wrong_object) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0), 0);
    if (hh) { EQC(BC(BCryptFinalizeKeyPair)(hh, 0), G4_INVALID_HANDLE); BC(BCryptDestroyHash)(hh); }
    g4_close(a);
}
TEST(gap4_finalize_symmetric_key_not_supported) {
    KREQ();
    if (!BC(BCryptGenerateSymmetricKey)) { t_skip("missing BCryptGenerateSymmetricKey"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_AES_ALGORITHM, 0); REQUIRE(a);
    BYTE secret[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    BCRYPT_KEY_HANDLE k = NULL;
    EQC(BC(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, 16, 0), 0);
    if (k) {
        EQC(BC(BCryptFinalizeKeyPair)(k, 0), G4_NOT_SUPPORTED);
        EQC(BC(BCryptDestroyKey)(k), 0);
    }
    g4_close(a);
}
TEST(gap4_finalize_twice) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    NTSTATUS s = BC(BCryptFinalizeKeyPair)(k, 0);
    t_note("second BCryptFinalizeKeyPair on a finalized key -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k);
    g4_close(a);
}
TEST(gap4_finalize_bad_flags) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    REQUIRE(BC(BCryptGenerateKeyPair)(a, &k, 256, 0) == 0);
    NTSTATUS s = BC(BCryptFinalizeKeyPair)(k, 0x80000000);
    t_note("BCryptFinalizeKeyPair with undefined flag bit -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k);
    g4_close(a);
}

/* ---- destroy ---- */
TEST(gap4_destroy_null_key) {
    KREQ();
    EQC(BC(BCryptDestroyKey)(NULL), G4_INVALID_HANDLE);
}
TEST(gap4_destroy_algorithm_handle_is_wrong_object) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    EQC(BC(BCryptDestroyKey)(a), G4_INVALID_HANDLE);
    /* the algorithm handle is still valid afterwards */
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256);
    CHECK(k != NULL);
    if (k) EQC(BC(BCryptDestroyKey)(k), 0);
    EQC(BC(BCryptCloseAlgorithmProvider)(a, 0), 0);
}
TEST(gap4_destroy_hash_handle_is_wrong_object) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0), 0);
    if (hh) {
        EQC(BC(BCryptDestroyKey)(hh), G4_INVALID_HANDLE);
        EQC(BC(BCryptDestroyHash)(hh), 0);
    }
    g4_close(a);
}
TEST(gap4_destroy_symmetric_key) {
    KREQ();
    if (!BC(BCryptGenerateSymmetricKey)) { t_skip("missing BCryptGenerateSymmetricKey"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_AES_ALGORITHM, 0); REQUIRE(a);
    BYTE secret[16] = { 0 };
    BCRYPT_KEY_HANDLE k = NULL;
    EQC(BC(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, 16, 0), 0);
    if (k) EQC(BC(BCryptDestroyKey)(k), 0);
    g4_close(a);
}
TEST(gap4_destroy_releases_algorithm_reference) {
    KREQ();
    /* close the algorithm first, then destroy the key: both succeed in either order */
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    EQC(BC(BCryptCloseAlgorithmProvider)(a, 0), 0);
    EQC(BC(BCryptDestroyKey)(k), 0);
}
TEST(gap4_destroy_after_close_order_reversed) {
    KREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    EQC(BC(BCryptDestroyKey)(k), 0);
    EQC(BC(BCryptCloseAlgorithmProvider)(a, 0), 0);
}
