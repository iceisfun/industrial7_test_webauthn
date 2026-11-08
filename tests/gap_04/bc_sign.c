#include "gap4.h"
/* BCryptSignHash / BCryptVerifySignature */

#define SREQ() do { if (!BC(BCryptSignHash) || !BC(BCryptVerifySignature) || !BC(BCryptGenerateKeyPair) || !BC(BCryptFinalizeKeyPair) || !BC(BCryptDestroyKey)) { t_skip("missing sign exports"); return; } } while (0)

static const BYTE H32[32] = { 0x6a,0x09,0xe6,0x67,0xbb,0x67,0xae,0x85,0x3c,0x6e,0xf3,0x72,0xa5,0x4f,0xf5,0x3a,
                              0x51,0x0e,0x52,0x7f,0x9b,0x05,0x68,0x8c,0x1f,0x83,0xd9,0xab,0x5b,0xe0,0xcd,0x19 };

typedef struct { const wchar_t *alg; ULONG bits, sig; } ec_t;
static const ec_t ecs[] = { { BCRYPT_ECDSA_P256_ALGORITHM, 256, 64 }, { BCRYPT_ECDSA_P384_ALGORITHM, 384, 96 }, { BCRYPT_ECDSA_P521_ALGORITHM, 521, 132 } };

static void ec_roundtrip(const ec_t *e)
{
    BCRYPT_ALG_HANDLE a = g4_open(e->alg, 0);
    if (!a) { CHECK(0); return; }
    BCRYPT_KEY_HANDLE k = g4_keypair(a, e->bits);
    if (!k) { CHECKF(0, "key pair"); g4_close(a); return; }
    ULONG n = 0xDEAD;
    BYTE sig[256]; memset(sig, 0xEE, sizeof sig);
    /* size query */
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, e->sig);
    /* short buffer */
    n = 0;
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, e->sig - 1, &n, 0), G4_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, e->sig);
    /* exact buffer */
    n = 0;
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, e->sig, &n, 0), 0);
    EXPECT_EQ(n, e->sig);
    int over = 0; for (ULONG i = n; i < sizeof sig; i++) if (sig[i] != 0xEE) over++;
    EXPECT_EQ(over, 0);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, e->sig, 0), 0);
    /* tampered signature */
    sig[3] ^= 1;
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, e->sig, 0), G4_BAD_SIGNATURE);
    sig[3] ^= 1;
    /* tampered hash */
    BYTE h2[32]; memcpy(h2, H32, 32); h2[31] ^= 0x80;
    EQC(BC(BCryptVerifySignature)(k, NULL, h2, 32, sig, e->sig, 0), G4_BAD_SIGNATURE);
    /* a different key rejects it */
    BCRYPT_KEY_HANDLE k2 = g4_keypair(a, e->bits);
    if (k2) { EQC(BC(BCryptVerifySignature)(k2, NULL, (PUCHAR)H32, 32, sig, e->sig, 0), G4_BAD_SIGNATURE); BC(BCryptDestroyKey)(k2); }
    BC(BCryptDestroyKey)(k);
    g4_close(a);
}
#define EC_T(i) TEST(gap4_sign_ecdsa_roundtrip_##i) { SREQ(); ec_roundtrip(&ecs[i]); }
EC_T(0) EC_T(1) EC_T(2)

TEST(gap4_sign_ecdsa_signatures_are_randomized) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE s1[64], s2[64]; ULONG n;
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, s1, 64, &n, 0), 0);
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, s2, 64, &n, 0), 0);
    CHECK(memcmp(s1, s2, 64) != 0);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, s1, 64, 0), 0);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, s2, 64, 0), 0);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_sign_ecdsa_verify_with_imported_public_key) {
    SREQ();
    if (!BC(BCryptImportKeyPair) || !BC(BCryptExportKey)) { t_skip("missing import/export"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE pub[72], sig[64]; ULONG n;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, pub, 72, &n, 0), 0);
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), 0);
    BCRYPT_KEY_HANDLE pk = NULL;
    EQC(BC(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &pk, pub, 72, 0), 0);
    if (pk) {
        EQC(BC(BCryptVerifySignature)(pk, NULL, (PUCHAR)H32, 32, sig, 64, 0), 0);
        /* a public-only key cannot sign */
        NTSTATUS s = BC(BCryptSignHash)(pk, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0);
        CHECK(s < 0);
        t_note("sign with public-only key -> 0x%lx", (unsigned long)s);
        BC(BCryptDestroyKey)(pk);
    }
    BC(BCryptDestroyKey)(k); g4_close(a);
}

/* ---- RSA PKCS#1 v1.5 ---- */
TEST(gap4_sign_rsa_pkcs1_roundtrip) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 1024); REQUIRE(k);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    BYTE sig[256]; ULONG n = 0;
    EQC(BC(BCryptSignHash)(k, &pi, (PUCHAR)H32, 32, NULL, 0, &n, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(n, 128);
    n = 0;
    EQC(BC(BCryptSignHash)(k, &pi, (PUCHAR)H32, 32, sig, 127, &n, BCRYPT_PAD_PKCS1), G4_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, 128);
    EQC(BC(BCryptSignHash)(k, &pi, (PUCHAR)H32, 32, sig, 128, &n, BCRYPT_PAD_PKCS1), 0);
    EXPECT_EQ(n, 128);
    EQC(BC(BCryptVerifySignature)(k, &pi, (PUCHAR)H32, 32, sig, 128, BCRYPT_PAD_PKCS1), 0);
    /* PKCS#1 v1.5 is deterministic */
    BYTE sig2[128];
    EQC(BC(BCryptSignHash)(k, &pi, (PUCHAR)H32, 32, sig2, 128, &n, BCRYPT_PAD_PKCS1), 0);
    CHECK(!memcmp(sig, sig2, 128));
    sig[10] ^= 4;
    EQC(BC(BCryptVerifySignature)(k, &pi, (PUCHAR)H32, 32, sig, 128, BCRYPT_PAD_PKCS1), G4_BAD_SIGNATURE);
    sig[10] ^= 4;
    /* wrong hash algorithm in the padding info */
    BCRYPT_PKCS1_PADDING_INFO pi1 = { BCRYPT_SHA1_ALGORITHM };
    NTSTATUS s = BC(BCryptVerifySignature)(k, &pi1, (PUCHAR)H32, 32, sig, 128, BCRYPT_PAD_PKCS1);
    CHECK(s < 0);
    t_note("verify with mismatched padding hash -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_sign_rsa_without_padding_flag) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 1024); REQUIRE(k);
    BYTE sig[128]; ULONG n = 0;
    NTSTATUS s = BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 128, &n, 0);
    CHECK(s < 0);
    t_note("RSA sign with no padding flag -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}

/* ---- argument validation (SignHash: pcbResult, key handle, key class) ---- */
TEST(gap4_sign_null_pcbresult) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE sig[64];
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 64, NULL, 0), G4_INVALID_PARAM);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_sign_null_pcbresult_wins_over_null_key) {
    SREQ();
    EQC(BC(BCryptSignHash)(NULL, NULL, (PUCHAR)H32, 32, NULL, 0, NULL, 0), G4_INVALID_PARAM);
}
TEST(gap4_sign_null_key) {
    SREQ();
    ULONG n = 0x77; BYTE sig[64];
    EQC(BC(BCryptSignHash)(NULL, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), G4_INVALID_HANDLE);
    EXPECT_EQ(n, 0x77);
}
TEST(gap4_sign_algorithm_handle_is_wrong_object) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    ULONG n; BYTE sig[64];
    EQC(BC(BCryptSignHash)(a, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), G4_INVALID_HANDLE);
    g4_close(a);
}
TEST(gap4_sign_hash_handle_is_wrong_object) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0), 0);
    ULONG n; BYTE sig[64];
    if (hh) { EQC(BC(BCryptSignHash)(hh, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), G4_INVALID_HANDLE); BC(BCryptDestroyHash)(hh); }
    g4_close(a);
}
TEST(gap4_sign_secret_agreement_key_not_supported) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDH_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    ULONG n = 0; BYTE sig[128];
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 128, &n, 0), G4_NOT_SUPPORTED);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, 64, 0), G4_NOT_SUPPORTED);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_sign_symmetric_key_not_supported) {
    SREQ();
    if (!BC(BCryptGenerateSymmetricKey)) { t_skip("missing BCryptGenerateSymmetricKey"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_AES_ALGORITHM, 0); REQUIRE(a);
    BYTE secret[16] = { 9 }; BCRYPT_KEY_HANDLE k = NULL;
    EQC(BC(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, secret, 16, 0), 0);
    REQUIRE(k);
    ULONG n = 0; BYTE sig[64];
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), G4_NOT_SUPPORTED);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, 64, 0), G4_NOT_SUPPORTED);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_sign_unfinalized_key) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    REQUIRE(BC(BCryptGenerateKeyPair)(a, &k, 256, 0) == 0);
    ULONG n = 0; BYTE sig[64];
    NTSTATUS s = BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0);
    CHECK(s < 0);
    t_note("sign with unfinalized key -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}

/* ---- VerifySignature validation: key handle, then NULL pointers, then key class ---- */
TEST(gap4_verify_null_key) {
    SREQ();
    BYTE sig[64] = { 0 };
    EQC(BC(BCryptVerifySignature)(NULL, NULL, (PUCHAR)H32, 32, sig, 64, 0), G4_INVALID_HANDLE);
}
TEST(gap4_verify_null_key_wins_over_null_pointers) {
    SREQ();
    EQC(BC(BCryptVerifySignature)(NULL, NULL, NULL, 0, NULL, 0, 0), G4_INVALID_HANDLE);
}
TEST(gap4_verify_null_signature) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, NULL, 64, 0), G4_INVALID_PARAM);
    EQC(BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, NULL, 0, 0), G4_INVALID_PARAM);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_verify_null_hash) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE sig[64] = { 0 };
    EQC(BC(BCryptVerifySignature)(k, NULL, NULL, 32, sig, 64, 0), G4_INVALID_PARAM);
    EQC(BC(BCryptVerifySignature)(k, NULL, NULL, 0, sig, 64, 0), G4_INVALID_PARAM);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_verify_null_pointers_checked_before_key_class) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDH_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    EQC(BC(BCryptVerifySignature)(k, NULL, NULL, 32, NULL, 64, 0), G4_INVALID_PARAM);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_verify_algorithm_handle_is_wrong_object) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BYTE sig[64] = { 0 };
    EQC(BC(BCryptVerifySignature)(a, NULL, (PUCHAR)H32, 32, sig, 64, 0), G4_INVALID_HANDLE);
    g4_close(a);
}
TEST(gap4_verify_all_zero_signature_rejected) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE sig[64] = { 0 };
    NTSTATUS s = BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, 64, 0);
    CHECK(s < 0);
    t_note("all-zero ECDSA signature -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_verify_wrong_signature_length) {
    SREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE sig[80]; ULONG n;
    EQC(BC(BCryptSignHash)(k, NULL, (PUCHAR)H32, 32, sig, 64, &n, 0), 0);
    memset(sig + 64, 0, 16);
    NTSTATUS s1 = BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, 63, 0);
    NTSTATUS s2 = BC(BCryptVerifySignature)(k, NULL, (PUCHAR)H32, 32, sig, 65, 0);
    t_note("ECDSA P-256 verify with cbSignature 63 -> 0x%lx, 65 -> 0x%lx", (unsigned long)s1, (unsigned long)s2);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
