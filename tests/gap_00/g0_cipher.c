#include "gap0.h"

#define BCRYPT_BLOCK_PADDING_ 1u
static NTSTATUS g0_setchain(BCRYPT_ALG_HANDLE a, const wchar_t *mode) {
    return U(BCryptSetProperty)(a, L"ChainingMode", (PUCHAR)mode, (ULONG)((lstrlenW(mode) + 1) * 2), 0);
}
static NTSTATUS g0_aeskey(BCRYPT_ALG_HANDLE a, const char *keyhex, BCRYPT_KEY_HANDLE *k) {
    unsigned char key[32]; size_t n = g0_hex(keyhex, key);
    *k = NULL; return U(BCryptGenerateSymmetricKey)(a, k, NULL, 0, key, (ULONG)n, 0);
}
static const char *K128 = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *PT4 = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

/* ---- GenerateSymmetricKey --------------------------------------------- */
TEST(gap0_symkey_aes_valid_sizes) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    G0_OKST(g0_open(&a, L"AES", 0));
    static const ULONG ok[] = {16, 24, 32};
    for (int i = 0; i < 3; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, ok[i], 0));
        CHECK(k != NULL);
        U(BCryptDestroyKey)(k);
    }
    g0_close(a);
}
TEST(gap0_symkey_aes_invalid_sizes) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char key[64] = {0};
    G0_OKST(g0_open(&a, L"AES", 0));
    static const ULONG bad[] = {0, 1, 8, 15, 17, 23, 25, 31, 33, 64};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        BCRYPT_KEY_HANDLE k = NULL;
        NTSTATUS st = U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, bad[i], 0);
        CHECKF(st < 0 && k == NULL, "AES key length %lu accepted (0x%08lx)", (unsigned long)bad[i], (unsigned long)st);
        if (st < 0) t_note("AES key length %lu -> 0x%08lx", (unsigned long)bad[i], (unsigned long)st);
        if (st >= 0) U(BCryptDestroyKey)(k);
    }
    g0_close(a);
}
TEST(gap0_symkey_argument_validation) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; unsigned char key[16] = {0}, obj[1024]; BCRYPT_KEY_HANDLE k = NULL;
    G0_OKST(g0_open(&a, L"AES", 0));
    ST(U(BCryptGenerateSymmetricKey)(NULL, &k, NULL, 0, key, 16, 0), G0_INVALID_HANDLE);
    ST(U(BCryptGenerateSymmetricKey)(a, NULL, NULL, 0, key, 16, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, NULL, 16, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 512, key, 16, 0), G0_INVALID_PARAMETER);   /* size without buffer */
    ST(U(BCryptGenerateSymmetricKey)(a, &k, obj, 0x3d, key, 16, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptGenerateSymmetricKey)(a, &k, obj, 0, key, 16, 0), G0_BUFFER_TOO_SMALL);
    CHECK(k == NULL);
    g0_close(a);
}
TEST(gap0_symkey_wrong_handle_types) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL, k2 = NULL; unsigned char key[16] = {0};
    G0_OKST(g0_open(&a, L"AES", 0));
    G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, 16, 0));
    ST(U(BCryptGenerateSymmetricKey)(k, &k2, NULL, 0, key, 16, 0), G0_INVALID_HANDLE);   /* key as algorithm */
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_symkey_caller_supplied_object) {
    REQUIRE(U(BCryptGenerateSymmetricKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char ct[16], key[32];
    G0_OKST(g0_open(&a, L"AES", 0));
    ULONG ol = g0_prop_u32(a, L"ObjectLength"); CHECK(ol >= 0x3e);
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ol);
    G0_OKST(g0_setchain(a, L"ChainingModeECB"));
    size_t n = g0_hex("000102030405060708090a0b0c0d0e0f", key);
    G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, obj, ol, key, (ULONG)n, 0));
    unsigned char pt[16]; g0_hex("00112233445566778899aabbccddeeff", pt); ULONG cb = 0;
    G0_OKST(U(BCryptEncrypt)(k, pt, 16, NULL, NULL, 0, ct, 16, &cb, 0));
    EXPECT_EQ(cb, 16);
    G0_CHECK_HEX(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    G0_OKST(U(BCryptDestroyKey)(k));
    HeapFree(GetProcessHeap(), 0, obj); g0_close(a);
}

/* ---- AES known answers ------------------------------------------------- */
TEST(gap0_aes_ecb_fips197) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    static const struct { const char *key, *ct; } v[] = {
        { "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a" },
        { "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191" },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089" },
    };
    for (int i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char pt[16], ct[16], back[16]; ULONG cb = 0;
        G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeECB"));
        G0_OKST(g0_aeskey(a, v[i].key, &k));
        g0_hex("00112233445566778899aabbccddeeff", pt);
        G0_OKST(U(BCryptEncrypt)(k, pt, 16, NULL, NULL, 0, ct, 16, &cb, 0));
        EXPECT_EQ(cb, 16);
        CHECK(g0_eqhex(ct, 16, v[i].ct));
        G0_OKST(U(BCryptDecrypt)(k, ct, 16, NULL, NULL, 0, back, 16, &cb, 0));
        EXPECT_EQ(cb, 16);
        CHECK(!memcmp(back, pt, 16));
        U(BCryptDestroyKey)(k); g0_close(a);
    }
}
TEST(gap0_aes_ecb_sp800_38a_four_blocks) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char pt[64], ct[64]; ULONG cb = 0;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeECB")); G0_OKST(g0_aeskey(a, K128, &k));
    g0_hex(PT4, pt);
    G0_OKST(U(BCryptEncrypt)(k, pt, 64, NULL, NULL, 0, ct, 64, &cb, 0));
    EXPECT_EQ(cb, 64);
    G0_CHECK_HEX(ct, 64, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_cbc_sp800_38a_and_iv_update) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char pt[64], ct[64], iv[16], back[64]; ULONG cb = 0;
    static const char *CT = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeCBC")); G0_OKST(g0_aeskey(a, K128, &k));
    g0_hex(PT4, pt);
    g0_hex("000102030405060708090a0b0c0d0e0f", iv);
    G0_OKST(U(BCryptEncrypt)(k, pt, 64, NULL, iv, 16, ct, 64, &cb, 0));
    EXPECT_EQ(cb, 64);
    CHECK(g0_eqhex(ct, 64, CT));
    CHECK(!memcmp(iv, ct + 48, 16));                       /* the IV buffer is updated to the last ciphertext block */
    g0_hex("000102030405060708090a0b0c0d0e0f", iv);
    G0_OKST(U(BCryptDecrypt)(k, ct, 64, NULL, iv, 16, back, 64, &cb, 0));
    EXPECT_EQ(cb, 64);
    CHECK(!memcmp(back, pt, 64));
    /* block-by-block chaining through the updated IV */
    g0_hex("000102030405060708090a0b0c0d0e0f", iv);
    for (int b = 0; b < 4; b++) {
        unsigned char o[16];
        G0_OKST(U(BCryptEncrypt)(k, pt + 16 * b, 16, NULL, iv, 16, o, 16, &cb, 0));
        CHECK(!memcmp(o, ct + 16 * b, 16));
    }
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_default_chaining_is_cbc) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; wchar_t m[64] = {0}; ULONG cb = 0;
    G0_OKST(g0_open(&a, L"AES", 0));
    G0_OKST(U(BCryptGetProperty)(a, L"ChainingMode", (PUCHAR)m, sizeof m, &cb, 0));
    EXPECT_WSTR(m, L"ChainingModeCBC");
    t_note("ChainingMode property size: %lu", (unsigned long)cb);
    g0_close(a);
}
TEST(gap0_aes_pkcs7_padding_sizes) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[48], ct[64], iv[16], back[64];
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    for (int i = 0; i < 48; i++) in[i] = (unsigned char)i;
    static const struct { ULONG in, out; } cases[] = { {0, 16}, {1, 16}, {15, 16}, {16, 32}, {17, 32}, {31, 32}, {32, 48}, {47, 48} };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        ULONG cb = 0, cb2 = 0;
        memset(iv, 0, 16);
        G0_OKST(U(BCryptEncrypt)(k, in, cases[i].in, NULL, iv, 16, NULL, 0, &cb, BCRYPT_BLOCK_PADDING));     /* size query */
        EXPECT_EQ(cb, cases[i].out);
        memset(iv, 0, 16);
        G0_OKST(U(BCryptEncrypt)(k, in, cases[i].in, NULL, iv, 16, ct, sizeof ct, &cb2, BCRYPT_BLOCK_PADDING));
        EXPECT_EQ(cb2, cases[i].out);
        memset(iv, 0, 16);
        ULONG pl = 0;
        G0_OKST(U(BCryptDecrypt)(k, ct, cb2, NULL, iv, 16, back, sizeof back, &pl, BCRYPT_BLOCK_PADDING));
        EXPECT_EQ(pl, cases[i].in);
        CHECK(!memcmp(back, in, cases[i].in));
    }
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_padded_output_too_small) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[16] = {0}, out[64], iv[16] = {0}; ULONG cb = 0;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    ST(U(BCryptEncrypt)(k, in, 16, NULL, iv, 16, out, 31, &cb, BCRYPT_BLOCK_PADDING), G0_BUFFER_TOO_SMALL);   /* needs 32 */
    memset(iv, 0, 16);
    ST(U(BCryptEncrypt)(k, in, 5, NULL, iv, 16, out, 8, &cb, BCRYPT_BLOCK_PADDING), G0_BUFFER_TOO_SMALL);    /* needs 16 */
    memset(iv, 0, 16);
    ST(U(BCryptEncrypt)(k, in, 16, NULL, iv, 16, out, 15, &cb, 0), G0_BUFFER_TOO_SMALL);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_unpadded_partial_block) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[32] = {0}, out[48], iv[16];
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    static const ULONG bad[] = {1, 15, 17, 31};
    for (size_t i = 0; i < 4; i++) {
        ULONG cb = 0; memset(iv, 0, 16);
        ST(U(BCryptEncrypt)(k, in, bad[i], NULL, iv, 16, out, sizeof out, &cb, 0), G0_INVALID_BUF_SIZE);
        memset(iv, 0, 16);
        ST(U(BCryptDecrypt)(k, in, bad[i], NULL, iv, 16, out, sizeof out, &cb, 0), G0_INVALID_BUF_SIZE);
    }
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_size_query_unpadded) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[32] = {0}, iv[16] = {0}; ULONG cb = 99;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    G0_OKST(U(BCryptEncrypt)(k, in, 32, NULL, iv, 16, NULL, 0, &cb, 0));
    EXPECT_EQ(cb, 32);
    cb = 99; memset(iv, 0, 16);
    G0_OKST(U(BCryptDecrypt)(k, in, 32, NULL, iv, 16, NULL, 0, &cb, 0));
    EXPECT_EQ(cb, 32);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_output_larger_than_needed) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[16] = {0}, out[64], iv[16] = {0}; ULONG cb = 0;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    memset(out, 0xEE, sizeof out);
    G0_OKST(U(BCryptEncrypt)(k, in, 16, NULL, iv, 16, out, 64, &cb, 0));
    EXPECT_EQ(cb, 16);
    for (int i = 16; i < 64; i++) CHECK(out[i] == 0xEE);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_mode_is_captured_at_key_creation) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[32] = {0}, o1[32], o2[32], iv[16] = {0}; ULONG cb;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeECB")); G0_OKST(g0_aeskey(a, K128, &k));
    G0_OKST(g0_setchain(a, L"ChainingModeCBC"));                     /* no effect on the existing key */
    G0_OKST(U(BCryptEncrypt)(k, in, 32, NULL, NULL, 0, o1, 32, &cb, 0));
    CHECK(!memcmp(o1, o1 + 16, 16));                                  /* ECB: equal plaintext blocks give equal ciphertext */
    U(BCryptDestroyKey)(k);
    G0_OKST(g0_aeskey(a, K128, &k));
    G0_OKST(U(BCryptEncrypt)(k, in, 32, NULL, iv, 16, o2, 32, &cb, 0));
    CHECK(memcmp(o2, o2 + 16, 16) != 0);                              /* CBC: chained */
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_cbc_missing_iv_note) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char in[16] = {0}, o[16], iv[16] = {0}; ULONG cb;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    NTSTATUS s0 = U(BCryptEncrypt)(k, in, 16, NULL, NULL, 0, o, 16, &cb, 0);
    NTSTATUS s1 = U(BCryptEncrypt)(k, in, 16, NULL, iv, 8, o, 16, &cb, 0);
    t_note("CBC no IV -> 0x%08lx ; IV of 8 bytes -> 0x%08lx", (unsigned long)s0, (unsigned long)s1);
    U(BCryptDestroyKey)(k); g0_close(a);
}

/* ---- Encrypt/Decrypt argument validation (decomp-verified) -------------- */
TEST(gap0_crypt_null_result_pointer_checked_first) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt));
    unsigned char b[16] = {0};
    /* pcbResult is validated before the key handle */
    ST(U(BCryptEncrypt)(NULL, b, 16, NULL, NULL, 0, b, 16, NULL, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDecrypt)(NULL, b, 16, NULL, NULL, 0, b, 16, NULL, 0), G0_INVALID_PARAMETER);
}
TEST(gap0_crypt_invalid_key_handle) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt));
    unsigned char b[16] = {0}; ULONG cb = 77;
    ST(U(BCryptEncrypt)(NULL, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);
    ST(U(BCryptDecrypt)(NULL, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"AES", 0));
    ST(U(BCryptEncrypt)(a, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);   /* algorithm handle is not a key */
    ST(U(BCryptDecrypt)(a, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);
    BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ST(U(BCryptEncrypt)(h, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);   /* hash handle is not a key */
    U(BCryptDestroyHash)(h); g0_close(a);
}
TEST(gap0_crypt_result_untouched_on_handle_error) {
    REQUIRE(U(BCryptEncrypt));
    unsigned char b[16] = {0}; ULONG cb = 0x1234;
    ST(U(BCryptEncrypt)(NULL, b, 16, NULL, NULL, 0, b, 16, &cb, 0), G0_INVALID_HANDLE);
    EXPECT_EQ(cb, 0x1234);
}

/* ---- GCM ---------------------------------------------------------------- */
static NTSTATUS g0_gcm_open(BCRYPT_ALG_HANDLE *a) {
    NTSTATUS st = g0_open(a, L"AES", 0); if (st < 0) return st;
    return g0_setchain(*a, L"ChainingModeGCM");
}
TEST(gap0_aes_gcm_known_answers) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char zero[16] = {0}, iv[12] = {0}, tag[16], ct[16], back[16]; ULONG cb;
    G0_OKST(g0_gcm_open(&a)); G0_OKST(g0_aeskey(a, "00000000000000000000000000000000", &k));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = iv; ai.cbNonce = 12; ai.pbTag = tag; ai.cbTag = 16;
    /* test case 1: empty plaintext */
    memset(tag, 0, 16);
    G0_OKST(U(BCryptEncrypt)(k, NULL, 0, &ai, NULL, 0, NULL, 0, &cb, 0));
    EXPECT_EQ(cb, 0);
    G0_CHECK_HEX(tag, 16, "58e2fccefa7e3061367f1d57a4e7455a");
    /* test case 2: one zero block */
    memset(tag, 0, 16);
    G0_OKST(U(BCryptEncrypt)(k, zero, 16, &ai, NULL, 0, ct, 16, &cb, 0));
    EXPECT_EQ(cb, 16);
    G0_CHECK_HEX(ct, 16, "0388dace60b6a392f328c2b971b2fe78");
    G0_CHECK_HEX(tag, 16, "ab6e47d42cec13bdf53a67b21257bddf");
    G0_OKST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, back, 16, &cb, 0));
    CHECK(!memcmp(back, zero, 16));
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_gcm_tag_mismatch) {
    REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char iv[12] = {0}, tag[16], ct[16], out[16]; ULONG cb;
    G0_OKST(g0_gcm_open(&a)); G0_OKST(g0_aeskey(a, "00000000000000000000000000000000", &k));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = iv; ai.cbNonce = 12; ai.pbTag = tag; ai.cbTag = 16;
    g0_hex("0388dace60b6a392f328c2b971b2fe78", ct);
    g0_hex("ab6e47d42cec13bdf53a67b21257bddf", tag);
    G0_OKST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, out, 16, &cb, 0));
    tag[15] ^= 1;
    ST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, out, 16, &cb, 0), G0_AUTH_TAG_MISMATCH);
    tag[15] ^= 1; ct[0] ^= 0x80;
    ST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, out, 16, &cb, 0), G0_AUTH_TAG_MISMATCH);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_aes_gcm_aad_changes_tag) {
    REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptDecrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; unsigned char iv[12] = {1}, t1[16], t2[16], ct[16], pt[16] = "gcm plaintext!!", out[16]; ULONG cb;
    G0_OKST(g0_gcm_open(&a)); G0_OKST(g0_aeskey(a, K128, &k));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = iv; ai.cbNonce = 12; ai.pbTag = t1; ai.cbTag = 16;
    G0_OKST(U(BCryptEncrypt)(k, pt, 16, &ai, NULL, 0, ct, 16, &cb, 0));
    ai.pbAuthData = (PUCHAR)"hdr"; ai.cbAuthData = 3; ai.pbTag = t2;
    G0_OKST(U(BCryptEncrypt)(k, pt, 16, &ai, NULL, 0, ct, 16, &cb, 0));
    CHECK(memcmp(t1, t2, 16) != 0);
    G0_OKST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, out, 16, &cb, 0));
    CHECK(!memcmp(out, pt, 16));
    ai.cbAuthData = 2;
    ST(U(BCryptDecrypt)(k, ct, 16, &ai, NULL, 0, out, 16, &cb, 0), G0_AUTH_TAG_MISMATCH);
    U(BCryptDestroyKey)(k); g0_close(a);
}

/* ---- DuplicateKey / DestroyKey ------------------------------------------ */
TEST(gap0_duplicatekey_same_cipher_output) {
    REQUIRE(U(BCryptDuplicateKey)); REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k, k2 = NULL; unsigned char in[16] = {9}, o1[16], o2[16]; ULONG cb;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeECB")); G0_OKST(g0_aeskey(a, K128, &k));
    G0_OKST(U(BCryptDuplicateKey)(k, &k2, NULL, 0, 0));
    CHECK(k2 != NULL && k2 != k);
    G0_OKST(U(BCryptEncrypt)(k, in, 16, NULL, NULL, 0, o1, 16, &cb, 0));
    U(BCryptDestroyKey)(k);                                         /* the duplicate survives its source */
    G0_OKST(U(BCryptEncrypt)(k2, in, 16, NULL, NULL, 0, o2, 16, &cb, 0));
    CHECK(!memcmp(o1, o2, 16));
    U(BCryptDestroyKey)(k2); g0_close(a);
}
TEST(gap0_duplicatekey_caller_buffer_and_errors) {
    REQUIRE(U(BCryptDuplicateKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k, k2 = NULL; unsigned char obj[2048];
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    ST(U(BCryptDuplicateKey)(NULL, &k2, NULL, 0, 0), G0_INVALID_HANDLE);
    ST(U(BCryptDuplicateKey)(a, &k2, NULL, 0, 0), G0_INVALID_HANDLE);
    ST(U(BCryptDuplicateKey)(k, NULL, NULL, 0, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDuplicateKey)(k, &k2, NULL, 512, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDuplicateKey)(k, &k2, obj, 0x3d, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptDuplicateKey)(k, &k2, obj, 0, 0), G0_BUFFER_TOO_SMALL);
    CHECK(k2 == NULL);
    ULONG ol = g0_prop_u32(a, L"ObjectLength");
    PUCHAR o = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ol);
    G0_OKST(U(BCryptDuplicateKey)(k, &k2, o, ol, 0));
    U(BCryptDestroyKey)(k2); HeapFree(GetProcessHeap(), 0, o);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_duplicatekey_non_symmetric_alg_class_note) {
    REQUIRE(U(BCryptDuplicateKey)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL, k2 = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ST(U(BCryptDuplicateKey)(h, &k2, NULL, 0, 0), G0_INVALID_HANDLE);   /* hash handle: wrong object tag */
    U(BCryptDestroyHash)(h);
}

/* ---- ImportKey (KeyDataBlob) -------------------------------------------- */
static size_t g0_keyblob(unsigned char *out, const unsigned char *key, ULONG cb) {
    BCRYPT_KEY_DATA_BLOB_HEADER *h = (BCRYPT_KEY_DATA_BLOB_HEADER *)out;
    h->dwMagic = 0x4d42444b; h->dwVersion = 1; h->cbKeyData = cb; memcpy(out + sizeof *h, key, cb); return sizeof *h + cb;
}
TEST(gap0_importkey_keydatablob_matches_generate) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptEncrypt)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char key[16], blob[64], pt[16], ct[16]; ULONG cb;
    G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_setchain(a, L"ChainingModeECB"));
    g0_hex("000102030405060708090a0b0c0d0e0f", key); g0_hex("00112233445566778899aabbccddeeff", pt);
    size_t n = g0_keyblob(blob, key, 16);
    G0_OKST(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n, 0));
    G0_OKST(U(BCryptEncrypt)(k, pt, 16, NULL, NULL, 0, ct, 16, &cb, 0));
    G0_CHECK_HEX(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_importkey_export_roundtrip) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptExportKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL, k2 = NULL; unsigned char key[16], blob[64], out[64]; ULONG cb = 0;
    G0_OKST(g0_open(&a, L"AES", 0)); g0_hex(K128, key);
    G0_OKST(g0_aeskey(a, K128, &k));
    G0_OKST(U(BCryptExportKey)(k, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &cb, 0));
    EXPECT_EQ(cb, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 16);
    G0_OKST(U(BCryptExportKey)(k, NULL, BCRYPT_KEY_DATA_BLOB, out, sizeof out, &cb, 0));
    size_t n = g0_keyblob(blob, key, 16);
    CHECK(cb == n && !memcmp(out, blob, n));
    G0_OKST(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k2, NULL, 0, out, cb, 0));
    U(BCryptDestroyKey)(k); U(BCryptDestroyKey)(k2); g0_close(a);
}
TEST(gap0_importkey_argument_validation) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char key[16] = {0}, blob[64], obj[1024];
    G0_OKST(g0_open(&a, L"AES", 0));
    size_t n = g0_keyblob(blob, key, 16);
    ST(U(BCryptImportKey)(NULL, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n, 0), G0_INVALID_HANDLE);
    ST(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, NULL, NULL, 0, blob, (ULONG)n, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptImportKey)(a, NULL, NULL, &k, NULL, 0, blob, (ULONG)n, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 512, blob, (ULONG)n, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, obj, 0x3d, blob, (ULONG)n, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptImportKey)(a, a /* not a key */, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n, 0), G0_INVALID_HANDLE);
    CHECK(k == NULL);
    g0_close(a);
}
TEST(gap0_importkey_malformed_blob_rejected) {
    REQUIRE(U(BCryptImportKey)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char key[16] = {0}, blob[64];
    G0_OKST(g0_open(&a, L"AES", 0));
    size_t n = g0_keyblob(blob, key, 16);
    NTSTATUS s;
    s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n - 1, 0);   /* truncated */
    CHECKF(s < 0 && k == NULL, "truncated blob accepted: 0x%08lx", (unsigned long)s); t_note("truncated blob -> 0x%08lx", (unsigned long)s);
    ((BCRYPT_KEY_DATA_BLOB_HEADER *)blob)->dwMagic = 0x12345678;
    s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n, 0);       /* bad magic */
    CHECKF(s < 0 && k == NULL, "bad magic accepted: 0x%08lx", (unsigned long)s); t_note("bad magic -> 0x%08lx", (unsigned long)s);
    ((BCRYPT_KEY_DATA_BLOB_HEADER *)blob)->dwMagic = 0x4d42444b; ((BCRYPT_KEY_DATA_BLOB_HEADER *)blob)->dwVersion = 2;
    s = U(BCryptImportKey)(a, NULL, BCRYPT_KEY_DATA_BLOB, &k, NULL, 0, blob, (ULONG)n, 0);       /* bad version */
    CHECKF(s < 0 && k == NULL, "bad version accepted: 0x%08lx", (unsigned long)s); t_note("bad version -> 0x%08lx", (unsigned long)s);
    s = U(BCryptImportKey)(a, NULL, L"NoSuchBlobType", &k, NULL, 0, blob, (ULONG)n, 0);
    CHECKF(s < 0 && k == NULL, "unknown blob type accepted: 0x%08lx", (unsigned long)s); t_note("unknown blob type -> 0x%08lx", (unsigned long)s);
    g0_close(a);
}
TEST(gap0_importkeypair_argument_validation) {
    REQUIRE(U(BCryptImportKeyPair)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; unsigned char blob[128] = {0};
    ST(U(BCryptImportKeyPair)(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, blob, sizeof blob, 0), G0_INVALID_HANDLE);
    if (g0_open(&a, L"ECDH_P256", 0) < 0) { t_skip("ECDH_P256 unavailable"); return; }
    ST(U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, blob, sizeof blob, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptImportKeyPair)(a, NULL, NULL, &k, blob, sizeof blob, 0), G0_INVALID_PARAMETER);
    NTSTATUS s = U(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, blob, sizeof blob, 0);
    CHECKF(s < 0 && k == NULL, "all-zero ECC blob accepted: 0x%08lx", (unsigned long)s); t_note("zero ECC blob -> 0x%08lx", (unsigned long)s);
    g0_close(a);
}

/* ---- GetProperty buffer protocol ----------------------------------------- */
TEST(gap0_getprop_argument_validation) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; ULONG v = 0, cb = 0; G0_OKST(g0_open(&a, L"AES", 0));
    ST(U(BCryptGetProperty)(a, NULL, (PUCHAR)&v, 4, &cb, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptGetProperty)(a, L"", (PUCHAR)&v, 4, &cb, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptGetProperty)(a, L"ObjectLength", (PUCHAR)&v, 4, NULL, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptGetProperty)(NULL, L"ObjectLength", (PUCHAR)&v, 4, &cb, 0), G0_INVALID_HANDLE);
    ST(U(BCryptGetProperty)(NULL, NULL, (PUCHAR)&v, 4, &cb, 0), G0_INVALID_PARAMETER);       /* property checked before handle */
    g0_close(a);
}
TEST(gap0_getprop_size_protocol) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; ULONG v = 0, cb = 0; wchar_t nm[16];
    G0_OKST(g0_open(&a, L"AES", 0));
    G0_OKST(U(BCryptGetProperty)(a, L"ObjectLength", NULL, 0, &cb, 0));          /* size query */
    EXPECT_EQ(cb, 4);
    cb = 0; ST(U(BCryptGetProperty)(a, L"ObjectLength", (PUCHAR)&v, 3, &cb, 0), G0_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 4);
    cb = 0; G0_OKST(U(BCryptGetProperty)(a, L"ObjectLength", (PUCHAR)nm, sizeof nm, &cb, 0));
    EXPECT_EQ(cb, 4);
    cb = 0; G0_OKST(U(BCryptGetProperty)(a, L"AlgorithmName", NULL, 0, &cb, 0));
    EXPECT_EQ(cb, 8);
    cb = 0; ST(U(BCryptGetProperty)(a, L"AlgorithmName", (PUCHAR)nm, 7, &cb, 0), G0_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 8);
    cb = 0; G0_OKST(U(BCryptGetProperty)(a, L"AlgorithmName", (PUCHAR)nm, 8, &cb, 0));
    EXPECT_EQ(cb, 8); EXPECT_WSTR(nm, L"AES");
    g0_close(a);
}
TEST(gap0_getprop_unknown_property) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; ULONG v = 0, cb = 0; G0_OKST(g0_open(&a, L"AES", 0));
    ST(U(BCryptGetProperty)(a, L"NoSuchProperty", (PUCHAR)&v, 4, &cb, 0), G0_NOT_SUPPORTED);
    ST(U(BCryptGetProperty)(a, L"HashDigestLength", (PUCHAR)&v, 4, &cb, 0), G0_NOT_SUPPORTED);   /* hash-only property on a cipher */
    g0_close(a);
}
TEST(gap0_getprop_aes_algorithm_properties) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_LENGTHS_STRUCT kl = {0}; ULONG cb = 0; G0_OKST(g0_open(&a, L"AES", 0));
    EXPECT_EQ(g0_prop_u32(a, L"BlockLength"), 16);
    G0_OKST(U(BCryptGetProperty)(a, L"KeyLengths", (PUCHAR)&kl, sizeof kl, &cb, 0));
    EXPECT_EQ(cb, sizeof kl); EXPECT_EQ(kl.dwMinLength, 128); EXPECT_EQ(kl.dwMaxLength, 256); EXPECT_EQ(kl.dwIncrement, 64);
    g0_close(a);
}
TEST(gap0_getprop_symmetric_key_handle) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k; G0_OKST(g0_open(&a, L"AES", 0)); G0_OKST(g0_aeskey(a, K128, &k));
    ULONG kl = g0_prop_u32(k, L"KeyLength");
    ULONG bl = g0_prop_u32(k, L"BlockLength");
    t_note("key handle: KeyLength=%lu BlockLength=%lu", (unsigned long)kl, (unsigned long)bl);
    U(BCryptDestroyKey)(k); g0_close(a);
}
TEST(gap0_getprop_hash_handle) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL; G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ULONG v = g0_prop_u32(h, L"HashDigestLength");
    t_note("hash handle HashDigestLength=%lu", (unsigned long)v);
    U(BCryptDestroyHash)(h);
}
TEST(gap0_getprop_pseudo_handles) {
    REQUIRE(U(BCryptGetProperty));
    EXPECT_EQ(g0_prop_u32(G0_PH_SHA256, L"HashDigestLength"), 32);
    EXPECT_EQ(g0_prop_u32(G0_PH_SHA1, L"HashDigestLength"), 20);
    EXPECT_EQ(g0_prop_u32(G0_PH_SHA512, L"HashDigestLength"), 64);
    EXPECT_EQ(g0_prop_u32(G0_PH_MD5, L"HashDigestLength"), 16);
}
