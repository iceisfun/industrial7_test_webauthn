#include "gap0.h"

typedef struct { const wchar_t *id; ULONG dlen, blen; const char *empty, *abc; } g0_halg;
static const g0_halg g0_halgs[] = {
    { L"MD5",    16,  64, "d41d8cd98f00b204e9800998ecf8427e", "900150983cd24fb0d6963f7d28e17f72" },
    { L"SHA1",   20,  64, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { L"SHA256", 32,  64, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { L"SHA384", 48, 128, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
    { L"SHA512", 64, 128, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
};
#define G0_NH (sizeof g0_halgs / sizeof *g0_halgs)

TEST(gap0_hash_kat_empty_and_abc) {
    REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    for (size_t i = 0; i < G0_NH; i++) {
        BCRYPT_ALG_HANDLE a; unsigned char d[64];
        G0_OKST(g0_open(&a, g0_halgs[i].id, 0));
        G0_OKST(g0_hash(a, NULL, 0, NULL, 0, d, g0_halgs[i].dlen));
        (void)0;
        CHECK(g0_eqhex(d, g0_halgs[i].dlen, g0_halgs[i].empty));
        G0_OKST(g0_hash(a, NULL, 0, "abc", 3, d, g0_halgs[i].dlen));
        CHECK(g0_eqhex(d, g0_halgs[i].dlen, g0_halgs[i].abc));
        g0_close(a);
    }
}
TEST(gap0_hash_properties_match_algorithm) {
    REQUIRE(U(BCryptGetProperty)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    for (size_t i = 0; i < G0_NH; i++) {
        BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, g0_halgs[i].id, 0));
        EXPECT_EQ(g0_prop_u32(a, L"HashDigestLength"), g0_halgs[i].dlen);
        EXPECT_EQ(g0_prop_u32(a, L"HashBlockLength"), g0_halgs[i].blen);
        CHECK(g0_prop_u32(a, L"ObjectLength") >= 0x46);   /* CreateHash refuses smaller caller buffers */
        wchar_t nm[32] = {0}; ULONG cb = 0;
        G0_OKST(U(BCryptGetProperty)(a, L"AlgorithmName", (PUCHAR)nm, sizeof nm, &cb, 0));
        EXPECT_EQ(cb, (lstrlenW(g0_halgs[i].id) + 1) * 2);
        EXPECT_WSTR(nm, g0_halgs[i].id);
        g0_close(a);
    }
}
TEST(gap0_hash_pseudo_handles) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_ALG_HANDLE ph[] = { G0_PH_MD5, G0_PH_SHA1, G0_PH_SHA256, G0_PH_SHA384, G0_PH_SHA512 };
    for (size_t i = 0; i < G0_NH; i++) {
        unsigned char d[64];
        G0_OKST(g0_hash(ph[i], NULL, 0, "abc", 3, d, g0_halgs[i].dlen));
        CHECK(g0_eqhex(d, g0_halgs[i].dlen, g0_halgs[i].abc));
    }
}
TEST(gap0_hash_sha1_two_block_vector) {
    REQUIRE(U(BCryptCreateHash));
    unsigned char d[20];
    G0_OKST(g0_hash(G0_PH_SHA1, NULL, 0, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d, 20));
    G0_CHECK_HEX(d, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}
TEST(gap0_hash_million_a_chunked) {
    REQUIRE(U(BCryptCreateHash));
    static const struct { BCRYPT_ALG_HANDLE h; ULONG n; const char *hex; } v[] = {
        { G0_PH_MD5, 16, "7707d6ae4e027c70eea2a935c2296f21" },
        { G0_PH_SHA1, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
        { G0_PH_SHA256, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" },
    };
    static unsigned char chunk[1000];
    memset(chunk, 'a', sizeof chunk);
    for (int k = 0; k < 3; k++) {
        BCRYPT_HASH_HANDLE h = NULL; unsigned char d[32];
        G0_OKST(U(BCryptCreateHash)(v[k].h, &h, NULL, 0, NULL, 0, 0));
        for (int i = 0; i < 1000; i++) G0_OKST(U(BCryptHashData)(h, chunk, sizeof chunk, 0));
        G0_OKST(U(BCryptFinishHash)(h, d, v[k].n, 0));
        CHECK(g0_eqhex(d, v[k].n, v[k].hex));
        G0_OKST(U(BCryptDestroyHash)(h));
    }
}
TEST(gap0_hash_incremental_equals_oneshot) {
    REQUIRE(U(BCryptCreateHash));
    unsigned char msg[300], d1[32], d2[32];
    for (int i = 0; i < 300; i++) msg[i] = (unsigned char)(i * 7 + 1);
    G0_OKST(g0_hash(G0_PH_SHA256, NULL, 0, msg, 300, d1, 32));
    static const int splits[] = {1, 2, 3, 55, 56, 63, 64, 65, 127, 128, 129, 299};
    for (size_t s = 0; s < sizeof splits / sizeof *splits; s++) {
        BCRYPT_HASH_HANDLE h = NULL;
        G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
        G0_OKST(U(BCryptHashData)(h, msg, splits[s], 0));
        G0_OKST(U(BCryptHashData)(h, msg + splits[s], 300 - splits[s], 0));
        G0_OKST(U(BCryptFinishHash)(h, d2, 32, 0));
        CHECK(!memcmp(d1, d2, 32));
        U(BCryptDestroyHash)(h);
    }
}
TEST(gap0_hash_zero_length_hashdata) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL; unsigned char d[32];
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"x", 0, 0));
    G0_OKST(U(BCryptFinishHash)(h, d, 32, 0));
    CHECK(g0_eqhex(d, 32, g0_halgs[2].empty));
    U(BCryptDestroyHash)(h);
}

/* HMAC ------------------------------------------------------------------ */
TEST(gap0_hmac_rfc_vectors) {
    REQUIRE(U(BCryptCreateHash));
    static const struct { const wchar_t *id; ULONG n; const char *key; ULONG klen; const char *data; const char *hex; } v[] = {
        { L"MD5",    16, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d" },
        { L"MD5",    16, "Jefe", 4, "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738" },
        { L"SHA1",   20, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00" },
        { L"SHA1",   20, "Jefe", 4, "what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" },
        { L"SHA256", 32, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, "Hi There",
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
        { L"SHA256", 32, "Jefe", 4, "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
        { L"SHA384", 48, "Jefe", 4, "what do ya want for nothing?",
          "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" },
        { L"SHA512", 64, "Jefe", 4, "what do ya want for nothing?",
          "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" },
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        BCRYPT_ALG_HANDLE a; unsigned char d[64];
        G0_OKST(g0_open(&a, v[i].id, G0_ALG_HMAC));
        G0_OKST(g0_hash(a, v[i].key, v[i].klen, v[i].data, (ULONG)strlen(v[i].data), d, v[i].n));
        CHECK(g0_eqhex(d, v[i].n, v[i].hex));
        g0_close(a);
    }
}
TEST(gap0_hmac_key_longer_than_block) {
    REQUIRE(U(BCryptCreateHash));
    unsigned char key[131], d[32]; memset(key, 0xaa, sizeof key);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
    G0_OKST(g0_hash(a, key, sizeof key, m, (ULONG)strlen(m), d, 32));
    G0_CHECK_HEX(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    g0_close(a);
}
TEST(gap0_hmac_pseudo_handle) {
    REQUIRE(U(BCryptCreateHash));
    /* BCRYPT_HMAC_SHA256_ALG_HANDLE */
    unsigned char d[32];
    G0_OKST(g0_hash((BCRYPT_ALG_HANDLE)(ULONG_PTR)0xb1, "Jefe", 4, "what do ya want for nothing?", 28, d, 32));
    G0_CHECK_HEX(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}
TEST(gap0_hmac_different_keys_differ) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_ALG_HANDLE a; unsigned char d1[32], d2[32], d3[32];
    G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    G0_OKST(g0_hash(a, "k1", 2, "m", 1, d1, 32));
    G0_OKST(g0_hash(a, "k2", 2, "m", 1, d2, 32));
    G0_OKST(g0_hash(a, "k1", 2, "m", 1, d3, 32));
    CHECK(memcmp(d1, d2, 32) != 0); CHECK(!memcmp(d1, d3, 32));
    g0_close(a);
}

/* CreateHash argument protocol (decomp-verified order) -------------------- */
TEST(gap0_createhash_invalid_alg_handle) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)1;
    ST(U(BCryptCreateHash)(NULL, &h, NULL, 0, NULL, 0, 0), G0_INVALID_HANDLE);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)1);
}
TEST(gap0_createhash_null_phhash) {
    REQUIRE(U(BCryptCreateHash));
    ST(U(BCryptCreateHash)(G0_PH_SHA256, NULL, NULL, 0, NULL, 0, 0), G0_INVALID_PARAMETER);
    unsigned char obj[512];
    ST(U(BCryptCreateHash)(G0_PH_SHA256, NULL, obj, sizeof obj, NULL, 0, 0), G0_INVALID_PARAMETER);
}
TEST(gap0_createhash_object_buffer_too_small) {
    REQUIRE(U(BCryptCreateHash));
    unsigned char obj[512]; BCRYPT_HASH_HANDLE h = NULL;
    static const ULONG small[] = {1, 16, 0x28, 0x45};
    for (size_t i = 0; i < 4; i++) ST(U(BCryptCreateHash)(G0_PH_SHA256, &h, obj, small[i], NULL, 0, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptCreateHash)(G0_PH_SHA256, &h, obj, 0, NULL, 0, 0), G0_BUFFER_TOO_SMALL);
    CHECK(h == NULL);
}
TEST(gap0_createhash_null_object_nonzero_size) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL;
    ST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 512, NULL, 0, 0), G0_INVALID_PARAMETER);
}
TEST(gap0_createhash_caller_supplied_object) {
    REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", 0));
    ULONG ol = g0_prop_u32(a, L"ObjectLength");
    CHECK(ol >= 0x46);
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ol);
    BCRYPT_HASH_HANDLE h = NULL; unsigned char d[32];
    G0_OKST(U(BCryptCreateHash)(a, &h, obj, ol, NULL, 0, 0));
    CHECK(h != NULL);
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    G0_OKST(U(BCryptFinishHash)(h, d, 32, 0));
    CHECK(g0_eqhex(d, 32, g0_halgs[2].abc));
    G0_OKST(U(BCryptDestroyHash)(h));
    HeapFree(GetProcessHeap(), 0, obj);
    g0_close(a);
}
TEST(gap0_createhash_non_hash_algorithm) {
    REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    static const wchar_t *ids[] = {L"AES", L"RNG", L"RSA", L"ECDH_P256"};
    for (int i = 0; i < 4; i++) {
        BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL; unsigned char obj[2048];
        if (g0_open(&a, ids[i], 0) < 0) continue;
        ST(U(BCryptCreateHash)(a, &h, obj, sizeof obj, NULL, 0, 0), G0_NOT_SUPPORTED);
        g0_close(a);
    }
}
TEST(gap0_createhash_key_handle_as_algorithm) {
    REQUIRE(U(BCryptCreateHash)); REQUIRE(U(BCryptGenerateSymmetricKey));
    BCRYPT_ALG_HANDLE a; BCRYPT_KEY_HANDLE k = NULL; BCRYPT_HASH_HANDLE h = NULL; unsigned char key[16] = {0};
    G0_OKST(g0_open(&a, L"AES", 0));
    G0_OKST(U(BCryptGenerateSymmetricKey)(a, &k, NULL, 0, key, 16, 0));
    ST(U(BCryptCreateHash)(k, &h, NULL, 0, NULL, 0, 0), G0_INVALID_HANDLE);
    U(BCryptDestroyKey)(k); g0_close(a);
}

/* HashData / FinishHash / DestroyHash invalid handles --------------------- */
TEST(gap0_hashdata_invalid_handles) {
    REQUIRE(U(BCryptHashData));
    ST(U(BCryptHashData)(NULL, (PUCHAR)"a", 1, 0), G0_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a;   /* an algorithm handle is not a hash handle: wrong object tag */
    G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptHashData)(a, (PUCHAR)"a", 1, 0), G0_INVALID_HANDLE);
    g0_close(a);
}
TEST(gap0_finishhash_invalid_handles) {
    REQUIRE(U(BCryptFinishHash));
    unsigned char d[32];
    ST(U(BCryptFinishHash)(NULL, d, 32, 0), G0_INVALID_HANDLE);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptFinishHash)(a, d, 32, 0), G0_INVALID_HANDLE);
    g0_close(a);
}
TEST(gap0_destroyhash_invalid_handle_is_invalid_parameter) {
    REQUIRE(U(BCryptDestroyHash));
    /* unlike HashData/FinishHash/DuplicateHash, DestroyHash reports STATUS_INVALID_PARAMETER */
    ST(U(BCryptDestroyHash)(NULL), G0_INVALID_PARAMETER);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptDestroyHash)(a), G0_INVALID_PARAMETER);
    g0_close(a);
}
TEST(gap0_destroyhash_succeeds_with_unfinished_hash) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"partial", 7, 0));
    G0_OKST(U(BCryptDestroyHash)(h));
}
TEST(gap0_hash_alg_close_after_hash_destroy) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(g0_open(&a, L"SHA256", 0));
    G0_OKST(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0));
    /* the algorithm object is reference counted by live hash objects; the hash keeps working */
    g0_close(a);
    unsigned char d[32];
    NTSTATUS st = U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0);
    t_note("HashData after CloseAlgorithmProvider with live hash: 0x%08lx", (unsigned long)st);
    if (st == 0) { G0_OKST(U(BCryptFinishHash)(h, d, 32, 0)); CHECK(g0_eqhex(d, 32, g0_halgs[2].abc)); }
    U(BCryptDestroyHash)(h);
}
TEST(gap0_finishhash_wrong_output_size_note) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL; unsigned char d[64];
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    NTSTATUS st1 = U(BCryptFinishHash)(h, d, 31, 0);
    NTSTATUS st2 = U(BCryptFinishHash)(h, d, 33, 0);
    t_note("FinishHash cb=31 -> 0x%08lx, cb=33 -> 0x%08lx", (unsigned long)st1, (unsigned long)st2);
    U(BCryptDestroyHash)(h);
}
TEST(gap0_hash_reuse_after_finish_note) {
    REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL; unsigned char d[32], e[32];
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    G0_OKST(U(BCryptFinishHash)(h, d, 32, 0));
    NTSTATUS a = U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0);
    t_note("HashData after Finish: 0x%08lx", (unsigned long)a);
    NTSTATUS b = U(BCryptFinishHash)(h, e, 32, 0);
    t_note("second Finish: 0x%08lx", (unsigned long)b);
    U(BCryptDestroyHash)(h);
}

/* DuplicateHash --------------------------------------------------------- */
TEST(gap0_duplicatehash_diverges_independently) {
    REQUIRE(U(BCryptDuplicateHash)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL, h2 = NULL; unsigned char d1[32], d2[32];
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"a", 1, 0));
    G0_OKST(U(BCryptDuplicateHash)(h, &h2, NULL, 0, 0));
    CHECK(h2 != NULL && h2 != h);
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"bc", 2, 0));       /* "abc" */
    G0_OKST(U(BCryptHashData)(h2, (PUCHAR)"bd", 2, 0));      /* "abd" */
    G0_OKST(U(BCryptFinishHash)(h, d1, 32, 0));
    G0_OKST(U(BCryptFinishHash)(h2, d2, 32, 0));
    CHECK(g0_eqhex(d1, 32, g0_halgs[2].abc));
    CHECK(memcmp(d1, d2, 32) != 0);
    G0_OKST(g0_hash(G0_PH_SHA256, NULL, 0, "abd", 3, d1, 32));
    CHECK(!memcmp(d1, d2, 32));
    U(BCryptDestroyHash)(h); U(BCryptDestroyHash)(h2);
}
TEST(gap0_duplicatehash_hmac) {
    REQUIRE(U(BCryptDuplicateHash)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL, h2 = NULL; unsigned char d[32];
    G0_OKST(g0_open(&a, L"SHA256", G0_ALG_HMAC));
    G0_OKST(U(BCryptCreateHash)(a, &h, NULL, 0, (PUCHAR)"Jefe", 4, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"what do ya want ", 16, 0));
    G0_OKST(U(BCryptDuplicateHash)(h, &h2, NULL, 0, 0));
    U(BCryptDestroyHash)(h);                                   /* the duplicate is independent of the source */
    G0_OKST(U(BCryptHashData)(h2, (PUCHAR)"for nothing?", 12, 0));
    G0_OKST(U(BCryptFinishHash)(h2, d, 32, 0));
    G0_CHECK_HEX(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    U(BCryptDestroyHash)(h2); g0_close(a);
}
TEST(gap0_duplicatehash_errors) {
    REQUIRE(U(BCryptDuplicateHash)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_HASH_HANDLE h = NULL, h2 = NULL; unsigned char obj[2048];
    ST(U(BCryptDuplicateHash)(NULL, &h2, NULL, 0, 0), G0_INVALID_HANDLE);
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ST(U(BCryptDuplicateHash)(h, NULL, NULL, 0, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptDuplicateHash)(h, &h2, NULL, 512, 0), G0_INVALID_PARAMETER);       /* size without buffer */
    ST(U(BCryptDuplicateHash)(h, &h2, obj, 0x45, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptDuplicateHash)(h, &h2, obj, 0, 0), G0_BUFFER_TOO_SMALL);
    CHECK(h2 == NULL);
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptDuplicateHash)(a, &h2, NULL, 0, 0), G0_INVALID_HANDLE);
    g0_close(a);
    U(BCryptDestroyHash)(h);
}
TEST(gap0_duplicatehash_caller_buffer) {
    REQUIRE(U(BCryptDuplicateHash)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_ALG_HANDLE a; G0_OKST(g0_open(&a, L"SHA256", 0));
    ULONG ol = g0_prop_u32(a, L"ObjectLength");
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ol);
    BCRYPT_HASH_HANDLE h = NULL, h2 = NULL; unsigned char d[32];
    G0_OKST(U(BCryptCreateHash)(a, &h, NULL, 0, NULL, 0, 0));
    G0_OKST(U(BCryptHashData)(h, (PUCHAR)"abc", 3, 0));
    G0_OKST(U(BCryptDuplicateHash)(h, &h2, obj, ol, 0));
    G0_OKST(U(BCryptFinishHash)(h2, d, 32, 0));
    CHECK(g0_eqhex(d, 32, g0_halgs[2].abc));
    U(BCryptDestroyHash)(h2); U(BCryptDestroyHash)(h);
    HeapFree(GetProcessHeap(), 0, obj); g0_close(a);
}

/* Multi-hash -------------------------------------------------------------- */
TEST(gap0_multihash_invalid_alg_handle) {
    REQUIRE(U(BCryptCreateMultiHash));
    BCRYPT_HASH_HANDLE h = NULL;
    ST(U(BCryptCreateMultiHash)(NULL, &h, 2, NULL, 0, NULL, 0, 0), G0_INVALID_HANDLE);
}
TEST(gap0_multihash_zero_count) {
    REQUIRE(U(BCryptCreateMultiHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptCreateMultiHash)(a, &h, 0, NULL, 0, NULL, 0, 0), G0_INVALID_PARAMETER);
    g0_close(a);
}
TEST(gap0_multihash_requires_multi_flag_provider) {
    REQUIRE(U(BCryptCreateMultiHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL; static unsigned char obj[8192];
    G0_OKST(g0_open(&a, L"SHA256", 0));
    /* an algorithm handle opened without BCRYPT_MULTI_FLAG exposes no multi-hash capability */
    ST(U(BCryptCreateMultiHash)(a, &h, 2, obj, sizeof obj, NULL, 0, 0), G0_NOT_SUPPORTED);
    g0_close(a);
}
TEST(gap0_multihash_small_object_buffer) {
    REQUIRE(U(BCryptCreateMultiHash)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL; unsigned char obj[64];
    G0_OKST(g0_open(&a, L"SHA256", 0));
    ST(U(BCryptCreateMultiHash)(a, &h, 2, obj, 0x45, NULL, 0, 0), G0_BUFFER_TOO_SMALL);
    ST(U(BCryptCreateMultiHash)(a, NULL, 2, obj, sizeof obj, NULL, 0, 0), G0_INVALID_PARAMETER);
    g0_close(a);
}
TEST(gap0_multihash_process_invalid_handles) {
    REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptCreateHash));
    BCRYPT_MULTI_HASH_OPERATION op = {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3};
    ST(U(BCryptProcessMultiOperations)(NULL, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), G0_INVALID_HANDLE);
    /* an ordinary (single) hash object has no multi-hash support */
    BCRYPT_HASH_HANDLE h = NULL;
    G0_OKST(U(BCryptCreateHash)(G0_PH_SHA256, &h, NULL, 0, NULL, 0, 0));
    ST(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), G0_INVALID_HANDLE);
    U(BCryptDestroyHash)(h);
}
TEST(gap0_multihash_roundtrip_if_supported) {
    REQUIRE(U(BCryptCreateMultiHash)); REQUIRE(U(BCryptProcessMultiOperations)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = g0_open(&a, L"SHA256", 0x20 /* BCRYPT_MULTI_FLAG */);
    if (st < 0) { t_skip("SHA256 with multi flag unavailable: 0x%08lx", (unsigned long)st); return; }
    BCRYPT_MULTI_OBJECT_LENGTH_STRUCT ml = {0}; ULONG cb = 0;
    st = U(BCryptGetProperty)(a, L"MultiObjectLength", (PUCHAR)&ml, sizeof ml, &cb, 0);
    t_note("MultiObjectLength st=0x%08lx perObject=%lu perElement=%lu", (unsigned long)st, ml.cbPerObject, ml.cbPerElement);
    if (st < 0) { g0_close(a); t_skip("no MultiObjectLength"); return; }
    ULONG need = ml.cbPerObject + 2 * ml.cbPerElement + 64;
    PUCHAR obj = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, need);
    st = U(BCryptCreateMultiHash)(a, &h, 2, obj, need, NULL, 0, 0);
    t_note("CreateMultiHash -> 0x%08lx", (unsigned long)st);
    if (st >= 0) {
        ST(U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, NULL, 0, 0), G0_INVALID_PARAMETER);
        unsigned char d0[32], d1[32];
        BCRYPT_MULTI_HASH_OPERATION ops[4] = {
            {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3},
            {1, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"", 0},
            {0, BCRYPT_HASH_OPERATION_FINISH_HASH, d0, 32},
            {1, BCRYPT_HASH_OPERATION_FINISH_HASH, d1, 32},
        };
        st = U(BCryptProcessMultiOperations)(h, BCRYPT_OPERATION_TYPE_HASH, ops, sizeof ops, 0);
        t_note("ProcessMultiOperations -> 0x%08lx", (unsigned long)st);
        if (st == 0) { CHECK(g0_eqhex(d0, 32, g0_halgs[2].abc)); CHECK(g0_eqhex(d1, 32, g0_halgs[2].empty)); }
        U(BCryptDestroyHash)(h);
    }
    HeapFree(GetProcessHeap(), 0, obj); g0_close(a);
}
