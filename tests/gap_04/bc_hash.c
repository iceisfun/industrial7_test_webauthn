#include "gap4.h"
/* BCryptHash: one-shot create / hash / finish / destroy. Known-answer vectors from the published hash and
 * HMAC test suites; error ordering from the CreateHash / HashData / FinishHash implementation. */

typedef struct { const wchar_t *alg; ULONG cb; const char *in; const char *hex; } kat;
static const kat kats[] = {
    { BCRYPT_MD5_ALGORITHM, 16, "", "d41d8cd98f00b204e9800998ecf8427e" },
    { BCRYPT_MD5_ALGORITHM, 16, "a", "0cc175b9c0f1b6a831c399e269772661" },
    { BCRYPT_MD5_ALGORITHM, 16, "abc", "900150983cd24fb0d6963f7d28e17f72" },
    { BCRYPT_MD5_ALGORITHM, 16, "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
    { BCRYPT_MD5_ALGORITHM, 16, "The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6" },
    { BCRYPT_SHA1_ALGORITHM, 20, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { BCRYPT_SHA1_ALGORITHM, 20, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { BCRYPT_SHA1_ALGORITHM, 20, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { BCRYPT_SHA1_ALGORITHM, 20, "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
    { BCRYPT_SHA256_ALGORITHM, 32, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { BCRYPT_SHA256_ALGORITHM, 32, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { BCRYPT_SHA256_ALGORITHM, 32, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    { BCRYPT_SHA256_ALGORITHM, 32, "The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" },
    { BCRYPT_SHA384_ALGORITHM, 48, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
    { BCRYPT_SHA384_ALGORITHM, 48, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
    { BCRYPT_SHA512_ALGORITHM, 64, "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
    { BCRYPT_SHA512_ALGORITHM, 64, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
};

static void run_kat(const kat *k)
{
    BCRYPT_ALG_HANDLE a = g4_open(k->alg, 0);
    if (!a) { CHECKF(0, "open %ls", k->alg); return; }
    BYTE out[64]; memset(out, 0xEE, sizeof out);
    char empty = 0;
    const char *in = k->in[0] ? k->in : &empty;
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, (PUCHAR)in, (ULONG)strlen(k->in), out, k->cb);
    t_check(s == 0, __FILE__, __LINE__, "BCryptHash == 0", "alg %ls in \"%s\" got 0x%lx", k->alg, k->in, (unsigned long)s);
    t_check(g4_hex(out, k->cb, k->hex), __FILE__, __LINE__, "digest matches", "alg %ls in \"%s\"", k->alg, k->in);
    /* nothing written past the digest */
    int over = 0;
    for (ULONG i = k->cb; i < sizeof out; i++) if (out[i] != 0xEE) over++;
    EXPECT_EQ(over, 0);
    g4_close(a);
}
#define KAT_TEST(i) TEST(gap4_hash_kat_##i) { if (!BC(BCryptHash)) { t_skip("missing export: BCryptHash"); return; } run_kat(&kats[i]); }
KAT_TEST(0) KAT_TEST(1) KAT_TEST(2) KAT_TEST(3) KAT_TEST(4) KAT_TEST(5) KAT_TEST(6) KAT_TEST(7) KAT_TEST(8)
KAT_TEST(9) KAT_TEST(10) KAT_TEST(11) KAT_TEST(12) KAT_TEST(13) KAT_TEST(14) KAT_TEST(15) KAT_TEST(16)

#define HREQ() do { if (!BC(BCryptHash)) { t_skip("missing export: BCryptHash"); return; } } while (0)

TEST(gap4_hash_null_input_zero_length) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BYTE out[32];
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, NULL, 0, out, 32);
    if (s == 0) CHECK(g4_hex(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    else t_note("NULL input with zero length -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
TEST(gap4_hash_million_a_sha256) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BYTE *m = (BYTE *)malloc(1000000); REQUIRE(m);
    memset(m, 'a', 1000000);
    BYTE out[32];
    EQC(BC(BCryptHash)(a, NULL, 0, m, 1000000, out, 32), 0);
    CHECK(g4_hex(out, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    free(m); g4_close(a);
}
TEST(gap4_hash_million_a_sha1) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA1_ALGORITHM, 0); REQUIRE(a);
    BYTE *m = (BYTE *)malloc(1000000); REQUIRE(m);
    memset(m, 'a', 1000000);
    BYTE out[20];
    EQC(BC(BCryptHash)(a, NULL, 0, m, 1000000, out, 20), 0);
    CHECK(g4_hex(out, 20, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    free(m); g4_close(a);
}
TEST(gap4_hash_million_a_md5) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_MD5_ALGORITHM, 0); REQUIRE(a);
    BYTE *m = (BYTE *)malloc(1000000); REQUIRE(m);
    memset(m, 'a', 1000000);
    BYTE out[16];
    EQC(BC(BCryptHash)(a, NULL, 0, m, 1000000, out, 16), 0);
    CHECK(g4_hex(out, 16, "7707d6ae4e027c70eea2a935c2296f21"));
    free(m); g4_close(a);
}
TEST(gap4_hash_block_boundary_lengths_agree_with_streaming) {
    HREQ();
    if (!BC(BCryptCreateHash) || !BC(BCryptHashData) || !BC(BCryptFinishHash)) { t_skip("missing hash exports"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BYTE data[300]; for (int i = 0; i < 300; i++) data[i] = (BYTE)(i * 7 + 3);
    static const ULONG lens[] = { 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 191, 192, 255, 256, 299 };
    int bad = 0;
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        BYTE one[32], two[32];
        if (BC(BCryptHash)(a, NULL, 0, data, lens[i], one, 32) != 0) { bad++; continue; }
        BCRYPT_HASH_HANDLE hh = NULL;
        if (BC(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0) != 0) { bad++; continue; }
        ULONG half = lens[i] / 2;
        BC(BCryptHashData)(hh, data, half, 0);
        BC(BCryptHashData)(hh, data + half, lens[i] - half, 0);
        if (BC(BCryptFinishHash)(hh, two, 32, 0) != 0) bad++;
        BC(BCryptDestroyHash)(hh);
        if (memcmp(one, two, 32)) bad++;
    }
    EXPECT_EQ(bad, 0);
    g4_close(a);
}
TEST(gap4_hash_deterministic_repeat) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA384_ALGORITHM, 0); REQUIRE(a);
    BYTE o1[48], o2[48];
    EQC(BC(BCryptHash)(a, NULL, 0, (PUCHAR)"repeat", 6, o1, 48), 0);
    EQC(BC(BCryptHash)(a, NULL, 0, (PUCHAR)"repeat", 6, o2, 48), 0);
    CHECK(!memcmp(o1, o2, 48));
    g4_close(a);
}

/* ---- HMAC (algorithm opened with BCRYPT_ALG_HANDLE_HMAC_FLAG, key passed as pbSecret) ---- */
TEST(gap4_hash_hmac_sha256_rfc4231_case1) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE key[20]; memset(key, 0x0b, 20);
    BYTE o[32];
    EQC(BC(BCryptHash)(a, key, 20, (PUCHAR)"Hi There", 8, o, 32), 0);
    CHECK(g4_hex(o, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    g4_close(a);
}
TEST(gap4_hash_hmac_sha256_fox) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE o[32];
    const char *m = "The quick brown fox jumps over the lazy dog";
    EQC(BC(BCryptHash)(a, (PUCHAR)"key", 3, (PUCHAR)m, (ULONG)strlen(m), o, 32), 0);
    CHECK(g4_hex(o, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
    g4_close(a);
}
TEST(gap4_hash_hmac_sha1_fox) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE o[20];
    const char *m = "The quick brown fox jumps over the lazy dog";
    EQC(BC(BCryptHash)(a, (PUCHAR)"key", 3, (PUCHAR)m, (ULONG)strlen(m), o, 20), 0);
    CHECK(g4_hex(o, 20, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"));
    g4_close(a);
}
TEST(gap4_hash_hmac_md5_fox) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_MD5_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE o[16];
    const char *m = "The quick brown fox jumps over the lazy dog";
    EQC(BC(BCryptHash)(a, (PUCHAR)"key", 3, (PUCHAR)m, (ULONG)strlen(m), o, 16), 0);
    CHECK(g4_hex(o, 16, "80070713463e7749b90c2dc24911e275"));
    g4_close(a);
}
TEST(gap4_hash_hmac_differs_with_key) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE o1[32], o2[32];
    EQC(BC(BCryptHash)(a, (PUCHAR)"k1", 2, (PUCHAR)"m", 1, o1, 32), 0);
    EQC(BC(BCryptHash)(a, (PUCHAR)"k2", 2, (PUCHAR)"m", 1, o2, 32), 0);
    CHECK(memcmp(o1, o2, 32) != 0);
    g4_close(a);
}
TEST(gap4_hash_hmac_long_key_is_hashed) {
    HREQ();
    /* keys longer than the block size are replaced by their hash: HMAC(K) == HMAC(H(K)) */
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_ALG_HANDLE p = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    REQUIRE(a); REQUIRE(p);
    BYTE key[100]; memset(key, 0xaa, sizeof key);
    BYTE hk[32], o1[32], o2[32];
    EQC(BC(BCryptHash)(p, NULL, 0, key, 100, hk, 32), 0);
    EQC(BC(BCryptHash)(a, key, 100, (PUCHAR)"msg", 3, o1, 32), 0);
    EQC(BC(BCryptHash)(a, hk, 32, (PUCHAR)"msg", 3, o2, 32), 0);
    CHECK(!memcmp(o1, o2, 32));
    g4_close(a); g4_close(p);
}

/* ---- pseudo handles (Windows 8+): low nibble 1 ---- */
#ifdef BCRYPT_SHA256_ALG_HANDLE
TEST(gap4_hash_pseudo_handle_sha256) {
    HREQ();
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, o, 32);
    EXPECT_EQ(s, 0);
    if (s == 0) CHECK(g4_hex(o, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}
TEST(gap4_hash_pseudo_handle_sha1_md5) {
    HREQ();
    BYTE o[20];
    NTSTATUS s = BC(BCryptHash)(BCRYPT_SHA1_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, o, 20);
    EXPECT_EQ(s, 0);
    if (s == 0) CHECK(g4_hex(o, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    BYTE m[16];
    s = BC(BCryptHash)(BCRYPT_MD5_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, m, 16);
    EXPECT_EQ(s, 0);
    if (s == 0) CHECK(g4_hex(m, 16, "900150983cd24fb0d6963f7d28e17f72"));
}
TEST(gap4_hash_pseudo_handle_hmac_sha256) {
    HREQ();
#ifdef BCRYPT_HMAC_SHA256_ALG_HANDLE
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(BCRYPT_HMAC_SHA256_ALG_HANDLE, (PUCHAR)"key", 3,
                                (PUCHAR)"The quick brown fox jumps over the lazy dog", 43, o, 32);
    EXPECT_EQ(s, 0);
    if (s == 0) CHECK(g4_hex(o, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));
#else
    t_skip("no HMAC pseudo handle in header");
#endif
}
#endif

/* ---- errors ---- */
TEST(gap4_hash_null_algorithm_handle) {
    HREQ();
    BYTE o[32];
    EQC(BC(BCryptHash)(NULL, NULL, 0, (PUCHAR)"abc", 3, o, 32), G4_INVALID_HANDLE);
}
TEST(gap4_hash_algorithm_class_not_hash_aes) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_AES_ALGORITHM, 0); REQUIRE(a);
    BYTE o[32];
    EQC(BC(BCryptHash)(a, NULL, 0, (PUCHAR)"abc", 3, o, 32), G4_NOT_SUPPORTED);
    g4_close(a);
}
TEST(gap4_hash_algorithm_class_not_hash_ecdsa) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, (PUCHAR)"abc", 3, o, 32); CHECK(s < 0); t_note("hash with ecdsa algorithm -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
TEST(gap4_hash_algorithm_class_not_hash_rsa) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, (PUCHAR)"abc", 3, o, 32); CHECK(s < 0); t_note("hash with rsa algorithm -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
TEST(gap4_hash_algorithm_handle_is_key_handle) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256);
    BYTE o[32];
    if (k) {
        EQC(BC(BCryptHash)(k, NULL, 0, (PUCHAR)"abc", 3, o, 32), G4_INVALID_HANDLE);
        BC(BCryptDestroyKey)(k);
    } else CHECKF(0, "key pair");
    g4_close(a);
}
static void bad_out_size(ULONG cb)
{
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0);
    if (!a) { CHECK(0); return; }
    BYTE o[128]; memset(o, 0xEE, sizeof o);
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, (PUCHAR)"abc", 3, o, cb);
    t_check(s < 0, __FILE__, __LINE__, "wrong output size fails", "cbOutput %lu got 0x%lx", (unsigned long)cb, (unsigned long)s);
    t_note("BCryptHash(SHA256) cbOutput=%lu -> 0x%lx", (unsigned long)cb, (unsigned long)s);
    g4_close(a);
}
TEST(gap4_hash_output_size_0) { HREQ(); bad_out_size(0); }
TEST(gap4_hash_output_size_31) { HREQ(); bad_out_size(31); }
TEST(gap4_hash_output_size_33) { HREQ(); bad_out_size(33); }
TEST(gap4_hash_output_size_64) { HREQ(); bad_out_size(64); }
TEST(gap4_hash_secret_on_non_hmac_algorithm) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(a, (PUCHAR)"key", 3, (PUCHAR)"abc", 3, o, 32);
    t_note("secret supplied for a non-HMAC algorithm -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
TEST(gap4_hash_hmac_without_secret) {
    HREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG); REQUIRE(a);
    BYTE o[32];
    NTSTATUS s = BC(BCryptHash)(a, NULL, 0, (PUCHAR)"abc", 3, o, 32);
    t_note("HMAC algorithm with no secret -> 0x%lx", (unsigned long)s);
    g4_close(a);
}
