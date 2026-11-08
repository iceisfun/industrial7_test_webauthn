/* Per-key-type authenticator data (real COSE keys: ES256/384/512, RS256/384/512, PS256/384/512, RS1, ECDH256, EdDSA)
 * plus truncation / trailing-byte sweeps. All reads happen on a buffer that ends at a PAGE_NOACCESS page, so any
 * read past the supplied length faults.
 */
#include "acd.h"

/* sizes of the encoded keys, cross-checked against the CBOR layout */
TEST(ctap_authdata_cose_keys_encoded_sizes) {
    /* ES256: A5 | 01 02 | 03 26 | 20 01 | 21 58 20 x32 | 22 58 20 y32 = 1+2+2+2+(1+2+32)*2 */
    vec v; v_init(&v); mk_es256(&v);
    EXPECT_EQ(v.n, 1 + 2 + 2 + 2 + 2 * (1 + 2 + 32));
    EXPECT_EQ(v.p[0], 0xA5);
    v_free(&v);
    /* EdDSA: A4 | 01 01 | 03 27 | 20 06 | 21 58 20 x32 */
    v_init(&v); mk_eddsa(&v);
    EXPECT_EQ(v.n, 1 + 2 + 2 + 2 + (1 + 2 + 32));
    EXPECT_EQ(v.p[0], 0xA4);
    v_free(&v);
}

#define KEY_TESTS(NAME, IDX) \
TEST(ctap_authdata_cose_key_##NAME##_parse) { \
    NEED_ALL(); \
    vec v; ad_full(&v, ACD_AT | ACD_UP | ACD_UV, 0x01020304, IDX, 32, 0); \
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP | ACD_UV, 0x01020304, #NAME); \
    v_free(&v); \
} \
TEST(ctap_authdata_cose_key_##NAME##_credid) { \
    NEED_ALL(); \
    static const unsigned lens[] = { 1, 16, 32, 64, 255, 256 }; \
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) { \
        vec v; ad_full(&v, ACD_AT | ACD_UP, 9, IDX, lens[i], 0); \
        cres r = acd_credid(v.p, v.n); \
        EXPECT_EQ(HRV(r.hr), 0); EXPECT_EQ(r.cb, lens[i]); EXPECT_EQ(r.off, 55); \
        BYTE exp[256]; cred_fill(exp, lens[i], 0x40); \
        CHECK(r.off + r.cb <= v.n && memcmp(v.p + r.off, exp, lens[i]) == 0); \
        v_free(&v); \
    } \
} \
TEST(ctap_authdata_cose_key_##NAME##_with_extensions) { \
    NEED_ALL(); \
    vec v; ad_full(&v, ACD_AT | ACD_ED | ACD_UP, 0x42, IDX, 20, 1); \
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_ED | ACD_UP, 0x42, #NAME); \
    cres r = acd_credid(v.p, v.n); \
    EXPECT_EQ(HRV(r.hr), 0); EXPECT_EQ(r.cb, 20); EXPECT_EQ(r.off, 55); \
    v_free(&v); \
} \
TEST(ctap_authdata_cose_key_##NAME##_truncation_sweep) { \
    NEED_ALL(); \
    vec v; ad_full(&v, ACD_AT | ACD_UP, 0x42, IDX, 24, 0); \
    for (size_t n = 0; n < v.n; n++) { expect_parse_fail(v.p, n, "truncated parse"); if (n) expect_cred_fail(v.p, n, "truncated credid"); } \
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP, 0x42, "full"); \
    v_free(&v); \
} \
TEST(ctap_authdata_cose_key_##NAME##_trailing_sweep) { \
    NEED_ALL(); \
    vec v; ad_full(&v, ACD_AT | ACD_UP, 0x42, IDX, 24, 0); \
    size_t full = v.n; \
    for (int extra = 1; extra <= 6; extra++) { v_u8(&v, 0xFF - extra); expect_parse_fail(v.p, v.n, "trailing"); expect_cred_fail(v.p, v.n, "trailing credid"); } \
    v.n = full; \
    v.p[32] |= ACD_ED;          /* with ED the same trailing bytes are extension data */ \
    for (int extra = 1; extra <= 6; extra++) { v_u8(&v, 0xFF - extra); expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP | ACD_ED, 0x42, "trailing with ED"); } \
    v_free(&v); \
} \
TEST(ctap_authdata_cose_key_##NAME##_truncation_sweep_with_ed) { \
    NEED_ALL(); \
    vec v; ad_full(&v, ACD_AT | ACD_ED, 0x42, IDX, 24, 1); \
    size_t keyend = 55 + 24 + 0; { vec k; v_init(&k); KEYS[IDX].mk(&k); keyend += k.n; v_free(&k); } \
    /* ED: cutting inside the (unvalidated) extension block keeps succeeding, cutting inside the key fails */ \
    for (size_t n = 0; n < keyend; n++) expect_parse_fail(v.p, n, "cut inside header/credId/key"); \
    for (size_t n = keyend; n <= v.n; n++) expect_parse_ok(v.p, n, ACD_AT | ACD_ED, 0x42, "cut inside extensions"); \
    v_free(&v); \
}

KEY_TESTS(es256, K_ES256)
KEY_TESTS(es384, K_ES384)
KEY_TESTS(es512, K_ES512)
KEY_TESTS(rs256, K_RS256)
KEY_TESTS(rs384, K_RS384)
KEY_TESTS(rs512, K_RS512)
KEY_TESTS(ps256, K_PS256)
KEY_TESTS(ps384, K_PS384)
KEY_TESTS(ps512, K_PS512)
KEY_TESTS(rs1, K_RS1)
KEY_TESTS(ecdh256, K_ECDH)
KEY_TESTS(eddsa, K_EDDSA)

TEST(ctap_authdata_cose_keys_independent_of_alg_for_parse) {
    NEED_ALL();
    /* the parser does not look at kty/alg: every key flavour yields identical headers */
    for (int k = 0; k < NKEYS; k++) {
        vec v; ad_full(&v, ACD_AT | ACD_UP, 0xCAFEBABE, k, 32, 0);
        expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP, 0xCAFEBABE, KEYS[k].name);
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_keys_credid_offset_independent_of_key_type) {
    NEED_ALL();
    for (int k = 0; k < NKEYS; k++) {
        vec v; ad_full(&v, ACD_AT, 1, k, 77, 0);
        cres r = acd_credid(v.p, v.n);
        CHECKF(HRV(r.hr) == 0 && r.cb == 77 && r.off == 55, "key %s hr=%08lx cb=%lu off=%lu", KEYS[k].name, HRV(r.hr), r.cb, r.off);
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_keys_big_rsa_modulus_4096_bit) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 32, 32, 3); cose_rsa(&v, -257, 512);
    expect_parse_ok(v.p, v.n, ACD_AT, 1, "4096-bit RSA");
    v_free(&v);
}

TEST(ctap_authdata_cose_keys_small_rsa_modulus_1024_bit) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 32, 32, 3); cose_rsa(&v, -257, 128);
    expect_parse_ok(v.p, v.n, ACD_AT, 1, "1024-bit RSA");
    v_free(&v);
}

TEST(ctap_authdata_cose_keys_ec_with_wrong_coordinate_length_still_parses) {
    NEED_ALL();
    /* structural parser only: odd coordinate lengths are not its concern */
    static const size_t cl[] = { 0, 1, 31, 33, 48, 65, 66 };
    for (size_t i = 0; i < sizeof cl / sizeof cl[0]; i++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 16, 16, 3); cose_ec(&v, -7, 1, cl[i], 0);
        expect_parse_ok(v.p, v.n, ACD_AT, 1, "coordinate length");
        v_free(&v);
    }
}

/* Unaligned placement: the buffer start is shifted 0..7 bytes inside the guarded region. */
TEST(ctap_authdata_cose_keys_every_start_alignment) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_UP, 0x0A0B0C0D, K_ES256, 33, 0);
    for (size_t sh = 0; sh < 8; sh++) {
        gbuf g; BYTE *base = (BYTE *)g_place(&g, v.p, v.n);
        /* move down by sh bytes inside the committed page, leaving a gap before the guard: overlap is safe since memmove */
        BYTE *dst = base - sh; memmove(dst, v.p, v.n);
        BYTE fl = SENT_FL; DWORD sc = SENT_SC;
        HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)((DWORD)v.n, dst, &fl, &sc);
        EXPECT_EQ(HRV(hr), 0); EXPECT_EQ(fl, ACD_AT | ACD_UP); EXPECT_EQ(sc, 0x0A0B0C0D);
        DWORD cb = 0, off = 0;
        hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, dst, &cb, &off);
        EXPECT_EQ(HRV(hr), 0); EXPECT_EQ(cb, 33); EXPECT_EQ(off, 55);
        g_free(&g);
    }
    v_free(&v);
}

/* Hand assembled registration data: UP|AT, count 0, zero AAGUID, 16-byte id, ES256 key with the P-256 generator point. */
TEST(ctap_authdata_cose_keys_zero_aaguid_p256_generator_vector) {
    NEED_ALL();
    vec v; v_init(&v);
    ad_header(&v, ACD_UP | ACD_AT, 0);
    BYTE z[16] = { 0 }; v_put(&v, z, 16); v_be16(&v, 16);
    BYTE id[16]; for (int i = 0; i < 16; i++) id[i] = (BYTE)(0xC0 + i); v_put(&v, id, 16);
    v_hex(&v, "A5 01 02 03 26 20 01 21 58 20"); v_put(&v, P256_GX, 32);
    v_hex(&v, "22 58 20"); v_put(&v, P256_GY, 32);
    expect_parse_ok(v.p, v.n, 0x41, 0, "vector");
    cres r = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(r.hr), 0); EXPECT_EQ(r.cb, 16); EXPECT_EQ(r.off, 55);
    CHECK(r.off + 16 <= v.n && memcmp(v.p + r.off, id, 16) == 0);
    v_free(&v);
}

TEST(ctap_authdata_cose_assertion_style_no_at_buffers) {
    NEED_ALL();
    /* getAssertion authenticator data: 37 bytes, optionally with extensions */
    static const BYTE fl[] = { ACD_UP, ACD_UP | ACD_UV, ACD_UV, 0 };
    for (size_t i = 0; i < sizeof fl; i++) {
        vec v; v_init(&v); ad_header(&v, fl[i], 1000 + (DWORD)i);
        expect_parse_ok(v.p, v.n, fl[i], 1000 + (DWORD)i, "assertion adata");
        expect_cred_fail(v.p, v.n, "assertion adata has no credential");
        v_free(&v);
        v_init(&v); ad_header(&v, fl[i] | ACD_ED, 1000 + (DWORD)i); ext_valid(&v);
        expect_parse_ok(v.p, v.n, fl[i] | ACD_ED, 1000 + (DWORD)i, "assertion adata + ext");
        v_free(&v);
    }
}
