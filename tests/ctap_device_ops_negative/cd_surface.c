#include "cd.h"
/* Export surface of the device-facing CTAP entry points, and self-checks of the fixture builders used by the
 * VerifyGetAssertion tests (these run without webauthn.dll so a broken fixture is caught before it blames the DLL). */

static const struct { const char *name; unsigned ord; } k_exp[] = {
    { "WebAuthNCtapChangeClientPin", 10 },
    { "WebAuthNCtapChangeClientPinForSelectedDevice", 11 },
    { "WebAuthNCtapGetAssertion", 13 },
    { "WebAuthNCtapMakeCredential", 17 },
    { "WebAuthNCtapResetDevice", 31 },
    { "WebAuthNCtapSendCommand", 35 },
    { "WebAuthNCtapSetClientPin", 36 },
    { "WebAuthNCtapVerifyGetAssertion", 39 },
};

TEST(ctapdev_surface_exports_resolve) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++) {
        FARPROC p = t_proc_in("webauthn.dll", k_exp[i].name);
        CHECKF(p != NULL, "%s", k_exp[i].name);
    }
}
TEST(ctapdev_surface_ordinals_match_names) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++) {
        FARPROC byname = t_proc_in("webauthn.dll", k_exp[i].name), byord = t_proc_ord("webauthn.dll", k_exp[i].ord);
        CHECKF(byname != NULL && byname == byord, "%s ordinal %u", k_exp[i].name, k_exp[i].ord);
    }
}
TEST(ctapdev_surface_exports_are_distinct) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++)
        for (size_t j = i + 1; j < sizeof k_exp / sizeof k_exp[0]; j++)
            CHECKF(t_proc_in("webauthn.dll", k_exp[i].name) != t_proc_in("webauthn.dll", k_exp[j].name), "%s vs %s", k_exp[i].name, k_exp[j].name);
}
TEST(ctapdev_surface_exports_inside_image) {
    REQUIRE(t_module("webauthn.dll"));
    HMODULE m = t_module("webauthn.dll");
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++) {
        BYTE *p = (BYTE *)t_proc_in("webauthn.dll", k_exp[i].name);
        CHECKF(p > (BYTE *)m && p < (BYTE *)m + 0x200000, "%s is not a forwarder (address inside image)", k_exp[i].name);
    }
}
TEST(ctapdev_surface_not_in_other_modules) {
    REQUIRE(t_module("webauthn.dll"));
    static const char *mods[] = { "ncrypt.dll", "bcrypt.dll", "kernel32.dll", "ntdll.dll" };
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++)
        for (size_t j = 0; j < 4; j++)
            CHECKF(t_proc_in(mods[j], k_exp[i].name) == NULL, "%s in %s", k_exp[i].name, mods[j]);
}
TEST(ctapdev_surface_getprocaddress_case_sensitive) {
    REQUIRE(t_module("webauthn.dll"));
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("webauthn.dll"), "webauthnctapsendcommand") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(t_module("webauthn.dll"), "WebAuthNCtapSendCommandW") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(ctapdev_surface_no_ansi_wide_variants) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < sizeof k_exp / sizeof k_exp[0]; i++) {
        char n[96];
        snprintf(n, sizeof n, "%sA", k_exp[i].name); CHECKF(t_proc_in("webauthn.dll", n) == NULL, "%s", n);
        snprintf(n, sizeof n, "%sW", k_exp[i].name); CHECKF(t_proc_in("webauthn.dll", n) == NULL, "%s", n);
    }
}

/* ---- fixture self-checks (no DUT needed) ---- */
TEST(ctapdev_fixture_sha256_known_answer) {
    CD_NEED_CRYPTO();
    static const BYTE abc[32] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
                                  0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    BYTE h[32]; cd_sha256("abc", 3, h); CHECK(!memcmp(h, abc, 32));
    static const BYTE empty[32] = { 0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
                                    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
    cd_sha256("", 0, h); CHECK(!memcmp(h, empty, 32));
}
TEST(ctapdev_fixture_rp_hash_is_utf8) {
    CD_NEED_CRYPTO();
    BYTE a[32], b[32];
    cd_rp_hash(L"example.com", a); cd_sha256("example.com", 11, b); CHECK(!memcmp(a, b, 32));
    cd_rp_hash(L"bücher.example", a); cd_sha256("b\xc3\xbc" "cher.example", 15, b); CHECK(!memcmp(a, b, 32));
}
TEST(ctapdev_fixture_sign_verify_roundtrip) {
    CD_NEED_CRYPTO();
    cd_key k; if (!cd_key_gen(&k)) { t_skip("P-256 key generation unavailable"); return; }
    BYTE sig[64]; const BYTE msg[] = "message";
    CHECK(cd_sign_raw(&k, msg, 7, sig));
    CHECK(cd_verify_raw(&k, msg, 7, sig));
    sig[63] ^= 1; CHECK(!cd_verify_raw(&k, msg, 7, sig));
    cd_key_free(&k);
}
TEST(ctapdev_fixture_der_shapes) {
    CD_NEED_CRYPTO();
    BYTE raw[64], der[80];
    memset(raw, 0x11, 64); ULONG n = cd_der_from_raw(raw, der);
    CHECK(n == 2 + 34 + 34 - 0 || n == 70); CHECK(der[0] == 0x30 && der[1] == n - 2 && der[2] == 2 && der[3] == 32);
    memset(raw, 0xF0, 64); n = cd_der_from_raw(raw, der);   /* high bit set: both integers get a 0x00 pad */
    CHECK(n == 72 && der[3] == 33 && der[4] == 0);
    memset(raw, 0, 64); raw[31] = 1; raw[63] = 2; n = cd_der_from_raw(raw, der);  /* leading zeros stripped */
    CHECK(n == 8 && !memcmp(der, "\x30\x06\x02\x01\x01\x02\x01\x02", 8));
}
TEST(ctapdev_fixture_cose_key_encoding) {
    BYTE x[32], y[32], c[100]; memset(x, 1, 32); memset(y, 2, 32);
    ULONG n = cd_cose_es256(c, x, y);
    CHECK(n == 77);
    CHECK(!memcmp(c, "\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20", 10));
    CHECK(c[42] == 0x22 && c[43] == 0x58 && c[44] == 0x20 && c[45] == 2 && c[76] == 2);
}
TEST(ctapdev_fixture_vector_is_self_consistent) {
    CD_NEED_CRYPTO();
    cd_key k; if (!cd_key_gen(&k)) { t_skip("P-256 key generation unavailable"); return; }
    cd_vec v; cd_vec_init(&v, &k, L"example.com", 0x05, 7, "{\"type\":\"webauthn.get\"}");
    CHECK(v.aaLen == 37 && v.aa[32] == 0x05 && v.aa[36] == 7);
    CHECK(v.caLen == 32 + 1 + 4 + 16 + 2 + 16 + 77);
    BYTE msg[69], raw[64];
    memcpy(msg, v.aa, 37); memcpy(msg + 37, v.chash, 32);
    /* decode our DER back to P1363 and verify with the key */
    CHECK(v.sig[0] == 0x30 && v.sig[1] == v.sigLen - 2);
    const BYTE *p = v.sig + 2; memset(raw, 0, 64);
    ULONG rl = p[1]; const BYTE *r = p + 2; if (rl == 33) { r++; rl--; }
    memcpy(raw + 32 - rl, r, rl);
    p = p + 2 + p[1]; ULONG sl = p[1]; const BYTE *s = p + 2; if (sl == 33) { s++; sl--; }
    memcpy(raw + 64 - sl, s, sl);
    CHECK(cd_verify_raw(&k, msg, 69, raw));
    cd_key_free(&k);
}
