/* WebAuthNGetCoseAlgorithmIdentifier(PCWSTR name, LONG *alg).
 * From the Windows 10 reference decompilation: the name is compared (exact, case sensitive, full string)
 * against an internal table of 11 algorithm names; on a match *alg receives the COSE algorithm number and
 * S_OK is returned. A NULL or unknown name returns NTE_NOT_SUPPORTED (0x80090029) and leaves *alg untouched.
 * Table: ES256 -7, RS256 -257, PS256 -37, RS384 -258, RS512 -259, PS384 -38, PS512 -39, ES384 -35,
 *        ES512 -36, RS1 -65535, ECDH256 -25.   ("EdDSA" is NOT in the table.)
 */
#include "acd.h"

#define SENT_ALG ((LONG)0x5EADBEEF)

static HRESULT alg_of(const wchar_t *name, LONG *out) {
    *out = SENT_ALG;
    return UN(WebAuthNGetCoseAlgorithmIdentifier)(name, out);
}

static void expect_alg(const wchar_t *name, LONG want) {
    LONG a;
    HRESULT hr = alg_of(name, &a);
    t_check(HRV(hr) == 0, __FILE__, __LINE__, "alg name", "hr=0x%08lx for %ls", HRV(hr), name);
    t_check(a == want, __FILE__, __LINE__, "alg value", "got %ld want %ld for %ls", (long)a, (long)want, name);
}
static void expect_unsupported(const wchar_t *name) {
    LONG a;
    HRESULT hr = alg_of(name, &a);
    t_check(HRV(hr) == ACD_NTE_NOT_SUPPORTED, __FILE__, __LINE__, "unsupported", "hr=0x%08lx for \"%ls\"", HRV(hr), name ? name : L"(null)");
    t_check(a == SENT_ALG, __FILE__, __LINE__, "unsupported", "output modified: %ld", (long)a);
}

TEST(ctap_authdata_cose_alg_es256) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"ES256", -7); }
TEST(ctap_authdata_cose_alg_es384) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"ES384", -35); }
TEST(ctap_authdata_cose_alg_es512) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"ES512", -36); }
TEST(ctap_authdata_cose_alg_rs256) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"RS256", -257); }
TEST(ctap_authdata_cose_alg_rs384) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"RS384", -258); }
TEST(ctap_authdata_cose_alg_rs512) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"RS512", -259); }
TEST(ctap_authdata_cose_alg_ps256) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"PS256", -37); }
TEST(ctap_authdata_cose_alg_ps384) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"PS384", -38); }
TEST(ctap_authdata_cose_alg_ps512) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"PS512", -39); }
TEST(ctap_authdata_cose_alg_rs1)   { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"RS1", -65535); }
TEST(ctap_authdata_cose_alg_ecdh256) { REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier)); expect_alg(L"ECDH256", -25); }

TEST(ctap_authdata_cose_alg_eddsa_not_in_table) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    expect_unsupported(L"EdDSA");
    expect_unsupported(L"EDDSA");
    expect_unsupported(L"Ed25519");
}

TEST(ctap_authdata_cose_alg_matches_key_table) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    for (int k = 0; k < NKEYS; k++) {
        if (!KEYS[k].wname) { expect_unsupported(L"EdDSA"); continue; }
        expect_alg(KEYS[k].wname, (LONG)KEYS[k].alg);
    }
}

TEST(ctap_authdata_cose_alg_value_is_negative_signed) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    LONG a = 0;
    HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(L"ES256", &a);
    EXPECT_EQ(HRV(hr), 0);
    EXPECT_EQ((DWORD)a, 0xFFFFFFF9);
    CHECK(a < 0);
}

TEST(ctap_authdata_cose_alg_case_sensitive) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    static const wchar_t *bad[] = { L"es256", L"Es256", L"eS256", L"rs256", L"Rs256", L"ps512", L"ecdh256", L"Ecdh256", L"rs1", L"RS1 ", L"es384", L"ES512 " };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) expect_unsupported(bad[i]);
}

TEST(ctap_authdata_cose_alg_exact_full_string_match) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    static const wchar_t *bad[] = { L"ES25", L"ES2566", L"ES256 ", L" ES256", L"ES256\t", L"ES256x", L"xES256", L"RS25", L"RS2560", L"RS", L"ES", L"PS", L"RS1x", L"RS12", L"R", L"E", L"ECDH", L"ECDH2560", L"ECDH25" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) expect_unsupported(bad[i]);
}

TEST(ctap_authdata_cose_alg_empty_string) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    expect_unsupported(L"");
}

TEST(ctap_authdata_cose_alg_null_name) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    LONG a = SENT_ALG;
    HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(NULL, &a);
    EXPECT_EQ(HRV(hr), ACD_NTE_NOT_SUPPORTED);
    EXPECT_EQ(a, SENT_ALG);
}

TEST(ctap_authdata_cose_alg_null_name_null_output) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    /* the name is tested first; the output pointer is not touched on failure */
    HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(NULL, NULL);
    EXPECT_EQ(HRV(hr), ACD_NTE_NOT_SUPPORTED);
}

TEST(ctap_authdata_cose_alg_unknown_name_null_output) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(L"NoSuchAlg", NULL);
    EXPECT_EQ(HRV(hr), ACD_NTE_NOT_SUPPORTED);
}

TEST(ctap_authdata_cose_alg_numeric_strings_rejected) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    static const wchar_t *bad[] = { L"-7", L"7", L"-257", L"-8", L"0", L"-35", L"-36", L"-65535", L"-25", L"1", L"2" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) expect_unsupported(bad[i]);
}

TEST(ctap_authdata_cose_alg_other_well_known_names_rejected) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    static const wchar_t *bad[] = { L"ES256K", L"HS256", L"RS224", L"ES224", L"ECDSA_P256", L"ECDSA_P384", L"ECDSA_P521",
        L"RSA", L"SHA256", L"SHA1", L"P-256", L"P-384", L"P-521", L"ECDH384", L"ECDH512", L"ECDH_P256", L"PS224", L"PS1",
        L"ES256-", L"ES-256", L"RS-256", L"Ed448", L"EdDSA " };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) expect_unsupported(bad[i]);
}

TEST(ctap_authdata_cose_alg_unicode_lookalikes_rejected) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    const wchar_t fullwidth[] = { 0xFF25, 0xFF33, 0xFF12, 0xFF15, 0xFF16, 0 };   /* fullwidth "ES256" */
    expect_unsupported(fullwidth);
    const wchar_t cyr[] = { 0x0415, L'S', L'2', L'5', L'6', 0 };                  /* Cyrillic E */
    expect_unsupported(cyr);
    const wchar_t embedded[] = { L'E', L'S', 0, L'2', L'5', L'6', 0 };           /* NUL terminates: "ES" */
    expect_unsupported(embedded);
}

TEST(ctap_authdata_cose_alg_string_ending_at_guard_page) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    /* strings whose terminator is the last readable word: no over-read allowed past the NUL */
    static const wchar_t *names[] = { L"ES256", L"RS1", L"ECDH256", L"PS512", L"X", L"", L"ES2" };
    static const int ok[] = { 1, 1, 1, 1, 0, 0, 0 };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        size_t bytes = (wcslen(names[i]) + 1) * 2;
        gbuf g; const BYTE *q = g_place(&g, names[i], bytes);
        LONG a = SENT_ALG;
        HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)((const wchar_t *)q, &a);
        if (ok[i]) EXPECT_EQ(HRV(hr), 0); else { EXPECT_EQ(HRV(hr), ACD_NTE_NOT_SUPPORTED); EXPECT_EQ(a, SENT_ALG); }
        g_free(&g);
    }
}

TEST(ctap_authdata_cose_alg_output_not_written_on_failure_multiple) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    LONG a = 12345;
    HRESULT hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(L"ES256", &a);
    EXPECT_EQ(HRV(hr), 0);
    EXPECT_EQ(a, -7);
    hr = UN(WebAuthNGetCoseAlgorithmIdentifier)(L"bogus", &a);   /* previous success value survives */
    EXPECT_EQ(HRV(hr), ACD_NTE_NOT_SUPPORTED);
    EXPECT_EQ(a, -7);
}

TEST(ctap_authdata_cose_alg_values_unique_and_stable) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    static const wchar_t *names[] = { L"ES256", L"RS256", L"PS256", L"RS384", L"RS512", L"PS384", L"PS512", L"ES384", L"ES512", L"RS1", L"ECDH256" };
    LONG vals[11];
    for (int i = 0; i < 11; i++) { HRESULT hr = alg_of(names[i], &vals[i]); EXPECT_EQ(HRV(hr), 0); }
    for (int i = 0; i < 11; i++) for (int j = i + 1; j < 11; j++) CHECKF(vals[i] != vals[j], "%ls == %ls", names[i], names[j]);
    for (int r = 0; r < 20; r++) for (int i = 0; i < 11; i++) { LONG a; alg_of(names[i], &a); CHECK(a == vals[i]); }
}

TEST(ctap_authdata_cose_alg_hresult_class) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    LONG a;
    HRESULT hr = alg_of(L"zzz", &a);
    CHECK(FAILED(hr));
    EXPECT_EQ(HRV(hr) >> 16, 0x8009);          /* NTE_* facility 9 (security) */
    hr = alg_of(L"ES256", &a);
    CHECK(SUCCEEDED(hr));
    EXPECT_EQ(hr, 0);
}

/* Algorithm numbers embedded in real COSE keys: the key's "alg" (label 3) must be the number the DLL maps its name to. */
TEST(ctap_authdata_cose_alg_matches_cose_key_alg_field) {
    REQUIRE(UN(WebAuthNGetCoseAlgorithmIdentifier));
    for (int k = 0; k < NKEYS; k++) {
        if (!KEYS[k].wname) continue;
        vec v; v_init(&v); KEYS[k].mk(&v);
        /* locate "03 <int>" key/value pair in the encoded map by re-encoding the expected pair */
        vec pair; v_init(&pair); cb_int(&pair, 3); cb_int(&pair, KEYS[k].alg);
        int found = 0;
        for (size_t i = 0; i + pair.n <= v.n; i++) if (!memcmp(v.p + i, pair.p, pair.n)) { found = 1; break; }
        CHECKF(found, "alg pair for %s", KEYS[k].name);
        LONG a; HRESULT hr = alg_of(KEYS[k].wname, &a);
        EXPECT_EQ(HRV(hr), 0);
        EXPECT_EQ(a, (LONG)KEYS[k].alg);
        v_free(&v); v_free(&pair);
    }
}
