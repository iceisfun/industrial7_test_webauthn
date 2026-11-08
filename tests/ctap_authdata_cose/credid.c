/* WebAuthNGetCredentialIdFromAuthenticatorData.
 * From the Windows 10 reference decompilation:
 *  - cb == 0, NULL buffer, NULL pcbCredId or NULL pdwOffset -> NTE_INVALID_PARAMETER (0x80090027), checked
 *    before anything is written
 *  - otherwise both outputs are zeroed, the buffer is validated exactly like WebAuthNCtapParseAuthenticatorData
 *    (failure -> 0x8007000D) and an AT buffer with credIdLen == 0 or no AT flag also gives 0x8007000D
 *  - success: *pcbCredId = credIdLen, *pdwOffset = byte offset of the id inside the buffer (55 for a well formed buffer)
 */
#include "acd.h"

static void check_credid_ok(const vec *v, unsigned credlen, const char *what) {
    cres r = acd_credid(v->p, v->n);
    t_check(HRV(r.hr) == 0, __FILE__, __LINE__, what, "hr=0x%08lx", HRV(r.hr));
    t_check(r.cb == credlen, __FILE__, __LINE__, what, "cb=%lu want %u", r.cb, credlen);
    t_check(r.off == ACD_CRED_OFF, __FILE__, __LINE__, what, "off=%lu want 55", r.off);
    if (HRV(r.hr) == 0 && r.off + r.cb <= v->n) {
        BYTE exp[2048]; cred_fill(exp, credlen < sizeof exp ? credlen : sizeof exp, 0x40);
        t_check(credlen > sizeof exp || memcmp(v->p + r.off, exp, credlen) == 0, __FILE__, __LINE__, what, "credential bytes differ");
    }
}

TEST(ctap_authdata_cose_credid_basic_es256) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_UP, 1, K_ES256, 32, 0);
    check_credid_ok(&v, 32, "basic");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_lengths_table) {
    NEED_ALL();
    static const unsigned lens[] = { 1, 2, 7, 16, 31, 32, 33, 48, 64, 100, 127, 128, 255, 256, 257, 500, 1023, 1024 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        vec v; ad_full(&v, ACD_AT | ACD_UP | ACD_UV, 7, K_ES256, lens[i], 0);
        check_credid_ok(&v, lens[i], "len table");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_credid_length_65535) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 7, K_ES256, 0xFFFF, 0);
    cres r = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(r.hr), 0);
    EXPECT_EQ(r.cb, 0xFFFF);
    EXPECT_EQ(r.off, 55);
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_with_extensions) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_ED | ACD_UP, 7, K_ES256, 40, 1);
    check_credid_ok(&v, 40, "AT|ED");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_ed_junk_extensions_ok) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_ED, 7, K_ES256, 24, 0);
    v_hex(&v, "FF FF BC");
    check_credid_ok(&v, 24, "AT|ED junk ext");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_offset_independent_of_signcount_and_flags) {
    NEED_ALL();
    static const BYTE fl[] = { ACD_AT, ACD_AT | ACD_UP, ACD_AT | ACD_UV | ACD_UP, ACD_AT | 0x08 | 0x10, ACD_AT | 0x3A };
    for (size_t i = 0; i < sizeof fl; i++) {
        vec v; ad_full(&v, fl[i], 0xFFFFFFFF - (DWORD)i, K_RS256, 20, 0);
        check_credid_ok(&v, 20, "flags");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_credid_zero_length_credential_is_invalid_data) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_UP, 1, K_ES256, 0, 0);
    expect_cred_fail(v.p, v.n, "credIdLen 0");
    /* ... although the structure itself parses */
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP, 1, "same buffer parses");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_no_at_flag_is_invalid_data) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_UP, 1);
    expect_cred_fail(v.p, v.n, "no AT");
    v_free(&v);
    v_init(&v); ad_header(&v, ACD_UP | ACD_ED, 1); ext_valid(&v);
    expect_cred_fail(v.p, v.n, "ED only");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_no_at_flag_but_attested_bytes_present) {
    NEED_ALL();
    /* attested-looking bytes without the AT flag are not interpreted */
    vec v; ad_full(&v, ACD_ED, 1, K_ES256, 32, 0);
    expect_cred_fail(v.p, v.n, "ED set, AT clear, attested bytes present");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_at_flag_header_only) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1);
    expect_cred_fail(v.p, v.n, "AT, no data");
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_too_short_every_length) {
    NEED_ALL();
    BYTE b[40] = { 0 }; b[32] = ACD_UP;
    for (size_t n = 1; n < 37; n++) expect_cred_fail(b, n, "cb < 37");
}

TEST(ctap_authdata_cose_credid_credidlen_exceeds_buffer) {
    NEED_ALL();
    vec key; v_init(&key); mk_es256(&key);
    static const unsigned lies[] = { 1000, 0x7FFF, 0xFFFF };
    for (size_t i = 0; i < sizeof lies / sizeof lies[0]; i++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 5); ad_att(&v, lies[i], 0, 1); v_put(&v, key.p, key.n);
        expect_cred_fail(v.p, v.n, "credIdLen lies");
        v_free(&v);
    }
    v_free(&key);
}

TEST(ctap_authdata_cose_credid_trailing_bytes_without_ed) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    v_u8(&v, 0);
    expect_cred_fail(v.p, v.n, "trailing byte");
    v_free(&v);
}

/* ---- parameter validation: NTE_INVALID_PARAMETER ---------------------------- */
TEST(ctap_authdata_cose_credid_null_buffer) {
    NEED_ALL();
    DWORD cb = SENT_CB, off = SENT_OFF;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(100, NULL, &cb, &off);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, SENT_CB);       /* outputs untouched: validation precedes the zeroing */
    EXPECT_EQ(off, SENT_OFF);
}

TEST(ctap_authdata_cose_credid_zero_length) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    DWORD cb = SENT_CB, off = SENT_OFF;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(0, v.p, &cb, &off);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, SENT_CB);
    EXPECT_EQ(off, SENT_OFF);
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_zero_length_and_null_buffer) {
    NEED_ALL();
    DWORD cb = SENT_CB, off = SENT_OFF;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(0, NULL, &cb, &off);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, SENT_CB);
    EXPECT_EQ(off, SENT_OFF);
}

TEST(ctap_authdata_cose_credid_null_cred_len_out) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    DWORD off = SENT_OFF;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, v.p, NULL, &off);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    EXPECT_EQ(off, SENT_OFF);
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_null_offset_out) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    DWORD cb = SENT_CB;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, v.p, &cb, NULL);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, SENT_CB);
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_both_outputs_null) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, v.p, NULL, NULL);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    v_free(&v);
}

TEST(ctap_authdata_cose_credid_param_check_precedes_data_validation) {
    NEED_ALL();
    /* a bad buffer plus a NULL output reports the parameter error, not invalid data */
    BYTE junk[10] = { 0 };
    DWORD off = SENT_OFF;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(10, junk, NULL, &off);
    EXPECT_EQ(HRV(hr), ACD_NTE_INVALID_PARAM);
    /* and the converse: a short non-NULL buffer with valid outputs reports invalid data */
    DWORD cb = SENT_CB; off = SENT_OFF;
    hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(10, junk, &cb, &off);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(cb, 0);
    EXPECT_EQ(off, 0);
}

TEST(ctap_authdata_cose_credid_failure_zeroes_stale_outputs) {
    NEED_ALL();
    BYTE b[37] = { 0 };
    DWORD cb = 0x1234, off = 0x5678;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)(37, b, &cb, &off);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(cb, 0);
    EXPECT_EQ(off, 0);
}

TEST(ctap_authdata_cose_credid_agrees_with_parse) {
    NEED_ALL();
    /* for every key type: both functions accept; for corrupted buffers both reject */
    for (int k = 0; k < NKEYS; k++) {
        vec v; ad_full(&v, ACD_AT | ACD_UP, 3, k, 33, 0);
        pres p = acd_parse(v.p, v.n);
        cres c = acd_credid(v.p, v.n);
        CHECKF(HRV(p.hr) == 0 && HRV(c.hr) == 0, "key %s parse=%08lx credid=%08lx", KEYS[k].name, HRV(p.hr), HRV(c.hr));
        v.n -= 1;
        p = acd_parse(v.p, v.n); c = acd_credid(v.p, v.n);
        CHECKF(HRV(p.hr) == ACD_E_INVALID_DATA && HRV(c.hr) == ACD_E_INVALID_DATA, "trunc key %s", KEYS[k].name);
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_credid_offset_points_inside_guarded_buffer) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 3, K_ES256, 64, 0);
    gbuf g; const BYTE *q = g_place(&g, v.p, v.n);
    DWORD cb = 0, off = 0;
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, q, &cb, &off);
    EXPECT_EQ(HRV(hr), 0);
    CHECK(off + cb <= v.n);
    CHECK(memcmp(q + off, v.p + 55, cb) == 0);
    g_free(&g); v_free(&v);
}

TEST(ctap_authdata_cose_credid_aliasing_pointers_distinct_outputs) {
    NEED_ALL();
    /* two outputs in one struct: each receives its own value */
    struct { DWORD cb, off; } o = { SENT_CB, SENT_OFF };
    vec v; ad_full(&v, ACD_AT, 3, K_ES384, 21, 0);
    HRESULT hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)v.n, v.p, &o.cb, &o.off);
    EXPECT_EQ(HRV(hr), 0);
    EXPECT_EQ(o.cb, 21);
    EXPECT_EQ(o.off, 55);
    v_free(&v);
}
