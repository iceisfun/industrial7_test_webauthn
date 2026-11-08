/* WebAuthNCtapParseAuthenticatorData: header, flags, signCount and structure validation.
 * Behaviour pinned from the Windows 10 reference decompilation:
 *  - cb < 37 -> HRESULT_FROM_WIN32(ERROR_INVALID_DATA) (0x8007000D), outputs zeroed first
 *  - flags = byte 32, signCount = big-endian u32 at 33; no flag bit is rejected on its own
 *  - AT: needs >= 18 bytes after the header, credIdLen <= remaining, then one well formed CBOR
 *        array/map item (its content is never inspected)
 *  - ED: everything left is extension data and is NOT validated (may be empty / garbage)
 *  - without ED, any byte after the last parsed element is an error
 */
#include "acd.h"

TEST(ctap_authdata_cose_parse_minimal_up) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_UP, 1);
    EXPECT_EQ(v.n, 37);
    expect_parse_ok(v.p, v.n, ACD_UP, 1, "minimal");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_minimal_all_zero) {
    NEED_ALL();
    BYTE b[37] = { 0 };
    expect_parse_ok(b, 37, 0, 0, "all zero");
}

TEST(ctap_authdata_cose_parse_outputs_overwritten_on_success) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_UP | ACD_UV, 0x12345678);
    pres r = acd_parse(v.p, v.n);
    EXPECT_EQ(HRV(r.hr), 0);
    EXPECT_EQ(r.fl, 0x05);
    EXPECT_EQ(r.sc, 0x12345678);
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_signcount_big_endian) {
    NEED_ALL();
    static const DWORD counts[] = { 0, 1, 2, 0xFF, 0x100, 0x0102, 0x010203, 0x01020304, 0x7FFFFFFF, 0x80000000, 0xFF000000, 0x00FF0000, 0x0000FF00, 0xFFFFFFFF, 0xDEADBEEF };
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        vec v; v_init(&v); ad_header(&v, ACD_UP, counts[i]);
        expect_parse_ok(v.p, v.n, ACD_UP, counts[i], "signCount");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_signcount_raw_bytes) {
    NEED_ALL();
    BYTE b[37] = { 0 }; b[32] = 0x01; b[33] = 0xA1; b[34] = 0xB2; b[35] = 0xC3; b[36] = 0xD4;
    expect_parse_ok(b, 37, 0x01, 0xA1B2C3D4, "raw BE");
}

TEST(ctap_authdata_cose_parse_rpidhash_not_interpreted) {
    NEED_ALL();
    for (int fill = 0; fill < 256; fill += 51) {
        BYTE b[37]; memset(b, fill, 32); b[32] = ACD_UP; b[33] = b[34] = b[35] = 0; b[36] = 9;
        expect_parse_ok(b, 37, ACD_UP, 9, "rpIdHash fill");
    }
}

/* Every flags value, with a body that matches the AT/ED bits: all must succeed and echo the raw flags. */
TEST(ctap_authdata_cose_parse_all_256_flag_values) {
    NEED_ALL();
    for (int f = 0; f < 256; f++) {
        vec v; ad_full(&v, (BYTE)f, 0xA0000000u | (DWORD)f, (f & ACD_AT) ? K_ES256 : -1, 32, (f & ACD_ED) ? 1 : 0);
        expect_parse_ok(v.p, v.n, (BYTE)f, 0xA0000000u | (DWORD)f, "flag value");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_rfu_flag_bits_ignored) {
    NEED_ALL();
    static const BYTE fl[] = { 0x02, 0x08, 0x10, 0x20, 0x3A, 0x1A };   /* RFU / BE / BS / other */
    for (size_t i = 0; i < sizeof fl; i++) {
        vec v; v_init(&v); ad_header(&v, fl[i], 77);
        expect_parse_ok(v.p, v.n, fl[i], 77, "rfu flag");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_flags_without_body_need_exact_37) {
    NEED_ALL();
    /* flags with neither AT nor ED set: trailing data is rejected */
    for (int f = 0; f < 256; f++) {
        if (f & (ACD_AT | ACD_ED)) continue;
        BYTE b[38] = { 0 }; b[32] = (BYTE)f;
        expect_parse_ok(b, 37, (BYTE)f, 0, "37 bytes");
        expect_parse_fail(b, 38, "38 bytes no AT/ED");
    }
}

TEST(ctap_authdata_cose_parse_at_flag_with_only_header_fails) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 5);
    expect_parse_fail(v.p, v.n, "AT with no data");
    v_free(&v);
    v_init(&v); ad_header(&v, ACD_AT | ACD_UP | ACD_ED, 5);
    expect_parse_fail(v.p, v.n, "AT|ED with no data");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_at_needs_18_bytes_after_header) {
    NEED_ALL();
    for (int extra = 0; extra <= 17; extra++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 5);
        for (int i = 0; i < extra; i++) v_u8(&v, 0);
        expect_parse_fail(v.p, v.n, "AT short");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_at_zero_credid_len_with_key_ok) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_UP, 3, K_ES256, 0, 0);
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP, 3, "credIdLen 0");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_at_18_bytes_no_key_fails) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 5); ad_att(&v, 0, 0, 1);
    EXPECT_EQ(v.n, 55);
    expect_parse_fail(v.p, v.n, "no COSE key, credIdLen 0");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_at_credid_consumes_all_fails) {
    NEED_ALL();
    for (unsigned n = 1; n <= 40; n += 13) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 5); ad_att(&v, n, n, 1);
        expect_parse_fail(v.p, v.n, "credId but no COSE key");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_credidlen_exceeds_remaining) {
    NEED_ALL();
    vec key; v_init(&key); mk_es256(&key);
    unsigned remaining = (unsigned)key.n;      /* bytes after the credIdLen field when credId is empty */
    static const int deltas[] = { 1, 2, 10, 100 };
    for (size_t i = 0; i < sizeof deltas / sizeof deltas[0]; i++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 5); ad_att(&v, 0, 0, 1);
        v.p[53] = 0; v.p[54] = 0;
        unsigned lie = remaining + deltas[i];
        v.p[53] = (BYTE)(lie >> 8); v.p[54] = (BYTE)lie;
        v_put(&v, key.p, key.n);
        expect_parse_fail(v.p, v.n, "credIdLen > remaining");
        v_free(&v);
    }
    v_free(&key);
}

TEST(ctap_authdata_cose_parse_credidlen_max_u16) {
    NEED_ALL();
    vec key; v_init(&key); mk_es256(&key);
    vec v; v_init(&v); ad_header(&v, ACD_AT, 5); ad_att(&v, 0xFFFF, 0, 1);
    v_put(&v, key.p, key.n);
    expect_parse_fail(v.p, v.n, "credIdLen 0xFFFF");
    v_free(&v); v_free(&key);
}

TEST(ctap_authdata_cose_parse_credidlen_shorter_than_actual_misparses_key) {
    NEED_ALL();
    /* credIdLen smaller than the real credential: the remaining bytes of the credential id start the
     * "COSE key", whose first byte is not a map/array -> invalid data. */
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
    v.p[53] = 0; v.p[54] = 16;
    expect_parse_fail(v.p, v.n, "credIdLen too small");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_credid_lengths_table) {
    NEED_ALL();
    static const unsigned lens[] = { 0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300, 512, 1000, 1023, 1024 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        vec v; ad_full(&v, ACD_AT | ACD_UP | ACD_UV, 100 + (DWORD)i, K_ES256, lens[i], 0);
        EXPECT_EQ(v.n, 55 + lens[i] + 77);
        expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP | ACD_UV, 100 + (DWORD)i, "credId length");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_credid_length_65535) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 9, K_ES256, 0xFFFF, 0);
    expect_parse_ok(v.p, v.n, ACD_AT, 9, "credIdLen 65535");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_aaguid_not_interpreted) {
    NEED_ALL();
    for (int fill = 0; fill < 256; fill += 85) {
        vec v; ad_full(&v, ACD_AT, 5, K_ES256, 16, 0);
        memset(v.p + 37, fill, 16);
        expect_parse_ok(v.p, v.n, ACD_AT, 5, "aaguid fill");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_at_and_ed_together) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_ED | ACD_UP | ACD_UV, 0x55, K_ES256, 32, 1);
    expect_parse_ok(v.p, v.n, 0xC5, 0x55, "AT|ED|UP|UV");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_ed_only_valid_extensions) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_ED | ACD_UP, 8, -1, 0, 1);
    expect_parse_ok(v.p, v.n, ACD_ED | ACD_UP, 8, "ED valid");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_ed_with_no_extension_bytes_ok) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_ED, 8, -1, 0, 0);
    EXPECT_EQ(v.n, 37);
    expect_parse_ok(v.p, v.n, ACD_ED, 8, "ED, zero extension bytes");
    v_free(&v);
    ad_full(&v, ACD_ED | ACD_AT, 8, K_ES256, 20, 0);
    expect_parse_ok(v.p, v.n, ACD_ED | ACD_AT, 8, "AT|ED, zero extension bytes");
    v_free(&v);
}

/* The extension block is carried through, not parsed: any byte string is accepted. */
TEST(ctap_authdata_cose_parse_ed_garbage_cbor_accepted) {
    NEED_ALL();
    static const char *junk[] = { "FF", "00", "BC", "BF", "A1", "A2 01", "5F", "7F FF", "1C", "FE FE FE FE", "A1 61 78", "B8 05 01" };
    for (size_t i = 0; i < sizeof junk / sizeof junk[0]; i++) {
        vec v; v_init(&v); ad_header(&v, ACD_ED, 4); v_hex(&v, junk[i]);
        expect_parse_ok(v.p, v.n, ACD_ED, 4, "ED junk");
        v_free(&v);
        v_init(&v); ad_header(&v, ACD_ED | ACD_AT, 4); ad_att(&v, 8, 8, 2); mk_es256(&v); v_hex(&v, junk[i]);
        expect_parse_ok(v.p, v.n, ACD_ED | ACD_AT, 4, "AT|ED junk");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_ed_large_tail_accepted) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_ED, 4);
    for (int i = 0; i < 3000; i++) v_u8(&v, i * 31);
    expect_parse_ok(v.p, v.n, ACD_ED, 4, "3000 ext bytes");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_trailing_bytes_after_key_without_ed) {
    NEED_ALL();
    for (int extra = 1; extra <= 8; extra++) {
        vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 0);
        for (int i = 0; i < extra; i++) v_u8(&v, 0xA0 + i);
        expect_parse_fail(v.p, v.n, "trailing after COSE");
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_trailing_valid_cbor_without_ed_fails) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT, 5, K_ES256, 32, 1);   /* valid extension map, but ED not set */
    expect_parse_fail(v.p, v.n, "extensions without ED flag");
    v_free(&v);
    ad_full(&v, ACD_UP, 5, -1, 0, 1);
    expect_parse_fail(v.p, v.n, "extensions without ED/AT flags");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_flag_content_matrix) {
    NEED_ALL();
    /* matrix of (AT,ED) x (has attested data, has ext bytes): success iff flags match what is present */
    for (int at = 0; at < 2; at++) for (int ed = 0; ed < 2; ed++) for (int hasAtt = 0; hasAtt < 2; hasAtt++) for (int hasExt = 0; hasExt < 2; hasExt++) {
        BYTE f = (BYTE)((at ? ACD_AT : 0) | (ed ? ACD_ED : 0));
        vec v; ad_full(&v, f, 6, hasAtt ? K_ES256 : -1, 16, hasExt);
        int want;
        if (at && !hasAtt) want = 0;                 /* AT set but nothing (or too little) follows */
        else if (!at && hasAtt) want = ed;           /* attested bytes are then just unvalidated extension bytes */
        else want = (hasExt ? ed : 1);
        pres r = acd_parse(v.p, v.n);
        CHECKF((HRV(r.hr) == 0) == want, "at=%d ed=%d att=%d ext=%d hr=%08lx", at, ed, hasAtt, hasExt, HRV(r.hr));
        if (!want) EXPECT_EQ(HRV(r.hr), ACD_E_INVALID_DATA);
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_parse_does_not_modify_input) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_ED, 0x77, K_RS256, 40, 1);
    vec c; v_copy(&c, &v);
    gbuf g; const BYTE *q = g_place(&g, v.p, v.n);
    BYTE fl; DWORD sc;
    HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)((DWORD)v.n, q, &fl, &sc);
    EXPECT_EQ(HRV(hr), 0);
    CHECK(memcmp(q, c.p, c.n) == 0);
    g_free(&g); v_free(&v); v_free(&c);
}

TEST(ctap_authdata_cose_parse_repeatable) {
    NEED_ALL();
    vec v; ad_full(&v, ACD_AT | ACD_UP, 0x99, K_ES384, 24, 0);
    for (int i = 0; i < 50; i++) expect_parse_ok(v.p, v.n, ACD_AT | ACD_UP, 0x99, "repeat");
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_too_short_every_length) {
    NEED_ALL();
    BYTE full[64]; memset(full, 0, sizeof full); full[32] = ACD_UP;
    for (size_t n = 0; n < 37; n++) expect_parse_fail(full, n, "cb < 37");
}

TEST(ctap_authdata_cose_parse_zero_length_null_pointer) {
    NEED_ALL();
    BYTE fl = SENT_FL; DWORD sc = SENT_SC;
    HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)(0, NULL, &fl, &sc);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(sc, 0);
}

TEST(ctap_authdata_cose_parse_zero_length_nonnull_pointer) {
    NEED_ALL();
    BYTE b[64] = { 0 };
    BYTE fl = SENT_FL; DWORD sc = SENT_SC;
    HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)(0, b, &fl, &sc);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(sc, 0);
}

TEST(ctap_authdata_cose_parse_short_null_pointer_len_36) {
    NEED_ALL();
    /* cb < 37 is rejected before the buffer pointer is used */
    BYTE fl = SENT_FL; DWORD sc = SENT_SC;
    HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)(36, NULL, &fl, &sc);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(sc, 0);
}

TEST(ctap_authdata_cose_parse_failure_zeroes_stale_outputs) {
    NEED_ALL();
    BYTE short_buf[10] = { 0 };
    BYTE fl = 0x7F; DWORD sc = 0x7F7F7F7F;
    HRESULT hr = UN(WebAuthNCtapParseAuthenticatorData)(10, short_buf, &fl, &sc);
    EXPECT_EQ(HRV(hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(fl, 0);
    EXPECT_EQ(sc, 0);
}

TEST(ctap_authdata_cose_parse_failure_after_header_still_zeroes_outputs) {
    NEED_ALL();
    /* header parsed (flags/signCount decoded internally) but the body is bad: caller must still see zeros */
    vec v; v_init(&v); ad_header(&v, ACD_AT | ACD_UP, 0xFFFFFFFF);
    pres r = acd_parse(v.p, v.n);
    EXPECT_EQ(HRV(r.hr), ACD_E_INVALID_DATA);
    EXPECT_EQ(r.fl, 0);
    EXPECT_EQ(r.sc, 0);
    v_free(&v);
}

TEST(ctap_authdata_cose_parse_hresult_is_win32_invalid_data) {
    NEED_ALL();
    BYTE b[4] = { 0 };
    pres r = acd_parse(b, 4);
    EXPECT_EQ(HRV(r.hr), 0x8007000D);
    CHECK(HRESULT_FROM_WIN32(ERROR_INVALID_DATA) == r.hr);
    CHECK(FAILED(r.hr));
}

TEST(ctap_authdata_cose_parse_ordinal_matches_name) {
    FARPROC a = t_proc("WebAuthNCtapParseAuthenticatorData");
    REQUIRE(a);
    EXPECT_EQ(t_proc_ord("webauthn.dll", 30), a);
    FARPROC b = t_proc("WebAuthNGetCredentialIdFromAuthenticatorData");
    REQUIRE(b);
    EXPECT_EQ(t_proc_ord("webauthn.dll", 52), b);
    FARPROC c = t_proc("WebAuthNGetCoseAlgorithmIdentifier");
    REQUIRE(c);
    EXPECT_EQ(t_proc_ord("webauthn.dll", 51), c);
}
