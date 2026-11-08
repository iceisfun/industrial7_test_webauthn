#include "aic.h"
/* WebAuthNEncodeAccountInformation: exact bytes, version independence, validation, limits. */

#define ENC_EXACT(tn, rpargs, usargs, ...) \
    TEST(tn) { AIC_REQ(); AIC_RP rp = RPV rpargs; AIC_USER us = USV usargs; AIC_ACCT a = { 1, &rp, &us }; \
        static const BYTE e[] = { __VA_ARGS__ }; aic_enc_expect(&a, e, sizeof e); }

#define NOUSER (1, 0, NULL, NULL, NULL, NULL)
#define NORP   (1, NULL, NULL, NULL)

/* ---- exact encodings ------------------------------------------------------------------ */
ENC_EXACT(aic_enc_exact_minimal, (1, L"a", NULL, NULL), (1, 1, (PBYTE)"\x01", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01)
ENC_EXACT(aic_enc_exact_rp_all_fields, (1, L"a.b", L"N", L"i"), (1, 1, (PBYTE)"\x01", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA3, 0x62, 'i', 'd', 0x63, 'a', '.', 'b', 0x64, 'i', 'c', 'o', 'n', 0x61, 'i',
          0x64, 'n', 'a', 'm', 'e', 0x61, 'N', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01)
ENC_EXACT(aic_enc_exact_user_all_fields, (1, L"r", NULL, NULL), (1, 2, (PBYTE)"\xAA\xBB", L"n", L"I", L"D"),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'r', 0x03, 0xA4, 0x62, 'i', 'd', 0x42, 0xAA, 0xBB,
          0x64, 'i', 'c', 'o', 'n', 0x61, 'I', 0x64, 'n', 'a', 'm', 'e', 0x61, 'n',
          0x6B, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x61, 'D')
ENC_EXACT(aic_enc_exact_empty_rp_map, (1, NULL, NULL, NULL), (1, 1, (PBYTE)"\x07", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x07)
ENC_EXACT(aic_enc_exact_empty_user_map, (1, L"x", NULL, NULL), (1, 0, NULL, NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'x', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_both_empty_maps, (1, NULL, NULL, NULL), (1, 0, NULL, NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_empty_strings_omitted_rp, (1, L"", L"", L""), (1, 0, NULL, NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_empty_strings_omitted_user, (1, L"q", NULL, NULL), (1, 0, NULL, L"", L"", L""),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'q', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_user_cbid_zero_ignores_pbid, (1, L"q", NULL, NULL), (1, 0, (PBYTE)"\x01\x02\x03", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'q', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_rp_name_only, (1, NULL, L"RP", NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x62, 'R', 'P', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_rp_icon_only, (1, NULL, NULL, L"ic"), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x64, 'i', 'c', 'o', 'n', 0x62, 'i', 'c', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_rp_name_icon_order, (1, NULL, L"N", L"I"), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA2, 0x64, 'i', 'c', 'o', 'n', 0x61, 'I', 0x64, 'n', 'a', 'm', 'e', 0x61, 'N', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_user_name_only, (1, NULL, NULL, NULL), (1, 0, NULL, L"U", NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'U')
ENC_EXACT(aic_enc_exact_user_display_only, (1, NULL, NULL, NULL), (1, 0, NULL, NULL, NULL, L"Disp"),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x6B, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x64, 'D', 'i', 's', 'p')
ENC_EXACT(aic_enc_exact_user_icon_only, (1, NULL, NULL, NULL), (1, 0, NULL, NULL, L"u.png", NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x64, 'i', 'c', 'o', 'n', 0x65, 'u', '.', 'p', 'n', 'g')
ENC_EXACT(aic_enc_exact_user_id_only, (1, NULL, NULL, NULL), (1, 3, (PBYTE)"\x00\x01\xFF", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x62, 'i', 'd', 0x43, 0x00, 0x01, 0xFF)
ENC_EXACT(aic_enc_exact_utf8_two_byte, (1, L"" L"\x00e9" L"", NULL, NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x62, 0xC3, 0xA9, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_utf8_three_byte, (1, L"" L"\x20ac" L"", NULL, NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x63, 0xE2, 0x82, 0xAC, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_utf8_four_byte_surrogate_pair, (1, L"\xD83D\xDE00", NULL, NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x64, 0xF0, 0x9F, 0x98, 0x80, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_utf8_mixed_user_name, (1, L"x", NULL, NULL), (1, 0, NULL, L"A" L"\x00e9" L"" L"\x20ac" L"", NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'x', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x66, 'A', 0xC3, 0xA9, 0xE2, 0x82, 0xAC)
ENC_EXACT(aic_enc_exact_space_only_string_kept, (1, L" ", NULL, NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, ' ', 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_control_chars_kept, (1, L"\t\n\x01", NULL, NULL), NOUSER,
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x63, 0x09, 0x0A, 0x01, 0x03, 0xA0)
ENC_EXACT(aic_enc_exact_user_binary_id_all_zero, (1, L"r", NULL, NULL), (1, 4, (PBYTE)"\x00\x00\x00\x00", NULL, NULL, NULL),
          0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'r', 0x03, 0xA1, 0x62, 'i', 'd', 0x44, 0, 0, 0, 0)

/* ---- version fields are not encoded -------------------------------------------------- */
TEST(aic_enc_account_version_not_encoded) {
    AIC_REQ();
    static const DWORD vers[] = { 0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF };
    AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_USER us = USV(1, 1, (PBYTE)"\x01", NULL, NULL, NULL);
    static const BYTE e[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 };
    for (unsigned i = 0; i < sizeof vers / sizeof vers[0]; i++) { AIC_ACCT a = { vers[i], &rp, &us }; aic_enc_expect(&a, e, sizeof e); }
}
TEST(aic_enc_rp_version_any_nonzero_accepted) {
    AIC_REQ();
    static const DWORD vers[] = { 1, 2, 5, 0x100, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF };
    AIC_USER us = USV(1, 1, (PBYTE)"\x01", NULL, NULL, NULL);
    static const BYTE e[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 };
    for (unsigned i = 0; i < sizeof vers / sizeof vers[0]; i++) { AIC_RP rp = RPV(vers[i], L"a", NULL, NULL); AIC_ACCT a = { 1, &rp, &us }; aic_enc_expect(&a, e, sizeof e); }
}
TEST(aic_enc_user_version_any_nonzero_accepted) {
    AIC_REQ();
    static const DWORD vers[] = { 1, 2, 9, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF };
    AIC_RP rp = RPV(1, L"a", NULL, NULL);
    static const BYTE e[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 };
    for (unsigned i = 0; i < sizeof vers / sizeof vers[0]; i++) { AIC_USER us = USV(vers[i], 1, (PBYTE)"\x01", NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us }; aic_enc_expect(&a, e, sizeof e); }
}

/* ---- validation failures (HRESULT, outputs untouched) ----------------------------------- */
static void enc_fail(const AIC_ACCT *a, HRESULT want, const char *tag) {
    DWORD cb = SENT_CB; PBYTE pb = (PBYTE)SENT_PTR;
    HRESULT hr = aic_enc(a, &cb, &pb);
    t_check(hr == want, __FILE__, __LINE__, tag, "got 0x%08lx want 0x%08lx", (unsigned long)hr, (unsigned long)want);
    t_check(cb == SENT_CB && pb == SENT_PTR, __FILE__, __LINE__, "outputs untouched on failure", "%s cb=%lu pb=%p", tag, (unsigned long)cb, (void *)pb);
    if (hr == 0 && pb && pb != SENT_PTR) aic_free_enc(pb);
}
TEST(aic_enc_null_rp_pointer) {
    AIC_REQ(); AIC_USER us = USV(1, 1, (PBYTE)"\x01", NULL, NULL, NULL); AIC_ACCT a = { 1, NULL, &us };
    enc_fail(&a, HR_INVALID_DATA, "NULL pRp");
}
TEST(aic_enc_null_user_pointer) {
    AIC_REQ(); AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_ACCT a = { 1, &rp, NULL };
    enc_fail(&a, HR_INVALID_DATA, "NULL pUser");
}
TEST(aic_enc_both_null) {
    AIC_REQ(); AIC_ACCT a = { 1, NULL, NULL };
    enc_fail(&a, HR_INVALID_DATA, "NULL pRp and pUser");
}
TEST(aic_enc_rp_version_zero) {
    AIC_REQ(); AIC_RP rp = RPV(0, L"a", NULL, NULL); AIC_USER us = USV(1, 1, (PBYTE)"\x01", NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    enc_fail(&a, HR_INVALID_DATA, "rp dwVersion 0");
}
TEST(aic_enc_user_version_zero) {
    AIC_REQ(); AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_USER us = USV(0, 1, (PBYTE)"\x01", NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    enc_fail(&a, HR_INVALID_DATA, "user dwVersion 0");
}
TEST(aic_enc_both_versions_zero_with_account_version_zero) {
    AIC_REQ(); AIC_RP rp = RPV(0, L"a", NULL, NULL); AIC_USER us = USV(0, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 0, &rp, &us };
    enc_fail(&a, HR_INVALID_DATA, "all versions 0");
}
TEST(aic_enc_rp_version_zero_empty_strings) {
    AIC_REQ(); AIC_RP rp = RPV(0, NULL, NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    enc_fail(&a, HR_INVALID_DATA, "rp dwVersion 0 empty");
}
/* Lone surrogates cannot be converted to UTF-8 (WC_ERR_INVALID_CHARS). */
#define LONE_TEST(tn, rpa, usa) TEST(tn) { AIC_REQ(); AIC_RP rp = RPV rpa; AIC_USER us = USV usa; AIC_ACCT a = { 1, &rp, &us }; \
    if (t_is_wine()) { t_skip("wine"); return; } enc_fail(&a, HR_INVALID_DATA, #tn); }
LONE_TEST(aic_enc_lone_high_surrogate_rp_id, (1, L"a\xD800", NULL, NULL), (1, 0, NULL, NULL, NULL, NULL))
LONE_TEST(aic_enc_lone_low_surrogate_rp_id, (1, L"\xDC00" L"a", NULL, NULL), (1, 0, NULL, NULL, NULL, NULL))
LONE_TEST(aic_enc_lone_surrogate_rp_name, (1, L"a", L"\xD800", NULL), (1, 0, NULL, NULL, NULL, NULL))
LONE_TEST(aic_enc_lone_surrogate_rp_icon, (1, L"a", NULL, L"\xDFFF"), (1, 0, NULL, NULL, NULL, NULL))
LONE_TEST(aic_enc_lone_surrogate_user_name, (1, L"a", NULL, NULL), (1, 0, NULL, L"\xD801", NULL, NULL))
LONE_TEST(aic_enc_lone_surrogate_user_icon, (1, L"a", NULL, NULL), (1, 0, NULL, NULL, L"x\xDC01", NULL))
LONE_TEST(aic_enc_lone_surrogate_user_display_name, (1, L"a", NULL, NULL), (1, 0, NULL, NULL, NULL, L"\xDBFF" L"y"))
LONE_TEST(aic_enc_reversed_surrogate_pair, (1, L"\xDE00\xD83D", NULL, NULL), (1, 0, NULL, NULL, NULL, NULL))

/* ---- header size boundaries for text and byte strings ------------------------------------ */
static const size_t k_lens[] = { 1, 22, 23, 24, 25, 100, 254, 255, 256, 257, 1000, 4096, 8000, 8163, 8164, 8191, 8192, 16384, 16385, 40000, 65535, 65536, 65537 };
static size_t head_len(size_t n, BYTE *h) {
    if (n < 24) { h[0] = (BYTE)n; return 1; }
    if (n < 256) { h[0] = 24; h[1] = (BYTE)n; return 2; }
    if (n < 65536) { h[0] = 25; h[1] = (BYTE)(n >> 8); h[2] = (BYTE)n; return 3; }
    h[0] = 26; h[1] = (BYTE)(n >> 24); h[2] = (BYTE)(n >> 16); h[3] = (BYTE)(n >> 8); h[4] = (BYTE)n; return 5;
}
TEST(aic_enc_rp_id_text_length_headers) {
    AIC_REQ();
    for (unsigned i = 0; i < sizeof k_lens / sizeof k_lens[0]; i++) {
        size_t n = k_lens[i]; WCHAR *w = (WCHAR *)malloc((n + 1) * 2);
        for (size_t k = 0; k < n; k++) w[k] = L'a' + (WCHAR)(k % 26);
        w[n] = 0;
        AIC_RP rp = RPV(1, w, NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
        DWORD cb = 0; PBYTE pb = NULL; HRESULT hr = aic_enc(&a, &cb, &pb);
        HR_EQ(hr, 0);
        if (hr == 0 && pb) {
            BYTE h[9]; size_t hl = head_len(n, h);
            static const BYTE pre[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd' };
            EXPECT_EQ(cb, sizeof pre + hl + n + 2);   /* pre + head(text) + payload + 03 A0 */
            if (cb >= sizeof pre + hl + 2) {
                CHECK(memcmp(pb, pre, sizeof pre) == 0);
                BYTE h0 = (BYTE)(0x60 | h[0]); CHECK(pb[sizeof pre] == h0);
                CHECK(hl == 1 || memcmp(pb + sizeof pre + 1, h + 1, hl - 1) == 0);
                CHECK(memcmp(pb + sizeof pre + hl, "abcdefghij", n < 10 ? n : 10) == 0);
                CHECK(pb[cb - 2] == 0x03 && pb[cb - 1] == 0xA0);
            }
            aic_free_enc(pb);
        }
        free(w);
    }
}
TEST(aic_enc_user_id_byte_length_headers) {
    AIC_REQ();
    for (unsigned i = 0; i < sizeof k_lens / sizeof k_lens[0]; i++) {
        size_t n = k_lens[i]; BYTE *id = (BYTE *)malloc(n);
        for (size_t k = 0; k < n; k++) id[k] = (BYTE)(k * 7 + 1);
        AIC_RP rp = RPV(1, NULL, NULL, NULL); AIC_USER us = USV(1, (DWORD)n, id, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
        DWORD cb = 0; PBYTE pb = NULL; HRESULT hr = aic_enc(&a, &cb, &pb);
        HR_EQ(hr, 0);
        if (hr == 0 && pb) {
            BYTE h[9]; size_t hl = head_len(n, h);
            static const BYTE pre[] = { 0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA1, 0x62, 'i', 'd' };
            EXPECT_EQ(cb, sizeof pre + hl + n);
            if (cb == sizeof pre + hl + n) {
                CHECK(memcmp(pb, pre, sizeof pre) == 0);
                CHECK(pb[sizeof pre] == (BYTE)(0x40 | h[0]));
                CHECK(hl == 1 || memcmp(pb + sizeof pre + 1, h + 1, hl - 1) == 0);
                CHECK(memcmp(pb + sizeof pre + hl, id, n) == 0);
            }
            aic_free_enc(pb);
        }
        free(id);
    }
}
TEST(aic_enc_rp_name_icon_user_strings_long) {
    AIC_REQ();
    static const size_t lens[] = { 23, 24, 255, 256, 5000 };
    for (unsigned i = 0; i < 5; i++) {
        size_t n = lens[i]; WCHAR *w = (WCHAR *)malloc((n + 1) * 2);
        for (size_t k = 0; k < n; k++) w[k] = L'A' + (WCHAR)(k % 26);
        w[n] = 0;
        AIC_RP rp = RPV(1, L"r", w, w); AIC_USER us = USV(1, 1, (PBYTE)"\x01", w, w, w); AIC_ACCT a = { 1, &rp, &us };
        DWORD cb = 0; PBYTE pb = NULL; HRESULT hr = aic_enc(&a, &cb, &pb);
        HR_EQ(hr, 0);
        BYTE h[9]; size_t hl = head_len(n, h);
        /* A3 01 01 02 | A3 "id" "r" "icon" S "name" S | 03 A4 "id" bstr "icon" S "name" S "displayName" S */
        size_t want = 4 + 1 + 3 + 2 + 5 + (hl + n) + 5 + (hl + n) + 1 + 1 + 3 + 2 + 5 + (hl + n) + 5 + (hl + n) + 12 + (hl + n);
        EXPECT_EQ(cb, want);
        if (hr == 0 && pb) aic_free_enc(pb);
        free(w);
    }
}

/* ---- allocation contract ----------------------------------------------------------------- */
TEST(aic_enc_output_is_local_alloc_and_freeable) {
    AIC_REQ();
    AIC_RP rp = RPV(1, L"example.com", L"Example", NULL); AIC_USER us = USV(1, 4, (PBYTE)"\x01\x02\x03\x04", L"bob", NULL, L"Bob"); AIC_ACCT a = { 1, &rp, &us };
    DWORD cb = 0; PBYTE pb = NULL; HRESULT hr = aic_enc(&a, &cb, &pb);
    HR_EQ(hr, 0);
    if (hr == 0 && pb) {
        SIZE_T ls = LocalSize(pb);
        CHECK(ls != 0 && ls != (SIZE_T)-1 && ls >= cb);
        if (ls != cb) t_note("LocalSize(encoded)=%lu cb=%lu", (unsigned long)ls, (unsigned long)cb);
        aic_free_enc(pb);
    }
}
TEST(aic_enc_two_calls_identical_distinct_buffers) {
    AIC_REQ();
    AIC_RP rp = RPV(1, L"example.com", L"Example", L"i"); AIC_USER us = USV(1, 2, (PBYTE)"\x01\x02", L"bob", L"x", L"Bob"); AIC_ACCT a = { 1, &rp, &us };
    DWORD c1 = 0, c2 = 0; PBYTE p1 = NULL, p2 = NULL;
    HR_EQ(aic_enc(&a, &c1, &p1), 0); HR_EQ(aic_enc(&a, &c2, &p2), 0);
    if (p1 && p2) { EXPECT_EQ(c1, c2); CHECK(p1 != p2); CHECK(c1 == c2 && memcmp(p1, p2, c1) == 0); }
    if (p1) aic_free_enc(p1);
    if (p2) aic_free_enc(p2);
}
TEST(aic_enc_output_does_not_alias_input) {
    AIC_REQ();
    WCHAR id[8] = L"abc"; BYTE uid[2] = { 9, 8 };
    AIC_RP rp = RPV(1, id, NULL, NULL); AIC_USER us = USV(1, 2, uid, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD cb = 0; PBYTE pb = NULL; HR_EQ(aic_enc(&a, &cb, &pb), 0);
    if (!pb) return;
    BYTE *copy = (BYTE *)malloc(cb); memcpy(copy, pb, cb);
    id[0] = L'z'; uid[0] = 0;
    CHECK(memcmp(copy, pb, cb) == 0);
    free(copy); aic_free_enc(pb);
}
TEST(aic_enc_input_not_modified) {
    AIC_REQ();
    AIC_RP rp = RPV(3, L"example.com", L"Ex", L"ic"); AIC_USER us = USV(4, 2, (PBYTE)"\x01\x02", L"bob", L"ic", L"Bob"); AIC_ACCT a = { 7, &rp, &us };
    AIC_RP rp0 = rp; AIC_USER us0 = us; AIC_ACCT a0 = a;
    DWORD cb = 0; PBYTE pb = NULL; HR_EQ(aic_enc(&a, &cb, &pb), 0);
    CHECK(memcmp(&rp, &rp0, sizeof rp) == 0 && memcmp(&us, &us0, sizeof us) == 0 && memcmp(&a, &a0, sizeof a) == 0);
    if (pb) aic_free_enc(pb);
}
TEST(aic_enc_input_in_guard_page_not_overread) {
    AIC_REQ();
    /* strings and id placed flush against a no-access page: encoder must read exactly the terminator and cbId bytes */
    GB gw, gb; const WCHAR s[] = L"example.com"; const BYTE id[5] = { 1, 2, 3, 4, 5 };
    if (!gb_make(&gw, s, sizeof s, 1) || !gb_make(&gb, id, sizeof id, 1)) { t_skip("VirtualAlloc"); return; }
    AIC_RP rp = RPV(1, (PCWSTR)gw.p, NULL, NULL); AIC_USER us = USV(1, 5, gb.p, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD cb = 0; PBYTE pb = NULL; HRESULT hr = aic_enc(&a, &cb, &pb);
    HR_EQ(hr, 0); EXPECT_EQ(cb, 31);
    if (pb) aic_free_enc(pb);
    gb_free(&gw); gb_free(&gb);
}
