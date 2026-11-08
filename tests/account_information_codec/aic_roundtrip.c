#include "aic.h"
#include <psapi.h>
/* Encode/decode round trips, mutation robustness (guard pages), free functions, leak loops, threads. */

#define RT(tn, rpargs, usargs) TEST(tn) { AIC_REQ(); AIC_RP rp = RPV rpargs; AIC_USER us = USV usargs; AIC_ACCT a = { 1, &rp, &us }; aic_roundtrip(&a); }
#define NOU (1, 0, NULL, NULL, NULL, NULL)

/* ---- ASCII ---------------------------------------------------------------------------- */
RT(aic_rt_minimal, (1, L"a", NULL, NULL), (1, 1, (PBYTE)"\x01", NULL, NULL, NULL))
RT(aic_rt_typical_rp_user, (1, L"example.com", L"Example Corp", L"https://example.com/icon.png"),
   (1, 16, (PBYTE)"0123456789abcdef", L"alice@example.com", L"https://example.com/alice.png", L"Alice Example"))
RT(aic_rt_rp_id_only_user_empty, (1, L"example.com", NULL, NULL), NOU)
RT(aic_rt_rp_id_name, (1, L"example.com", L"Example", NULL), NOU)
RT(aic_rt_rp_id_icon, (1, L"example.com", NULL, L"i"), NOU)
RT(aic_rt_user_id_only, (1, L"x", NULL, NULL), (1, 3, (PBYTE)"\x01\x02\x03", NULL, NULL, NULL))
RT(aic_rt_user_name_only, (1, L"x", NULL, NULL), (1, 0, NULL, L"bob", NULL, NULL))
RT(aic_rt_user_icon_only, (1, L"x", NULL, NULL), (1, 0, NULL, NULL, L"ic", NULL))
RT(aic_rt_user_display_only, (1, L"x", NULL, NULL), (1, 0, NULL, NULL, NULL, L"Bob"))
RT(aic_rt_user_name_display_same, (1, L"x", NULL, NULL), (1, 0, NULL, L"bob", NULL, L"bob"))
RT(aic_rt_all_fields_present, (1, L"rp", L"rpn", L"rpi"), (1, 4, (PBYTE)"\xDE\xAD\xBE\xEF", L"un", L"ui", L"ud"))
RT(aic_rt_empty_strings_all, (1, L"x", L"", L""), (1, 0, NULL, L"", L"", L""))
RT(aic_rt_rp_id_empty_decode_fails, (1, L"", L"n", L"i"), (1, 1, (PBYTE)"\x01", NULL, NULL, NULL))
RT(aic_rt_rp_id_null_decode_fails, (1, NULL, L"n", NULL), NOU)
RT(aic_rt_everything_empty_decode_fails, (1, NULL, NULL, NULL), NOU)
RT(aic_rt_single_char_everywhere, (1, L"r", L"n", L"i"), (1, 1, (PBYTE)"u", L"n", L"i", L"d"))
RT(aic_rt_numeric_strings, (1, L"0", L"1", L"2"), (1, 1, (PBYTE)"\x00", L"3", L"4", L"5"))
RT(aic_rt_whitespace_strings, (1, L" ", L"\t", L"\r\n"), (1, 0, NULL, L"  ", L"\t\t", L"\n"))
RT(aic_rt_url_like_strings, (1, L"login.example.co.uk:8443", L"Ex & Co <\"quoted\">", L"data:image/png;base64,AAAA"),
   (1, 1, (PBYTE)"\x01", L"a+b@c.d", L"file:///x", L"O'Brien"))
RT(aic_rt_json_like_strings, (1, L"{\"a\":[1,2]}", L"[]", L"null"), (1, 0, NULL, L"{}", L"\\", L"/"))
RT(aic_rt_version_values, (0x7FFFFFFF, L"a", NULL, NULL), (0xFFFFFFFF, 1, (PBYTE)"\x01", NULL, NULL, NULL))

/* ---- Unicode --------------------------------------------------------------------------- */
RT(aic_rt_unicode_latin1, (1, L"caf" L"\x00e9" L".example", L"Caf" L"\x00e9" L" " L"\x00dc" L"" L"\x00f1" L"" L"\x00ee" L"", NULL), (1, 0, NULL, L"Jos" L"\x00e9" L"", NULL, L"Jos" L"\x00e9" L" " L"\x00c1" L"lvarez"))
RT(aic_rt_unicode_greek, (1, L"" L"\x03b5" L"" L"\x03bb" L"" L"\x03bb" L"" L"\x03b7" L"" L"\x03bd" L"" L"\x03b9" L"" L"\x03ba" L"" L"\x03ac" L"", L"" L"\x0395" L"" L"\x03bb" L"" L"\x03bb" L"" L"\x03ac" L"" L"\x03b4" L"" L"\x03b1" L"", NULL), NOU)
RT(aic_rt_unicode_cyrillic, (1, L"" L"\x043f" L"" L"\x0440" L"" L"\x0438" L"" L"\x043c" L"" L"\x0435" L"" L"\x0440" L"", L"" L"\x041f" L"" L"\x0440" L"" L"\x0438" L"" L"\x043c" L"" L"\x0435" L"" L"\x0440" L"", NULL), (1, 0, NULL, L"" L"\x0418" L"" L"\x0432" L"" L"\x0430" L"" L"\x043d" L"", NULL, NULL))
RT(aic_rt_unicode_cjk, (1, L"" L"\x4f8b" L"" L"\x3048" L"", L"" L"\x4f8b" L"" L"\x3048" L"" L"\x682a" L"" L"\x5f0f" L"" L"\x4f1a" L"" L"\x793e" L"", NULL), (1, 0, NULL, L"" L"\x5c71" L"" L"\x7530" L"", NULL, L"" L"\x5c71" L"" L"\x7530" L"" L"\x592a" L"" L"\x90ce" L""))
RT(aic_rt_unicode_hangul, (1, L"" L"\xd55c" L"" L"\xae00" L"", L"" L"\xd55c" L"" L"\xad6d" L"", NULL), NOU)
RT(aic_rt_unicode_hebrew_arabic, (1, L"" L"\x05e9" L"" L"\x05dc" L"" L"\x05d5" L"" L"\x05dd" L"", L"" L"\x0645" L"" L"\x0631" L"" L"\x062d" L"" L"\x0628" L"" L"\x0627" L"", NULL), (1, 0, NULL, L"" L"\x05d3" L"" L"\x05d5" L"" L"\x05d3" L"", NULL, L"" L"\x0623" L"" L"\x062d" L"" L"\x0645" L"" L"\x062f" L""))
RT(aic_rt_unicode_thai_devanagari, (1, L"" L"\x0e2a" L"" L"\x0e27" L"" L"\x0e31" L"" L"\x0e2a" L"" L"\x0e14" L"" L"\x0e35" L"", L"" L"\x0928" L"" L"\x092e" L"" L"\x0938" L"" L"\x094d" L"" L"\x0924" L"" L"\x0947" L"", NULL), NOU)
RT(aic_rt_unicode_combining_marks, (1, L"e" L"\x0301" L"" L"\x0302" L"" L"\x0303" L"", L"a" L"\x0308" L"", NULL), NOU)
RT(aic_rt_unicode_emoji_surrogate_pairs, (1, L"\xD83D\xDE00\xD83C\xDF89", L"\xD83D\xDC68\x200D\xD83D\xDCBB", NULL), (1, 0, NULL, L"\xD83E\xDD84", NULL, L"x\xD83D\xDE00y"))
RT(aic_rt_unicode_bmp_edges, (1, L"\x7f\x80\x7ff\x800\xffff", L"\xd7ff\xe000\xfffd", NULL), NOU)
RT(aic_rt_unicode_plane_edges, (1, L"\xD800\xDC00\xDBFF\xDFFF", L"\xD83F\xDFFE", NULL), NOU)
RT(aic_rt_unicode_mixed_scripts, (1, L"a" L"\x00e9" L"" L"\x20ac" L"\xD83D\xDE00" L"\x4e2d" L"", L"" L"\x0416" L"z" L"\x05d0" L"", L"" L"\x2603" L""), (1, 2, (PBYTE)"\xC3\xA9", L"" L"\x2605" L"", L"" L"\x2606" L"", L"" L"\x2607" L""))
RT(aic_rt_unicode_bom_and_zero_width, (1, L"" L"\xfeff" L"abc" L"\x200b" L"", L"" L"\x200d" L"", NULL), NOU)
RT(aic_rt_unicode_only_in_user_fields, (1, L"example.com", NULL, NULL), (1, 0, NULL, L"" L"\x00e9" L"", L"" L"\x20ac" L"", L"\xD83D\xDE00"))

/* ---- user id binary patterns --------------------------------------------------------------- */
TEST(aic_rt_user_id_binary_patterns) {
    AIC_REQ();
    BYTE all[256], z[64], f[64], inc[64];
    for (int i = 0; i < 256; i++) all[i] = (BYTE)i;
    memset(z, 0, sizeof z); memset(f, 0xFF, sizeof f); for (int i = 0; i < 64; i++) inc[i] = (BYTE)(i * 4 + 1);
    const struct { const BYTE *p; DWORD n; } c[] = { { all, 256 }, { all, 1 }, { all + 255, 1 }, { z, 1 }, { z, 64 }, { f, 1 }, { f, 64 }, { inc, 64 }, { inc, 32 }, { all, 255 }, { all, 23 }, { all, 24 }, { all, 25 } };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        AIC_RP rp = RPV(1, L"x", NULL, NULL); AIC_USER us = USV(1, c[i].n, (PBYTE)c[i].p, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
        aic_roundtrip(&a);
    }
}
TEST(aic_rt_user_id_lengths_1_to_300) {
    AIC_REQ();
    BYTE id[300]; for (int i = 0; i < 300; i++) id[i] = (BYTE)(i ^ 0x5A);
    for (DWORD n = 1; n <= 300; n++) {
        AIC_RP rp = RPV(1, L"x", NULL, NULL); AIC_USER us = USV(1, n, id, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
        aic_roundtrip(&a);
    }
}
TEST(aic_rt_rp_id_lengths_1_to_300) {
    AIC_REQ();
    WCHAR w[301]; for (int i = 0; i < 300; i++) w[i] = L'a' + (WCHAR)(i % 26); w[300] = 0;
    for (int n = 1; n <= 300; n++) {
        WCHAR save = w[n]; w[n] = 0;
        AIC_RP rp = RPV(1, w, NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
        aic_roundtrip(&a); w[n] = save;
    }
}
TEST(aic_rt_utf8_width_boundaries_per_length) {
    AIC_REQ();
    /* strings whose UTF-8 length crosses the 23/24 and 255/256 header boundaries with multibyte characters */
    static const int euros[] = { 7, 8, 9, 10, 84, 85, 86, 87 };
    for (unsigned i = 0; i < sizeof euros / sizeof euros[0]; i++) {
        WCHAR w[100]; int n = euros[i]; for (int k = 0; k < n; k++) w[k] = 0x20AC; w[n] = 0;
        AIC_RP rp = RPV(1, w, w, w); AIC_USER us = USV(1, 1, (PBYTE)"\x01", w, w, w); AIC_ACCT a = { 1, &rp, &us };
        aic_roundtrip(&a);
    }
}

/* ---- all subsets of the optional members --------------------------------------------------- */
TEST(aic_rt_all_optional_member_subsets) {
    AIC_REQ();
    for (unsigned m = 0; m < 64; m++) {
        AIC_RP rp = RPV(1, L"example.com", (m & 1) ? L"Name" : NULL, (m & 2) ? L"Icon" : NULL);
        AIC_USER us = USV(1, (m & 4) ? 3 : 0, (PBYTE)"\x01\x02\x03", (m & 8) ? L"un" : NULL, (m & 16) ? L"ui" : NULL, (m & 32) ? L"ud" : NULL);
        AIC_ACCT a = { 1, &rp, &us }; aic_roundtrip(&a);
    }
}
TEST(aic_rt_all_optional_subsets_with_empty_strings) {
    AIC_REQ();
    for (unsigned m = 0; m < 64; m++) {
        AIC_RP rp = RPV(1, L"example.com", (m & 1) ? L"" : NULL, (m & 2) ? L"" : NULL);
        AIC_USER us = USV(1, 0, (m & 4) ? (PBYTE)"\x01" : NULL, (m & 8) ? L"" : NULL, (m & 16) ? L"" : NULL, (m & 32) ? L"" : NULL);
        AIC_ACCT a = { 1, &rp, &us }; aic_roundtrip(&a);
    }
}

/* ---- re-encode canonical form -------------------------------------------------------------- */
TEST(aic_rt_decode_then_reencode_is_byte_identical) {
    AIC_REQ();
    AIC_RP rp = RPV(1, L"example.com", L"Ex" L"\x00e9" L"", L"i"); AIC_USER us = USV(1, 5, (PBYTE)"\x01\x02\x03\x04\x05", L"b" L"\x20ac" L"", L"u", L"\xD83D\xDE00"); AIC_ACCT a = { 1, &rp, &us };
    DWORD c1 = 0; PBYTE p1 = NULL; HR_EQ(aic_enc(&a, &c1, &p1), 0); if (!p1) return;
    AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(p1, c1, 1, &o), 0);
    if (o) {
        DWORD c2 = 0; PBYTE p2 = NULL; HR_EQ(aic_enc(o, &c2, &p2), 0);
        if (p2) { EXPECT_EQ(c2, c1); CHECK(c1 == c2 && !memcmp(p1, p2, c1)); aic_free_enc(p2); }
        aic_free_dec(o);
    }
    aic_free_enc(p1);
}
TEST(aic_rt_decoded_account_usable_as_encode_input_repeatedly) {
    AIC_REQ();
    SPEC s = { .ver = 9, .has_rp = 1, .has_user = 1, .rid = "a.b", .uid = "\x01", .ucb = 1 };
    B b; b_init(&b, 128); b_acct(&b, &s);
    AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(b.d, b.n, 1, &o), 0);
    if (o) {
        PBYTE first = NULL; DWORD fc = 0;
        for (int i = 0; i < 5; i++) {
            DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(o, &c, &p), 0);
            if (!p) break;
            if (!first) { first = p; fc = c; } else { CHECK(c == fc && !memcmp(p, first, c)); aic_free_enc(p); }
        }
        if (first) aic_free_enc(first);
        aic_free_dec(o);
    }
    b_done(&b);
}
TEST(aic_rt_encoded_blob_version_key_is_one_regardless_of_input) {
    AIC_REQ();
    AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 42, &rp, &us };
    DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0);
    if (p) {
        AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(p, c, 1, &o), 0);
        if (o) { EXPECT_EQ(o->dwVersion, 1); aic_free_dec(o); }
        aic_free_enc(p);
    }
}

/* ---- limits through the full path ------------------------------------------------------- */
static void rt_len(size_t cch, int expect_dec_ok) {
    WCHAR *w = (WCHAR *)malloc((cch + 1) * 2); for (size_t i = 0; i < cch; i++) w[i] = L'k'; w[cch] = 0;
    AIC_RP rp = RPV(1, w, NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0);
    if (p) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(p, c, 1, &o);
        if (expect_dec_ok) { HR_EQ(hr, 0); if (hr == 0) { CHECK(lstrlenW(o->pRp->pwszId) == (int)cch); aic_free_dec(o); } }
        else { HR_EQ(hr, HR_INVALID_DATA); CHECK(o == SENT_PTR); }
        aic_free_enc(p);
    }
    free(w);
}
TEST(aic_rt_limit_rp_id_8163_roundtrips) { AIC_REQ(); rt_len(8163, 1); }
TEST(aic_rt_limit_rp_id_8164_encodes_but_does_not_decode) { AIC_REQ(); rt_len(8164, 0); }
TEST(aic_rt_limit_rp_id_20000_encodes_but_does_not_decode) { AIC_REQ(); rt_len(20000, 0); }
TEST(aic_rt_limit_user_id_16384_roundtrips) {
    AIC_REQ(); BYTE *id = (BYTE *)malloc(16384); for (int i = 0; i < 16384; i++) id[i] = (BYTE)(i * 3);
    AIC_RP rp = RPV(1, L"x", NULL, NULL); AIC_USER us = USV(1, 16384, id, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us }; aic_roundtrip(&a); free(id);
}
TEST(aic_rt_limit_user_id_16385_does_not_decode) {
    AIC_REQ(); BYTE *id = (BYTE *)malloc(16385); memset(id, 0x42, 16385);
    AIC_RP rp = RPV(1, L"x", NULL, NULL); AIC_USER us = USV(1, 16385, id, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0);
    if (p) { AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HR_EQ(aic_dec_g(p, c, 1, &o), HR_INVALID_DATA); CHECK(o == SENT_PTR); aic_free_enc(p); }
    free(id);
}
TEST(aic_rt_moderately_large_all_members) {
    AIC_REQ();
    WCHAR *w = (WCHAR *)malloc(1001 * 2); for (int i = 0; i < 1000; i++) w[i] = L'a' + (WCHAR)(i % 26); w[1000] = 0;
    BYTE *id = (BYTE *)malloc(4000); for (int i = 0; i < 4000; i++) id[i] = (BYTE)i;
    AIC_RP rp = RPV(1, w, w, w); AIC_USER us = USV(1, 4000, id, w, w, w); AIC_ACCT a = { 1, &rp, &us }; aic_roundtrip(&a);
    free(w); free(id);
}
TEST(aic_rt_encode_huge_binary_id_100000) {
    AIC_REQ();
    BYTE *id = (BYTE *)malloc(100000); for (int i = 0; i < 100000; i++) id[i] = (BYTE)(i >> 3);
    AIC_RP rp = RPV(1, L"x", NULL, NULL); AIC_USER us = USV(1, 100000, id, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0);
    if (p) { EXPECT_EQ(c, 10 + 5 + 5 + 100000);   /* rp {id:"x"} adds 5 bytes over the empty map */ aic_free_enc(p); }
    free(id);
}

/* ---- mutation robustness -------------------------------------------------------------------- */
static int hr_known(HRESULT hr) {
    return hr == 0 || hr == HR_INVALID_DATA || hr == HR_NO_MEDIA || hr == HR_BAD_TYPE || hr == HR_BAD_LENGTH || hr == HR_NOMEM;
}
static void dec_mut(const BYTE *d, size_t n, unsigned *ok, unsigned *bad) {
    for (int tail = 1; tail >= 0; tail--) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, n, tail, &o);
        CHECKF(hr_known(hr), "unexpected hr 0x%08lx", (unsigned long)hr);
        if (hr == 0) {
            (*ok)++;
            if (o != SENT_PTR && o) { aic_check_block(o); aic_free_dec(o); }
            else CHECK(0);
        } else { (*bad)++; CHECK(o == SENT_PTR); }
    }
}
static size_t make_full(BYTE *out, size_t cap) {
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "example.com", .rname = "Ex\xC3\xA9", .ricon = "i", .uid = "\x01\x02\x03\x04", .ucb = 4, .uname = "bob", .uicon = "u", .udisp = "Bob\xE2\x82\xAC" };
    B b; b_init(&b, cap); b_acct(&b, &s); size_t n = b.n; memcpy(out, b.d, n); b_done(&b); return n;
}
TEST(aic_mut_single_bit_flips_full_document) {
    AIC_REQ(); BYTE d[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    for (size_t i = 0; i < n; i++) for (int bit = 0; bit < 8; bit++) {
        d[i] ^= (BYTE)(1 << bit); dec_mut(d, n, &ok, &bad); d[i] ^= (BYTE)(1 << bit);
    }
    t_note("bit flips: %u decodes succeeded, %u failed (document %u bytes)", ok, bad, (unsigned)n);
}
TEST(aic_mut_single_bit_flips_minimal_document) {
    AIC_REQ(); BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 }; unsigned ok = 0, bad = 0;
    for (size_t i = 0; i < sizeof d; i++) for (int bit = 0; bit < 8; bit++) { d[i] ^= (BYTE)(1 << bit); dec_mut(d, sizeof d, &ok, &bad); d[i] ^= (BYTE)(1 << bit); }
    t_note("bit flips: %u ok, %u failed", ok, bad);
}
TEST(aic_mut_byte_substitution_full_document) {
    AIC_REQ(); BYTE d[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    static const BYTE vals[] = { 0x00, 0xFF, 0x80, 0xA0, 0x1F, 0x1B, 0xBF, 0x7F, 0x5F, 0xC0, 0xF8 };
    for (size_t i = 0; i < n; i++) for (unsigned v = 0; v < sizeof vals; v++) {
        BYTE keep = d[i]; d[i] = vals[v]; dec_mut(d, n, &ok, &bad); d[i] = keep;
    }
    t_note("substitutions: %u ok, %u failed", ok, bad);
}
TEST(aic_mut_byte_deletion_full_document) {
    AIC_REQ(); BYTE d[512], t[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    for (size_t i = 0; i < n; i++) { memcpy(t, d, i); memcpy(t + i, d + i + 1, n - i - 1); dec_mut(t, n - 1, &ok, &bad); }
    t_note("deletions: %u ok, %u failed", ok, bad);
}
TEST(aic_mut_byte_insertion_full_document) {
    AIC_REQ(); BYTE d[512], t[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    for (size_t i = 0; i <= n; i++) for (int v = 0; v < 2; v++) {
        memcpy(t, d, i); t[i] = v ? 0xFF : 0x00; memcpy(t + i + 1, d + i, n - i); dec_mut(t, n + 1, &ok, &bad);
    }
    t_note("insertions: %u ok, %u failed", ok, bad);
}
TEST(aic_mut_guard_page_exact_fit_valid_document) {
    AIC_REQ(); BYTE d[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    dec_mut(d, n, &ok, &bad); EXPECT_EQ(ok, 2); EXPECT_EQ(bad, 0);
}
TEST(aic_mut_every_prefix_guard_pages_no_overread) {
    AIC_REQ(); BYTE d[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0;
    for (size_t k = 0; k < n; k++) dec_mut(d, k, &ok, &bad);
    EXPECT_EQ(ok, 0);
}
TEST(aic_mut_pseudo_random_in_process) {
    AIC_REQ(); BYTE d[512], t[512]; size_t n = make_full(d, sizeof d); unsigned ok = 0, bad = 0; unsigned long long s = 0x9E3779B97F4A7C15ull;
    for (int it = 0; it < 3000; it++) {
        memcpy(t, d, n); int k = 1 + (int)((s >> 33) % 4);
        for (int j = 0; j < k; j++) { s = s * 6364136223846793005ull + 1442695040888963407ull; t[(s >> 33) % n] = (BYTE)(s >> 24); }
        dec_mut(t, n, &ok, &bad);
    }
    t_note("random mutations: %u ok, %u failed", ok, bad);
}
CHILD(aic_fuzz) {
    UN(WebAuthNDecodeAccountInformation); if (!UN(WebAuthNDecodeAccountInformation) || !UN(WebAuthNFreeDecodedAccountInformation)) return 77;
    BYTE d[512], t[512]; size_t n = make_full(d, sizeof d); unsigned long long s = 0x1234567887654321ull;
    for (int it = 0; it < 30000; it++) {
        size_t len = n; memcpy(t, d, n);
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        int k = 1 + (int)((s >> 33) % 6);
        for (int j = 0; j < k; j++) { s = s * 6364136223846793005ull + 1442695040888963407ull; t[(s >> 33) % n] = (BYTE)(s >> 24); }
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        if (((s >> 40) & 7) == 0) len = (s >> 20) % (n + 1);
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; GB g;
        if (!gb_make(&g, t, len, it & 1)) return 78;
        HRESULT hr = UN(WebAuthNDecodeAccountInformation)((DWORD)len, g.p, &o);
        gb_free(&g);
        if (!hr_known(hr)) return 79;
        if (hr == 0) { if (o == SENT_PTR || !o) return 80; UN(WebAuthNFreeDecodedAccountInformation)(o); }
        else if (o != SENT_PTR) return 81;
    }
    return 0;
}
TEST(aic_mut_pseudo_random_isolated_child_30000) {
    AIC_REQ();
    DWORD code = t_run_child("aic_fuzz", "", 120000);
    if (code == 77) { t_skip("exports missing in child"); return; }
    CHECKF(code == 0, "child exit code 0x%lx (0xDEAD0001 = timeout)", (unsigned long)code);
}

/* ---- free functions -------------------------------------------------------------------- */
TEST(aic_free_encoded_null_is_noop) { AIC_REQ(); aic_free_enc(NULL); aic_free_enc(NULL); CHECK(1); }
TEST(aic_free_decoded_null_is_noop) { AIC_REQ(); aic_free_dec(NULL); aic_free_dec(NULL); CHECK(1); }
TEST(aic_free_preserves_last_error) {
    AIC_REQ(); WebAuthNFreeEncodedAccountInformation_pfn fe = UN(WebAuthNFreeEncodedAccountInformation);
    WebAuthNFreeDecodedAccountInformation_pfn fd = UN(WebAuthNFreeDecodedAccountInformation);
    SET_ERR(0x1234); fe(NULL); EXPECT_EQ(GetLastError(), 0x1234); fd(NULL); EXPECT_EQ(GetLastError(), 0x1234);
}
TEST(aic_free_after_encode_then_encode_again) {
    AIC_REQ(); AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    for (int i = 0; i < 20; i++) { DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0); CHECK(p != NULL); aic_free_enc(p); }
}
TEST(aic_free_after_decode_then_decode_again) {
    AIC_REQ(); static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    for (int i = 0; i < 20; i++) { AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(d, sizeof d, 1, &o), 0); CHECK(o != NULL); if (o) aic_free_dec(o); }
}
TEST(aic_free_functions_are_interchangeable) {
    AIC_REQ();
    /* all four Free* exports release a LocalAlloc block; record whether they share one entry point */
    FARPROC f1 = t_proc("WebAuthNFreeEncodedAccountInformation"), f2 = t_proc("WebAuthNFreeDecodedAccountInformation");
    t_note("FreeEncoded=%p FreeDecoded=%p same=%d", (void *)f1, (void *)f2, f1 == f2);
    AIC_RP rp = RPV(1, L"a", NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    DWORD c = 0; PBYTE p = NULL; HR_EQ(aic_enc(&a, &c, &p), 0);
    if (p) { AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(p, c, 1, &o), 0); aic_free_dec(p); if (o) aic_free_enc(o); }
}
TEST(aic_free_decoded_block_is_local_alloc) {
    AIC_REQ(); static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(d, sizeof d, 1, &o), 0);
    if (o) { SIZE_T s = LocalSize(o); CHECK(s != 0 && s != (SIZE_T)-1 && s >= 0x60); LocalFree(o); }
}
TEST(aic_free_decoded_one_free_releases_whole_graph) {
    AIC_REQ(); SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .rname = "b", .ricon = "c", .uid = "\x01", .ucb = 1, .uname = "d", .uicon = "e", .udisp = "f" };
    B b; b_init(&b, 256); b_acct(&b, &s);
    for (int i = 0; i < 200; i++) { AIC_ACCT *o = NULL; HR_EQ(aic_dec_g(b.d, b.n, 1, &o), 0); if (o) { CHECK(LocalSize(o) >= 0x90); aic_free_dec(o); } }
    b_done(&b);
}

/* ---- leak loops and threads ---------------------------------------------------------------- */
typedef BOOL (WINAPI *pfnGPMI)(HANDLE, PROCESS_MEMORY_COUNTERS *, DWORD);
static SIZE_T working_set(void) {
    static pfnGPMI f; PROCESS_MEMORY_COUNTERS pm; if (!f) f = (pfnGPMI)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetProcessMemoryInfo");
    if (!f) return 0; memset(&pm, 0, sizeof pm); pm.cb = sizeof pm; return f(GetCurrentProcess(), &pm, sizeof pm) ? pm.WorkingSetSize : 0;
}
TEST(aic_loop_encode_free_10000) {
    AIC_REQ(); AIC_RP rp = RPV(1, L"example.com", L"Example", L"i"); AIC_USER us = USV(1, 8, (PBYTE)"abcdefgh", L"bob", L"u", L"Bob"); AIC_ACCT a = { 1, &rp, &us };
    SIZE_T w0 = working_set(); int bad = 0;
    for (int i = 0; i < 10000; i++) { DWORD c = 0; PBYTE p = NULL; if (aic_enc(&a, &c, &p) != 0 || !p) { bad++; continue; } aic_free_enc(p); }
    EXPECT_EQ(bad, 0); SIZE_T w1 = working_set();
    t_note("working set before %lu KiB, after %lu KiB (delta %ld KiB)", (unsigned long)(w0 / 1024), (unsigned long)(w1 / 1024), (long)((long long)w1 - (long long)w0) / 1024);
}
TEST(aic_loop_decode_free_10000) {
    AIC_REQ(); SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "example.com", .rname = "Example", .ricon = "i", .uid = "abcdefgh", .ucb = 8, .uname = "bob", .uicon = "u", .udisp = "Bob" };
    B b; b_init(&b, 256); b_acct(&b, &s);
    SIZE_T w0 = working_set(); int bad = 0;
    for (int i = 0; i < 10000; i++) { AIC_ACCT *o = NULL; if (UN(WebAuthNDecodeAccountInformation)((DWORD)b.n, b.d, &o) != 0 || !o) { bad++; continue; } aic_free_dec(o); }
    EXPECT_EQ(bad, 0); SIZE_T w1 = working_set();
    t_note("working set before %lu KiB, after %lu KiB (delta %ld KiB)", (unsigned long)(w0 / 1024), (unsigned long)(w1 / 1024), (long)((long long)w1 - (long long)w0) / 1024);
    b_done(&b);
}
TEST(aic_loop_decode_failure_10000_no_growth) {
    AIC_REQ(); static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 0xFF };
    SIZE_T w0 = working_set(); int bad = 0;
    for (int i = 0; i < 10000; i++) { AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; if (UN(WebAuthNDecodeAccountInformation)(sizeof d, d, &o) != HR_INVALID_DATA || o != SENT_PTR) bad++; }
    EXPECT_EQ(bad, 0); SIZE_T w1 = working_set();
    t_note("failure loop working set delta %ld KiB", (long)((long long)w1 - (long long)w0) / 1024);
}
TEST(aic_loop_encode_failure_10000_no_growth) {
    AIC_REQ(); AIC_RP rp = RPV(1, L"a\xD800", NULL, NULL); AIC_USER us = USV(1, 0, NULL, NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    if (t_is_wine()) { t_skip("wine"); return; }
    SIZE_T w0 = working_set(); int bad = 0;
    for (int i = 0; i < 10000; i++) { DWORD c = SENT_CB; PBYTE p = (PBYTE)SENT_PTR; if (aic_enc(&a, &c, &p) != HR_INVALID_DATA || p != SENT_PTR) bad++; }
    EXPECT_EQ(bad, 0); SIZE_T w1 = working_set();
    t_note("failure loop working set delta %ld KiB", (long)((long long)w1 - (long long)w0) / 1024);
}
TEST(aic_loop_roundtrip_large_1000) {
    AIC_REQ(); WCHAR *w = (WCHAR *)malloc(4001 * 2); for (int i = 0; i < 4000; i++) w[i] = L'a' + (WCHAR)(i % 26); w[4000] = 0;
    AIC_RP rp = RPV(1, w, w, NULL); AIC_USER us = USV(1, 1, (PBYTE)"\x01", NULL, NULL, NULL); AIC_ACCT a = { 1, &rp, &us };
    SIZE_T w0 = working_set();
    for (int i = 0; i < 1000; i++) aic_roundtrip(&a);
    t_note("large round trip x1000 working set delta %ld KiB", (long)((long long)working_set() - (long long)w0) / 1024);
    free(w);
}
static volatile LONG g_thr_bad;
static DWORD WINAPI thr_main(LPVOID arg) {
    int id = (int)(INT_PTR)arg;
    WCHAR name[32]; wsprintfW(name, L"thread-%d", id);
    AIC_RP rp = RPV(1, L"example.com", name, NULL); AIC_USER us = USV(1, 4, (PBYTE)"\x01\x02\x03\x04", name, NULL, name); AIC_ACCT a = { 1, &rp, &us };
    for (int i = 0; i < 2000; i++) {
        DWORD c = 0; PBYTE p = NULL; AIC_ACCT *o = NULL;
        if (aic_enc(&a, &c, &p) != 0 || !p) { InterlockedIncrement(&g_thr_bad); continue; }
        if (UN(WebAuthNDecodeAccountInformation)(c, p, &o) != 0 || !o) InterlockedIncrement(&g_thr_bad);
        else { if (!o->pRp || !o->pUser || lstrcmpW(o->pUser->pwszName, name) != 0) InterlockedIncrement(&g_thr_bad); aic_free_dec(o); }
        aic_free_enc(p);
    }
    return 0;
}
TEST(aic_threads_concurrent_roundtrips) {
    AIC_REQ(); HANDLE h[4]; g_thr_bad = 0;
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, thr_main, (LPVOID)(INT_PTR)i, 0, NULL);
    DWORD w = WaitForMultipleObjects(4, h, TRUE, 30000);
    CHECK(w == WAIT_OBJECT_0);
    if (w != WAIT_OBJECT_0) for (int i = 0; i < 4; i++) TerminateThread(h[i], 1);
    for (int i = 0; i < 4; i++) CloseHandle(h[i]);
    EXPECT_EQ(g_thr_bad, 0);
}
struct DA { AIC_ACCT *o; HRESULT hr; };
static DWORD WINAPI dec_thread(LPVOID p) {
    static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    struct DA *x = (struct DA *)p; x->hr = UN(WebAuthNDecodeAccountInformation)(sizeof d, d, &x->o); return 0;
}
TEST(aic_decode_from_other_thread_result_freed_on_main) {
    AIC_REQ();
    struct DA a = { 0, 0 };
    HANDLE h = CreateThread(NULL, 0, dec_thread, &a, 0, NULL); WaitForSingleObject(h, 10000); CloseHandle(h);
    HR_EQ(a.hr, 0); if (a.o) aic_free_dec(a.o);
}
