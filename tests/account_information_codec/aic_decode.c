#include "aic.h"
/* WebAuthNDecodeAccountInformation: hand-built CBOR, error classes, limits. */

/* ---- helpers ------------------------------------------------------------------------- */
static void check_spec(const AIC_ACCT *o, const SPEC *s) {
    CHECK(o != NULL); if (!o) return;
    EXPECT_EQ(o->dwVersion, s->ver < 0 ? 0 : (unsigned)s->ver);
    CHECK(o->pRp != NULL && o->pUser != NULL);
    if (!o->pRp || !o->pUser) return;
    EXPECT_EQ(o->pRp->dwVersion, 1);
    EXPECT_EQ(o->pUser->dwVersion, 1);
    CHECK(aic_streq(o->pRp->pwszId, s->rid));
    CHECK(aic_streq(o->pRp->pwszName, s->rname));
    CHECK(aic_streq(o->pRp->pwszIcon, s->ricon));
    CHECK(aic_streq(o->pUser->pwszName, s->uname));
    CHECK(aic_streq(o->pUser->pwszIcon, s->uicon));
    CHECK(aic_streq(o->pUser->pwszDisplayName, s->udisp));
    if (!s->uid || s->ucb == 0) { EXPECT_EQ(o->pUser->cbId, 0); }
    else { EXPECT_EQ(o->pUser->cbId, s->ucb); CHECK(o->pUser->pbId && o->pUser->cbId == s->ucb && !memcmp(o->pUser->pbId, s->uid, s->ucb)); }
    if (!s->uid) CHECK(o->pUser->pbId == NULL);
}
static void dec_spec(const SPEC *s) {
    B b; b_init(&b, 70000); b_acct(&b, s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, 0, "spec decode");
    if (o) { check_spec(o, s); aic_free_dec(o); }
    b_done(&b);
}
#define SPEC_TEST(tn, ...) TEST(tn) { AIC_REQ(); SPEC s = { __VA_ARGS__ }; dec_spec(&s); }
#define DEC_HR(tn, hr, ...) TEST(tn) { AIC_REQ(); static const BYTE d[] = { __VA_ARGS__ }; AIC_ACCT *o_ = EXPECT_DEC(d, sizeof d, hr); if (o_) aic_free_dec(o_); }

/* ---- successful decodes ---------------------------------------------------------------- */
SPEC_TEST(aic_dec_ok_minimal, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a")
SPEC_TEST(aic_dec_ok_no_version_key_gives_zero, .ver = -1, .has_rp = 1, .has_user = 1, .rid = "a")
SPEC_TEST(aic_dec_ok_version_zero, .ver = 0, .has_rp = 1, .has_user = 1, .rid = "a")
SPEC_TEST(aic_dec_ok_version_two, .ver = 2, .has_rp = 1, .has_user = 1, .rid = "a")
SPEC_TEST(aic_dec_ok_version_large, .ver = 0x7FFFFFFF, .has_rp = 1, .has_user = 1, .rid = "a")
SPEC_TEST(aic_dec_ok_user_first_order, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uname = "u", .user_first = 1)
SPEC_TEST(aic_dec_ok_all_rp_fields, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "example.com", .rname = "Example", .ricon = "https://x/i.png")
SPEC_TEST(aic_dec_ok_all_user_fields, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = "\x01\x02\x03\x04", .ucb = 4, .uname = "bob", .uicon = "i", .udisp = "Bob B")
SPEC_TEST(aic_dec_ok_user_id_only, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = "\xFF\x00\xFF", .ucb = 3)
SPEC_TEST(aic_dec_ok_user_name_only, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uname = "n")
SPEC_TEST(aic_dec_ok_user_display_only, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .udisp = "d")
SPEC_TEST(aic_dec_ok_user_icon_only, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uicon = "i")
SPEC_TEST(aic_dec_ok_rp_name_only_plus_id, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .rname = "n")
SPEC_TEST(aic_dec_ok_rp_icon_only_plus_id, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .ricon = "i")
SPEC_TEST(aic_dec_ok_empty_rp_id_string_is_nonnull_empty, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "")
SPEC_TEST(aic_dec_ok_empty_strings_everywhere_nonnull, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "", .rname = "", .ricon = "", .uname = "", .uicon = "", .udisp = "")
SPEC_TEST(aic_dec_ok_user_id_zero_length, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = "", .ucb = 0)
SPEC_TEST(aic_dec_ok_utf8_two_byte, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "\xC3\xA9", .uname = "\xC3\xA9\xC3\xA8")
SPEC_TEST(aic_dec_ok_utf8_three_byte, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "\xE2\x82\xAC", .udisp = "\xE6\x97\xA5\xE6\x9C\xAC")
SPEC_TEST(aic_dec_ok_utf8_four_byte, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "\xF0\x9F\x98\x80", .ricon = "\xF0\x9F\x8E\x89")
SPEC_TEST(aic_dec_ok_utf8_rtl_text, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "\xD7\xA9\xD7\x9C\xD7\x95\xD7\x9D", .uname = "\xD8\xB3\xD9\x84\xD8\xA7\xD9\x85")
SPEC_TEST(aic_dec_ok_control_chars_in_text, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a\tb\nc\x01")
SPEC_TEST(aic_dec_ok_long_ascii_strings, .ver = 1, .has_rp = 1, .has_user = 1, .rid = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789", .uname = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789")

TEST(aic_dec_ok_version_values_table) {
    AIC_REQ();
    static const unsigned vers[] = { 0, 1, 2, 3, 255, 256, 65535, 65536, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
    for (unsigned i = 0; i < sizeof vers / sizeof vers[0]; i++) {
        B b; b_init(&b, 256);
        b_head(&b, 5, 3); b_uint(&b, 1); b_uint(&b, vers[i]);
        b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a");
        b_uint(&b, 3); b_head(&b, 5, 0);
        AIC_ACCT *o = aic_expect_dec(b.d, b.n, 0, "version value");
        if (o) { EXPECT_EQ(o->dwVersion, vers[i]); aic_free_dec(o); }
        b_done(&b);
    }
}
TEST(aic_dec_ok_user_id_all_byte_values) {
    AIC_REQ(); BYTE id[256]; for (int i = 0; i < 256; i++) id[i] = (BYTE)i;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = id, .ucb = 256 }; dec_spec(&s);
}
TEST(aic_dec_ok_user_id_lengths_table) {
    AIC_REQ();
    static const size_t lens[] = { 1, 2, 23, 24, 25, 64, 255, 256, 257, 1000, 4096 };
    for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        BYTE *id = (BYTE *)malloc(lens[i]); for (size_t k = 0; k < lens[i]; k++) id[k] = (BYTE)(k * 13 + 5);
        SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = id, .ucb = lens[i] }; dec_spec(&s); free(id);
    }
}
TEST(aic_dec_ok_text_lengths_table) {
    AIC_REQ();
    static const size_t lens[] = { 1, 22, 23, 24, 25, 255, 256, 257, 1000, 4000 };
    for (unsigned i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char *t = (char *)malloc(lens[i] + 1); for (size_t k = 0; k < lens[i]; k++) t[k] = (char)('a' + k % 26); t[lens[i]] = 0;
        SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = t, .uname = t }; dec_spec(&s); free(t);
    }
}

/* ---- decoded block layout ------------------------------------------------------------- */
TEST(aic_dec_layout_single_block_sequential) {
    AIC_REQ();
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "rp.example", .rname = "RP", .ricon = "ic",
               .uid = "\x01\x02\x03", .ucb = 3, .uname = "bob", .uicon = "u", .udisp = "Bobby" };
    B b; b_init(&b, 512); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, 0, "layout");
    if (o) {
        const BYTE *base = (const BYTE *)o;
        CHECK((const BYTE *)o->pRp == base + 0x18);
        CHECK((const BYTE *)o->pRp->pwszId == base + 0x38);
        CHECK((const BYTE *)o->pRp->pwszName == base + 0x50);
        CHECK((const BYTE *)o->pRp->pwszIcon == base + 0x58);
        CHECK((const BYTE *)o->pUser == base + 0x60);
        CHECK((const BYTE *)o->pUser->pbId == base + 0x88);
        CHECK((const BYTE *)o->pUser->pwszName == base + 0x90);
        CHECK((const BYTE *)o->pUser->pwszIcon == base + 0x98);
        CHECK((const BYTE *)o->pUser->pwszDisplayName == base + 0xA0);
        SIZE_T ls = LocalSize(o); CHECK(ls >= 0xB0);
        if (ls != 0xB0) t_note("LocalSize(decoded)=0x%lx (expected block 0xB0)", (unsigned long)ls);
        check_spec(o, &s); aic_free_dec(o);
    }
    b_done(&b);
}
TEST(aic_dec_layout_pointers_8_aligned) {
    AIC_REQ();
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "x", .rname = "yy", .ricon = "zzz", .uid = "\x01", .ucb = 1, .uname = "q", .uicon = "rr", .udisp = "sss" };
    B b; b_init(&b, 512); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, 0, "align");
    if (o) {
        const void *ps[] = { o->pRp, o->pRp->pwszId, o->pRp->pwszName, o->pRp->pwszIcon, o->pUser, o->pUser->pbId, o->pUser->pwszName, o->pUser->pwszIcon, o->pUser->pwszDisplayName };
        for (unsigned i = 0; i < sizeof ps / sizeof ps[0]; i++) CHECK(((ULONG_PTR)ps[i] & 7) == 0);
        aic_free_dec(o);
    }
    b_done(&b);
}
TEST(aic_dec_result_independent_of_input_buffer) {
    AIC_REQ();
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "abc", .uid = "\x09", .ucb = 1, .uname = "n" };
    B b; b_init(&b, 256); b_acct(&b, &s);
    BYTE *copy = (BYTE *)malloc(b.n); memcpy(copy, b.d, b.n);
    AIC_ACCT *o = NULL; HRESULT hr = UN(WebAuthNDecodeAccountInformation)((DWORD)b.n, copy, &o);
    HR_EQ(hr, 0);
    memset(copy, 0xEE, b.n);
    if (o) { check_spec(o, &s); aic_free_dec(o); }
    free(copy); b_done(&b);
}

/* ---- top-level malformed input ---------------------------------------------------------- */
TEST(aic_dec_empty_input_size_zero_null_pointer) {
    AIC_REQ(); AIC_ACCT *out = (AIC_ACCT *)SENT_PTR;
    HRESULT hr = UN(WebAuthNDecodeAccountInformation)(0, NULL, &out);
    HR_EQ(hr, HR_NO_MEDIA); CHECK(out == SENT_PTR);
}
TEST(aic_dec_empty_input_size_zero_valid_pointer) {
    AIC_REQ(); EXPECT_DEC("", 0, HR_NO_MEDIA);
}
TEST(aic_dec_size_zero_but_data_present) {
    AIC_REQ(); static const BYTE d[] = { 0xA0 }; AIC_ACCT *out = (AIC_ACCT *)SENT_PTR;
    HRESULT hr = UN(WebAuthNDecodeAccountInformation)(0, d, &out);
    HR_EQ(hr, HR_NO_MEDIA); CHECK(out == SENT_PTR);
}
TEST(aic_dec_size_limits_input_to_prefix) {
    AIC_REQ();
    /* A valid blob handed over with size cut by one byte must not be read past the stated size. */
    static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0); if (o) aic_free_dec(o);
    AIC_ACCT *p = aic_expect_dec(d, sizeof d - 1, HR_NO_MEDIA, "cut by one"); if (p) aic_free_dec(p);
}
/* wrong CBOR major type / simple value at top level */
DEC_HR(aic_dec_top_uint_zero, HR_BAD_TYPE, 0x00)
DEC_HR(aic_dec_top_uint_23, HR_BAD_TYPE, 0x17)
DEC_HR(aic_dec_top_uint_1byte, HR_BAD_TYPE, 0x18, 0x40)
DEC_HR(aic_dec_top_uint_8byte, HR_BAD_TYPE, 0x1B, 1, 2, 3, 4, 5, 6, 7, 8)
DEC_HR(aic_dec_top_negint, HR_BAD_TYPE, 0x20)
DEC_HR(aic_dec_top_bytes_empty, HR_BAD_TYPE, 0x40)
DEC_HR(aic_dec_top_bytes_with_map_inside, HR_BAD_TYPE, 0x43, 0xA1, 0x01, 0x01)
DEC_HR(aic_dec_top_text_empty, HR_BAD_TYPE, 0x60)
DEC_HR(aic_dec_top_text, HR_BAD_TYPE, 0x62, 'i', 'd')
DEC_HR(aic_dec_top_array_empty, HR_BAD_TYPE, 0x80)
DEC_HR(aic_dec_top_array_of_maps, HR_BAD_TYPE, 0x81, 0xA0)
DEC_HR(aic_dec_top_tag_wrapping_map, HR_BAD_TYPE, 0xC1, 0xA0)
DEC_HR(aic_dec_top_false, HR_BAD_TYPE, 0xF4)
DEC_HR(aic_dec_top_true, HR_BAD_TYPE, 0xF5)
DEC_HR(aic_dec_top_null, HR_BAD_TYPE, 0xF6)
DEC_HR(aic_dec_top_undefined, HR_BAD_TYPE, 0xF7)
DEC_HR(aic_dec_top_float16, HR_BAD_TYPE, 0xF9, 0x3C, 0x00)
DEC_HR(aic_dec_top_float32, HR_BAD_TYPE, 0xFA, 0x3F, 0x80, 0, 0)
DEC_HR(aic_dec_top_float64, HR_BAD_TYPE, 0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0)
DEC_HR(aic_dec_top_indefinite_bytes, HR_BAD_TYPE, 0x5F, 0xFF)
DEC_HR(aic_dec_top_indefinite_text, HR_BAD_TYPE, 0x7F, 0xFF)
DEC_HR(aic_dec_top_indefinite_array, HR_BAD_TYPE, 0x9F, 0xFF)
/* invalid initial bytes */
DEC_HR(aic_dec_top_break_byte, HR_INVALID_DATA, 0xFF)
DEC_HR(aic_dec_top_reserved_ai28_map, HR_INVALID_DATA, 0xBC)
DEC_HR(aic_dec_top_reserved_ai29_map, HR_INVALID_DATA, 0xBD, 0xA0)
DEC_HR(aic_dec_top_reserved_ai30_map, HR_INVALID_DATA, 0xBE, 0xA0)
DEC_HR(aic_dec_top_reserved_ai28_uint, HR_INVALID_DATA, 0x1C)
DEC_HR(aic_dec_top_reserved_ai28_negint, HR_INVALID_DATA, 0x3C)
DEC_HR(aic_dec_top_reserved_ai28_bytes, HR_INVALID_DATA, 0x5C)
DEC_HR(aic_dec_top_reserved_ai28_text, HR_INVALID_DATA, 0x7C)
DEC_HR(aic_dec_top_reserved_ai28_array, HR_INVALID_DATA, 0x9C)
DEC_HR(aic_dec_top_reserved_ai28_tag, HR_INVALID_DATA, 0xDC)
DEC_HR(aic_dec_top_reserved_ai28_simple, HR_BAD_TYPE, 0xFC)
DEC_HR(aic_dec_top_reserved_ai29_simple, HR_BAD_TYPE, 0xFD)
DEC_HR(aic_dec_top_reserved_ai30_simple, HR_BAD_TYPE, 0xFE)
DEC_HR(aic_dec_top_indefinite_uint, HR_INVALID_DATA, 0x1F)
DEC_HR(aic_dec_top_indefinite_negint, HR_INVALID_DATA, 0x3F)
DEC_HR(aic_dec_top_indefinite_tag, HR_INVALID_DATA, 0xDF)
/* indefinite-length top-level map is rejected whatever follows */
DEC_HR(aic_dec_top_indefinite_map_alone, HR_BAD_LENGTH, 0xBF)
DEC_HR(aic_dec_top_indefinite_map_empty, HR_BAD_LENGTH, 0xBF, 0xFF)
DEC_HR(aic_dec_top_indefinite_map_full, HR_BAD_LENGTH, 0xBF, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0, 0xFF)
DEC_HR(aic_dec_top_indefinite_map_unterminated, HR_BAD_LENGTH, 0xBF, 0x01, 0x01)
/* truncated headers (preparse needs the whole argument) */
DEC_HR(aic_dec_top_map_header_trunc_1, HR_NO_MEDIA, 0xB8)
DEC_HR(aic_dec_top_map_header_trunc_2a, HR_NO_MEDIA, 0xB9)
DEC_HR(aic_dec_top_map_header_trunc_2b, HR_NO_MEDIA, 0xB9, 0x00)
DEC_HR(aic_dec_top_map_header_trunc_4, HR_NO_MEDIA, 0xBA, 0, 0, 0)
DEC_HR(aic_dec_top_map_header_trunc_8, HR_NO_MEDIA, 0xBB, 0, 0, 0, 0, 0, 0, 0)
DEC_HR(aic_dec_top_uint_header_trunc, HR_NO_MEDIA, 0x19, 0x01)
/* map entry count cap: more than 1000 entries is refused up front */
DEC_HR(aic_dec_top_map_count_1001_2byte, HR_INVALID_DATA, 0xB9, 0x03, 0xE9)
DEC_HR(aic_dec_top_map_count_1001_4byte, HR_INVALID_DATA, 0xBA, 0x00, 0x00, 0x03, 0xE9)
DEC_HR(aic_dec_top_map_count_1001_8byte, HR_INVALID_DATA, 0xBB, 0, 0, 0, 0, 0, 0, 0x03, 0xE9)
DEC_HR(aic_dec_top_map_count_huge_8byte, HR_INVALID_DATA, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
DEC_HR(aic_dec_top_map_count_4g, HR_INVALID_DATA, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF)
DEC_HR(aic_dec_top_map_count_65535, HR_INVALID_DATA, 0xB9, 0xFF, 0xFF)
/* required members */
DEC_HR(aic_dec_empty_map, HR_INVALID_DATA, 0xA0)
DEC_HR(aic_dec_version_only, HR_INVALID_DATA, 0xA1, 0x01, 0x01)
DEC_HR(aic_dec_missing_user, HR_INVALID_DATA, 0xA2, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a')
DEC_HR(aic_dec_missing_rp, HR_INVALID_DATA, 0xA2, 0x01, 0x01, 0x03, 0xA0)
DEC_HR(aic_dec_rp_without_id, HR_INVALID_DATA, 0xA3, 0x01, 0x01, 0x02, 0xA0, 0x03, 0xA0)
DEC_HR(aic_dec_rp_name_but_no_id, HR_INVALID_DATA, 0xA2, 0x02, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'n', 0x03, 0xA0)
DEC_HR(aic_dec_user_only, HR_INVALID_DATA, 0xA1, 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01)
DEC_HR(aic_dec_rp_only_empty_user_absent, HR_INVALID_DATA, 0xA1, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a')
DEC_HR(aic_dec_rp_id_key_case_sensitive, HR_INVALID_DATA, 0xA2, 0x02, 0xA1, 0x62, 'I', 'D', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_minimal_without_version_key_is_valid_shape, 0, 0xA2, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)

/* ---- wrong types of known members --------------------------------------------------------- */
#define MIN_HEAD 0xA3, 0x01, 0x01
DEC_HR(aic_dec_rp_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0x05, 0x03, 0xA0)
DEC_HR(aic_dec_rp_is_text, HR_BAD_TYPE, MIN_HEAD, 0x02, 0x62, 'i', 'd', 0x03, 0xA0)
DEC_HR(aic_dec_rp_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0x41, 0x00, 0x03, 0xA0)
DEC_HR(aic_dec_rp_is_array, HR_BAD_TYPE, MIN_HEAD, 0x02, 0x80, 0x03, 0xA0)
DEC_HR(aic_dec_rp_is_null, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xF6, 0x03, 0xA0)
DEC_HR(aic_dec_user_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0x01)
DEC_HR(aic_dec_user_is_text, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0x61, 'x')
DEC_HR(aic_dec_user_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0x40)
DEC_HR(aic_dec_user_is_array, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0x80)
DEC_HR(aic_dec_user_is_null, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xF6)
DEC_HR(aic_dec_rp_id_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x01, 0x03, 0xA0)
DEC_HR(aic_dec_rp_id_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x41, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_rp_id_is_array, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x81, 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_rp_id_is_map, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0xA0, 0x03, 0xA0)
DEC_HR(aic_dec_rp_id_is_null, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0xF6, 0x03, 0xA0)
DEC_HR(aic_dec_rp_name_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'n', 'a', 'm', 'e', 0x07, 0x03, 0xA0)
DEC_HR(aic_dec_rp_name_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'n', 'a', 'm', 'e', 0x41, 'x', 0x03, 0xA0)
DEC_HR(aic_dec_rp_icon_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'i', 'c', 'o', 'n', 0x07, 0x03, 0xA0)
DEC_HR(aic_dec_user_id_is_text, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x61, 'x')
DEC_HR(aic_dec_user_id_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x01)
DEC_HR(aic_dec_user_id_is_array, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x81, 0x01)
DEC_HR(aic_dec_user_name_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x41, 'x')
DEC_HR(aic_dec_user_name_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x01)
DEC_HR(aic_dec_user_icon_is_bytes, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'i', 'c', 'o', 'n', 0x41, 'x')
DEC_HR(aic_dec_user_display_is_uint, HR_BAD_TYPE, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x6B, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x01)
/* version member */
DEC_HR(aic_dec_version_is_text, HR_BAD_TYPE, 0xA3, 0x01, 0x61, '1', 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_is_negint, HR_BAD_TYPE, 0xA3, 0x01, 0x20, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_is_bytes, HR_BAD_TYPE, 0xA3, 0x01, 0x41, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_is_map, HR_BAD_TYPE, 0xA3, 0x01, 0xA0, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_is_true, HR_BAD_TYPE, 0xA3, 0x01, 0xF5, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_exceeds_uint32, HR_INVALID_DATA, 0xA3, 0x01, 0x1B, 0, 0, 0, 1, 0, 0, 0, 0, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_uint64_max, HR_INVALID_DATA, 0xA3, 0x01, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_version_uint32_max_ok, 0, 0xA3, 0x01, 0x1A, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
/* map keys */
DEC_HR(aic_dec_key_is_text, HR_BAD_TYPE, 0xA3, 0x61, 'a', 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_key_is_negint, HR_BAD_TYPE, 0xA3, 0x20, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_key_is_bytes, HR_BAD_TYPE, 0xA3, 0x41, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_key_exceeds_uint32, HR_INVALID_DATA, 0xA3, 0x1B, 0, 0, 0, 1, 0, 0, 0, 1, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_key_one_wrapped_in_uint64_encoding_ok, 0, 0xA3, 0x1B, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
DEC_HR(aic_dec_key_one_wrapped_in_uint8_encoding_ok, 0, 0xA3, 0x18, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0)
/* invalid UTF-8 in text members */
#define BADU8(tn, bytes, field_prefix_rp, field_prefix_us) DEC_HR(tn, HR_INVALID_DATA, bytes)
DEC_HR(aic_dec_utf8_bad_ff_rp_id, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 0xFF, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_lone_continuation_rp_id, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 0x80, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_truncated_3byte_rp_id, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x62, 0xE2, 0x82, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_truncated_2byte_rp_id, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 0xC3, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_five_byte_form_rp_id, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x65, 0xF8, 0x88, 0x80, 0x80, 0x80, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_bad_rp_name, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'n', 'a', 'm', 'e', 0x61, 0xFF, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_bad_rp_icon, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'i', 'c', 'o', 'n', 0x61, 0x80, 0x03, 0xA0)
DEC_HR(aic_dec_utf8_bad_user_name, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 0xFF)
DEC_HR(aic_dec_utf8_bad_user_icon, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'i', 'c', 'o', 'n', 0x61, 0xFE)
DEC_HR(aic_dec_utf8_bad_user_display, HR_INVALID_DATA, MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x6B, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x62, 0xC3, 0x28)
TEST(aic_dec_utf8_edge_forms_notes) {
    AIC_REQ();
    /* overlong NUL, encoded surrogate and beyond-U+10FFFF are rejected by MB_ERR_INVALID_CHARS on Windows 10; recorded, not asserted */
    static const BYTE c1[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x62, 0xC0, 0x80, 0x03, 0xA0 };
    static const BYTE c2[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x63, 0xED, 0xA0, 0x80, 0x03, 0xA0 };
    static const BYTE c3[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x64, 0xF4, 0x90, 0x80, 0x80, 0x03, 0xA0 };
    static const BYTE c4[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x62, 'a', 0x00, 0x03, 0xA0 };
    const struct { const char *n; const BYTE *d; size_t l; } c[] = { { "overlong C0 80", c1, sizeof c1 }, { "ED A0 80 surrogate", c2, sizeof c2 }, { "F4 90 80 80 > U+10FFFF", c3, sizeof c3 }, { "embedded NUL", c4, sizeof c4 } };
    for (int i = 0; i < 4; i++) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(c[i].d, c[i].l, 1, &o);
        t_note("%s -> hr=0x%08lx", c[i].n, (unsigned long)hr);
        if (hr == 0 && o != SENT_PTR) { if (o->pRp && o->pRp->pwszId) t_note("  decoded id length %d", lstrlenW(o->pRp->pwszId)); aic_free_dec(o); }
    }
}

/* ---- truncation of a full document: every strict prefix fails ----------------------------- */
TEST(aic_dec_every_prefix_of_full_document_fails) {
    AIC_REQ();
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "example.com", .rname = "Example", .ricon = "i", .uid = "\x01\x02\x03\x04", .ucb = 4, .uname = "bob", .uicon = "u", .udisp = "Bob" };
    B b; b_init(&b, 512); b_acct(&b, &s);
    int exact = 0, other = 0;
    for (size_t n = 0; n < b.n; n++) {
        for (int tail = 1; tail >= 0; tail--) {
            AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(b.d, n, tail, &o);
            CHECKF(hr < 0, "prefix %u of %u unexpectedly succeeded", (unsigned)n, (unsigned)b.n);
            CHECK(o == SENT_PTR);
            if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
            if (hr == HR_NO_MEDIA) exact++; else { other++; if (tail) t_note("prefix %u -> 0x%08lx", (unsigned)n, (unsigned long)hr); }
        }
    }
    t_note("prefixes: %d reported as 0x8007044C, %d other", exact, other);
    b_done(&b);
}
TEST(aic_dec_prefix_mid_header_is_no_media) {
    AIC_REQ();
    static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x41, 0x01 };
    /* cuts inside item headers/payloads, where the next item cannot be read */
    static const size_t cuts[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    for (unsigned i = 0; i < sizeof cuts / sizeof cuts[0]; i++) { AIC_ACCT *o = aic_expect_dec(d, cuts[i], HR_NO_MEDIA, "prefix"); if (o) aic_free_dec(o); }
}
TEST(aic_dec_text_length_exceeds_remaining) {
    AIC_REQ();
    static const BYTE d[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x78, 0x40, 'a', 'b', 0x03, 0xA0 };
    AIC_ACCT *o = aic_expect_dec(d, sizeof d, HR_NO_MEDIA, "tstr length 64, 2 bytes present"); if (o) aic_free_dec(o);
}
TEST(aic_dec_text_length_4gb_claim) {
    AIC_REQ();
    static const BYTE d[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x7A, 0xFF, 0xFF, 0xFF, 0xFF, 'a' };
    for (int tail = 1; tail >= 0; tail--) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, tail, &o);
        CHECK(hr < 0); CHECK(o == SENT_PTR);
        t_note("tstr 0xFFFFFFFF length with 1 byte present: hr=0x%08lx", (unsigned long)hr);
        if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
    }
}
TEST(aic_dec_bytes_length_8byte_claim) {
    AIC_REQ();
    static const BYTE d[] = { MIN_HEAD, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x62, 'i', 'd', 0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2 };
    for (int tail = 1; tail >= 0; tail--) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, tail, &o);
        CHECK(hr < 0); CHECK(o == SENT_PTR);
        t_note("bstr 2^64-1 length: hr=0x%08lx", (unsigned long)hr);
        if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
    }
}
TEST(aic_dec_nested_map_count_exceeds_content) {
    AIC_REQ();
    static const BYTE d[] = { MIN_HEAD, 0x02, 0xA5, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };   /* rp claims 5 entries, has 1 */
    for (int tail = 1; tail >= 0; tail--) {
        AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, tail, &o);
        CHECK(hr < 0); CHECK(o == SENT_PTR);
        t_note("rp map count 5 with 1 entry: hr=0x%08lx", (unsigned long)hr);
        if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
    }
}
TEST(aic_dec_top_map_count_exceeds_content) {
    AIC_REQ();
    static const BYTE d[] = { 0xA4, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };   /* claims 4 entries, has 3 */
    AIC_ACCT *o = aic_expect_dec(d, sizeof d, HR_NO_MEDIA, "count 4, 3 entries"); if (o) aic_free_dec(o);
}
TEST(aic_dec_top_map_count_less_than_content) {
    AIC_REQ();
    /* claims 2 entries (version, rp) and then user follows: user is not part of the map -> missing user */
    static const BYTE d[] = { 0xA2, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    AIC_ACCT *o = aic_expect_dec(d, sizeof d, HR_INVALID_DATA, "count 2, extra entry ignored"); if (o) aic_free_dec(o);
}

/* ---- trailing data, unknown members, duplicate members ------------------------------------ */
TEST(aic_dec_trailing_bytes_ignored) {
    AIC_REQ();
    static const BYTE base[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    BYTE buf[64];
    static const BYTE tails[][4] = { { 0 }, { 0xFF }, { 0xA0 }, { 0x01, 0x02, 0x03, 0x04 } };
    for (unsigned i = 0; i < 4; i++) {
        memcpy(buf, base, sizeof base); memcpy(buf + sizeof base, tails[i], 4);
        AIC_ACCT *o = aic_expect_dec(buf, sizeof base + 1 + (i == 3 ? 3 : 0), 0, "trailing"); if (o) aic_free_dec(o);
    }
}
TEST(aic_dec_trailing_second_document_ignored) {
    AIC_REQ();
    static const BYTE one[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    BYTE two[2 * sizeof one]; memcpy(two, one, sizeof one); memcpy(two + sizeof one, one, sizeof one);
    AIC_ACCT *o = aic_expect_dec(two, sizeof two, 0, "two documents"); if (o) aic_free_dec(o);
}
TEST(aic_dec_trailing_garbage_large) {
    AIC_REQ();
    static const BYTE one[] = { 0xA3, 0x01, 0x01, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    BYTE *p = (BYTE *)malloc(10000); memcpy(p, one, sizeof one); memset(p + sizeof one, 0xFF, 10000 - sizeof one);
    AIC_ACCT *o = aic_expect_dec(p, 10000, 0, "10000 bytes of 0xFF after document"); if (o) aic_free_dec(o);
    free(p);
}
static void unknown_key_test(unsigned long long key, const BYTE *val, size_t vn, HRESULT want, const char *tag) {
    B b; b_init(&b, 70000);
    b_head(&b, 5, 4); b_uint(&b, 1); b_uint(&b, 1);
    b_uint(&b, key); b_put(&b, val, vn);
    b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a");
    b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag);
    if (o) { EXPECT_EQ(o->dwVersion, 1); CHECK(aic_streq(o->pRp->pwszId, "a")); aic_free_dec(o); }
    b_done(&b);
}
TEST(aic_dec_unknown_keys_skipped_all_value_types) {
    AIC_REQ();
    static const unsigned long long keys[] = { 0, 4, 5, 100, 255, 256, 65535, 65536, 0xFFFFFFFFull };
    static const BYTE u0[] = { 0x00 }, u1[] = { 0x19, 0x01, 0x00 }, tx[] = { 0x63, 'a', 'b', 'c' }, by[] = { 0x42, 1, 2 }, ar[] = { 0x83, 1, 2, 3 },
        mp[] = { 0xA2, 0x01, 0x02, 0x62, 'k', 'k', 0x81, 0xA0 }, ng[] = { 0x38, 0x63 }, tb[] = { 0xF5 }, nl[] = { 0xF6 };
    const struct { const BYTE *v; size_t n; } vals[] = { { u0, 1 }, { u1, 3 }, { tx, 4 }, { by, 3 }, { ar, 4 }, { mp, 8 }, { ng, 2 }, { tb, 1 }, { nl, 1 } };
    for (unsigned k = 0; k < sizeof keys / sizeof keys[0]; k++)
        for (unsigned v = 0; v < sizeof vals / sizeof vals[0]; v++) unknown_key_test(keys[k], vals[v].v, vals[v].n, 0, "unknown key skipped");
}
TEST(aic_dec_unknown_key_with_utf8_invalid_text_value_is_skipped) {
    AIC_REQ(); static const BYTE v[] = { 0x62, 0xFF, 0xFE };
    B b; b_init(&b, 64);
    b_head(&b, 5, 3); b_uint(&b, 7); b_put(&b, v, sizeof v);
    b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a"); b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(b.d, b.n, 1, &o);
    t_note("invalid UTF-8 inside a skipped unknown member: hr=0x%08lx", (unsigned long)hr);
    if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
    b_done(&b);
}
TEST(aic_dec_unknown_key_big_text_value_is_skipped) {
    AIC_REQ(); B v; b_init(&v, 40000); b_textrep(&v, 'z', 30000);
    unknown_key_test(7, v.d, v.n, 0, "unknown key with 30000-byte text");
    b_done(&v);
}
TEST(aic_dec_unknown_key_value_truncated_fails) {
    AIC_REQ(); B b; b_init(&b, 64);
    b_head(&b, 5, 2); b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a"); b_uint(&b, 9); b_head(&b, 3, 20); b_text(&b, "short");
    b.n -= 0;
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, HR_NO_MEDIA, "unknown key with truncated value"); if (o) aic_free_dec(o);
    b_done(&b);
}
TEST(aic_dec_unknown_keys_in_rp_and_user_maps_ignored) {
    AIC_REQ();
    static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA3, 0x62, 'i', 'd', 0x61, 'a', 0x63, 'f', 'o', 'o', 0x83, 1, 2, 3, 0x01, 0x07,
                              0x03, 0xA2, 0x63, 'b', 'a', 'r', 0xA0, 0x64, 'n', 'a', 'm', 'e', 0x61, 'u' };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { CHECK(aic_streq(o->pRp->pwszId, "a")); CHECK(aic_streq(o->pUser->pwszName, "u")); aic_free_dec(o); }
}
TEST(aic_dec_duplicate_rp_last_wins) {
    AIC_REQ();
    static const BYTE d[] = { 0xA4, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'b', 0x03, 0xA0, 0x01, 0x05 };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { CHECK(aic_streq(o->pRp->pwszId, "b")); EXPECT_EQ(o->dwVersion, 5); aic_free_dec(o); }
}
TEST(aic_dec_duplicate_user_last_wins) {
    AIC_REQ();
    static const BYTE d[] = { 0xA3, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'x', 0x03, 0xA1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'y' };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { CHECK(aic_streq(o->pUser->pwszName, "y")); aic_free_dec(o); }
}
TEST(aic_dec_duplicate_version_last_wins) {
    AIC_REQ();
    static const BYTE d[] = { 0xA4, 0x01, 0x07, 0x01, 0x09, 0x02, 0xA1, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { EXPECT_EQ(o->dwVersion, 9); aic_free_dec(o); }
}
TEST(aic_dec_duplicate_inner_key_first_wins) {
    AIC_REQ();
    /* inner members are located with a map search: the first matching key is used */
    static const BYTE d[] = { 0xA2, 0x02, 0xA2, 0x62, 'i', 'd', 0x61, 'a', 0x62, 'i', 'd', 0x61, 'b', 0x03, 0xA0 };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { t_note("duplicate rp id: decoded \"%ls\"", o->pRp->pwszId ? o->pRp->pwszId : L"(null)"); aic_free_dec(o); }
}
TEST(aic_dec_inner_map_keys_any_order) {
    AIC_REQ();
    static const BYTE d[] = { 0xA3, 0x01, 0x01, 0x02, 0xA3, 0x64, 'n', 'a', 'm', 'e', 0x61, 'N', 0x64, 'i', 'c', 'o', 'n', 0x61, 'I', 0x62, 'i', 'd', 0x61, 'R',
                              0x03, 0xA4, 0x6B, 'd', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x61, 'D', 0x64, 'n', 'a', 'm', 'e', 0x61, 'n', 0x64, 'i', 'c', 'o', 'n', 0x61, 'i', 0x62, 'i', 'd', 0x41, 0x05 };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) {
        CHECK(aic_streq(o->pRp->pwszId, "R")); CHECK(aic_streq(o->pRp->pwszName, "N")); CHECK(aic_streq(o->pRp->pwszIcon, "I"));
        CHECK(aic_streq(o->pUser->pwszName, "n")); CHECK(aic_streq(o->pUser->pwszIcon, "i")); CHECK(aic_streq(o->pUser->pwszDisplayName, "D"));
        EXPECT_EQ(o->pUser->cbId, 1); CHECK(o->pUser->pbId && o->pUser->pbId[0] == 5);
        aic_free_dec(o);
    }
}
TEST(aic_dec_inner_map_key_names_are_case_sensitive) {
    AIC_REQ();
    static const BYTE d[] = { 0xA2, 0x02, 0xA3, 0x62, 'i', 'd', 0x61, 'a', 0x64, 'N', 'a', 'm', 'e', 0x61, 'x', 0x64, 'I', 'c', 'o', 'n', 0x61, 'y',
                              0x03, 0xA2, 0x6B, 'D', 'i', 's', 'p', 'l', 'a', 'y', 'N', 'a', 'm', 'e', 0x61, 'z', 0x64, 'N', 'A', 'M', 'E', 0x61, 'w' };
    AIC_ACCT *o = EXPECT_DEC(d, sizeof d, 0);
    if (o) { CHECK(!o->pRp->pwszName && !o->pRp->pwszIcon && !o->pUser->pwszName && !o->pUser->pwszDisplayName); aic_free_dec(o); }
}
TEST(aic_dec_inner_map_with_non_text_keys_tolerated) {
    AIC_REQ();
    static const BYTE d[] = { 0xA2, 0x02, 0xA2, 0x01, 0x07, 0x62, 'i', 'd', 0x61, 'a', 0x03, 0xA0 };
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, 1, &o);
    t_note("non-text key inside rp map: hr=0x%08lx", (unsigned long)hr);
    if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
}
TEST(aic_dec_inner_indefinite_maps_accepted_or_noted) {
    AIC_REQ();
    static const BYTE d[] = { 0xA2, 0x02, 0xBF, 0x62, 'i', 'd', 0x61, 'a', 0xFF, 0x03, 0xBF, 0xFF };
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, 1, &o);
    t_note("indefinite-length rp/user maps: hr=0x%08lx", (unsigned long)hr);
    if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
}
TEST(aic_dec_indefinite_text_value_noted) {
    AIC_REQ();
    static const BYTE d[] = { 0xA2, 0x02, 0xA1, 0x62, 'i', 'd', 0x7F, 0x61, 'a', 0x61, 'b', 0xFF, 0x03, 0xA0 };
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, 1, &o);
    t_note("chunked text id: hr=0x%08lx id=%ls", (unsigned long)hr, (hr == 0 && o != SENT_PTR && o->pRp->pwszId) ? o->pRp->pwszId : L"-");
    if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
}
TEST(aic_dec_tagged_values_noted) {
    AIC_REQ();
    static const BYTE d[] = { 0xA2, 0x02, 0xA1, 0x62, 'i', 'd', 0xC1, 0x61, 'a', 0x03, 0xA0 };
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(d, sizeof d, 1, &o);
    t_note("tagged text id: hr=0x%08lx", (unsigned long)hr);
    if (hr == 0 && o != SENT_PTR) aic_free_dec(o);
}

/* ---- limits ---------------------------------------------------------------------------- */
static void limit_text(size_t cch, int user_first, HRESULT want, const char *tag) {
    char *t = (char *)malloc(cch + 1); memset(t, 'q', cch); t[cch] = 0;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = t, .user_first = user_first };
    B b; b_init(&b, cch + 256); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag);
    if (o) { CHECK(o->pRp->pwszId && (size_t)lstrlenW(o->pRp->pwszId) == cch); aic_free_dec(o); }
    b_done(&b); free(t);
}
TEST(aic_dec_limit_rp_id_8163_chars_then_user_ok) { AIC_REQ(); limit_text(8163, 0, 0, "id 8163 chars, user after"); }
TEST(aic_dec_limit_rp_id_8164_chars_then_user_fails) { AIC_REQ(); limit_text(8164, 0, HR_INVALID_DATA, "id 8164 chars, user after"); }
TEST(aic_dec_limit_rp_id_8191_chars_user_first_ok) { AIC_REQ(); limit_text(8191, 1, 0, "id 8191 chars, user first"); }
TEST(aic_dec_limit_rp_id_8192_chars_user_first_fails) { AIC_REQ(); limit_text(8192, 1, HR_INVALID_DATA, "id 8192 chars, user first"); }
TEST(aic_dec_limit_rp_id_16384_chars_fails) { AIC_REQ(); limit_text(16384, 1, HR_INVALID_DATA, "id 16384 chars"); }
TEST(aic_dec_limit_rp_id_100000_chars_fails) { AIC_REQ(); limit_text(100000, 1, HR_INVALID_DATA, "id 100000 chars"); }
TEST(aic_dec_limit_rp_id_many_small_sizes_ok) {
    AIC_REQ();
    for (size_t n = 1; n <= 40; n++) limit_text(n, 0, 0, "small sizes");
    for (size_t n = 8150; n <= 8163; n++) limit_text(n, 0, 0, "near limit");
}
static void limit_euro(size_t euros, size_t extra_ascii, HRESULT want, const char *tag) {
    B v; b_init(&v, 40000);
    size_t n = euros * 3 + extra_ascii; b_head(&v, 3, n);
    for (size_t i = 0; i < euros; i++) { b_byte(&v, 0xE2); b_byte(&v, 0x82); b_byte(&v, 0xAC); }
    b_rep(&v, 'a', extra_ascii);
    B b; b_init(&b, 40100);
    b_head(&b, 5, 3); b_uint(&b, 1); b_uint(&b, 1); b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_put(&b, v.d, v.n);
    b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag);
    if (o) { CHECK(o->pRp->pwszId && (size_t)lstrlenW(o->pRp->pwszId) == euros + extra_ascii); aic_free_dec(o); }
    b_done(&b); b_done(&v);
}
TEST(aic_dec_limit_text_bytes_16384_ok) { AIC_REQ(); limit_euro(5461, 1, 0, "16384 UTF-8 bytes"); }
TEST(aic_dec_limit_text_bytes_16385_fails) { AIC_REQ(); limit_euro(5461, 2, HR_INVALID_DATA, "16385 UTF-8 bytes"); }
TEST(aic_dec_limit_text_bytes_16383_ok) { AIC_REQ(); limit_euro(5461, 0, 0, "16383 UTF-8 bytes"); }
TEST(aic_dec_limit_text_bytes_16386_fails) { AIC_REQ(); limit_euro(5462, 0, HR_INVALID_DATA, "16386 UTF-8 bytes"); }
static void limit_userid(size_t n, HRESULT want, const char *tag) {
    BYTE *id = (BYTE *)malloc(n); for (size_t i = 0; i < n; i++) id[i] = (BYTE)(i * 31 + 7);
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = "a", .uid = id, .ucb = n };
    B b; b_init(&b, n + 256); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag);
    if (o) { EXPECT_EQ(o->pUser->cbId, n); CHECK(o->pUser->pbId && !memcmp(o->pUser->pbId, id, n)); aic_free_dec(o); }
    b_done(&b); free(id);
}
TEST(aic_dec_limit_user_id_16384_ok) { AIC_REQ(); limit_userid(16384, 0, "user id 16384 bytes"); }
TEST(aic_dec_limit_user_id_16385_fails) { AIC_REQ(); limit_userid(16385, HR_INVALID_DATA, "user id 16385 bytes"); }
TEST(aic_dec_limit_user_id_16383_ok) { AIC_REQ(); limit_userid(16383, 0, "user id 16383 bytes"); }
TEST(aic_dec_limit_user_id_65536_fails) { AIC_REQ(); limit_userid(65536, HR_INVALID_DATA, "user id 65536 bytes"); }
TEST(aic_dec_limit_user_id_1mib_fails) { AIC_REQ(); limit_userid(1 << 20, HR_INVALID_DATA, "user id 1 MiB"); }
TEST(aic_dec_limit_total_block_over_16k_fails_on_next_alloc) {
    AIC_REQ();
    /* two 8000-char ids: rp.id (16000 B), then rp.name still starts below 0x4000, but the user struct then starts at 0x38+2*16008 > 0x4000 -> refused */
    char *t = (char *)malloc(8001); memset(t, 'x', 8000); t[8000] = 0;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = t, .rname = t };
    B b; b_init(&b, 20000); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, HR_INVALID_DATA, "two 8000-char members"); if (o) aic_free_dec(o);
    b_done(&b); free(t);
}
TEST(aic_dec_limit_many_medium_members_ok) {
    AIC_REQ();
    char *t = (char *)malloc(1001); memset(t, 'm', 1000); t[1000] = 0;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = t, .rname = t, .ricon = t, .uid = t, .ucb = 1000, .uname = t, .uicon = t, .udisp = t };
    dec_spec(&s); free(t);
}

/* top-level entry count: 1000 accepted, 1001 refused */
static void entries_test(unsigned total, HRESULT want, const char *tag) {
    B b; b_init(&b, 40000);
    b_head(&b, 5, total); b_uint(&b, 1); b_uint(&b, 1);
    for (unsigned i = 0; i < total - 3; i++) { b_uint(&b, 10 + i); b_uint(&b, i); }
    b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a");
    b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag); if (o) aic_free_dec(o);
    b_done(&b);
}
TEST(aic_dec_top_map_1000_entries_ok) { AIC_REQ(); entries_test(1000, 0, "1000 entries"); }
TEST(aic_dec_top_map_999_entries_ok) { AIC_REQ(); entries_test(999, 0, "999 entries"); }
TEST(aic_dec_top_map_1001_entries_fails) { AIC_REQ(); entries_test(1001, HR_INVALID_DATA, "1001 entries"); }
TEST(aic_dec_top_map_3000_entries_fails) { AIC_REQ(); entries_test(3000, HR_INVALID_DATA, "3000 entries"); }

/* nesting of unknown values: arrays nested up to 1024 deep are skipped, deeper is refused */
static void nest_test(unsigned depth, HRESULT want, const char *tag) {
    B b; b_init(&b, depth + 128);
    b_head(&b, 5, 4); b_uint(&b, 1); b_uint(&b, 1);
    b_uint(&b, 77); for (unsigned i = 1; i < depth; i++) b_byte(&b, 0x81); b_byte(&b, 0x80);
    b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a");
    b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag); if (o) aic_free_dec(o);
    b_done(&b);
}
TEST(aic_dec_nesting_depth_1_ok) { AIC_REQ(); nest_test(1, 0, "depth 1"); }
TEST(aic_dec_nesting_depth_16_ok) { AIC_REQ(); nest_test(16, 0, "depth 16"); }
TEST(aic_dec_nesting_depth_100_ok) { AIC_REQ(); nest_test(100, 0, "depth 100"); }
TEST(aic_dec_nesting_depth_1024_ok) { AIC_REQ(); nest_test(1024, 0, "depth 1024"); }
TEST(aic_dec_nesting_depth_1025_fails) { AIC_REQ(); nest_test(1025, HR_INVALID_DATA, "depth 1025"); }
TEST(aic_dec_nesting_depth_5000_fails) { AIC_REQ(); nest_test(5000, HR_INVALID_DATA, "depth 5000"); }
TEST(aic_dec_nesting_depth_100000_fails_without_crash) { AIC_REQ(); nest_test(100000, HR_INVALID_DATA, "depth 100000"); }
TEST(aic_dec_nesting_unterminated_deep_array_fails) {
    AIC_REQ(); B b; b_init(&b, 4096);
    b_head(&b, 5, 1); b_uint(&b, 77); for (int i = 0; i < 2000; i++) b_byte(&b, 0x81);
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(b.d, b.n, 1, &o);
    CHECK(hr < 0); CHECK(o == SENT_PTR); t_note("2000 unterminated nested arrays: hr=0x%08lx", (unsigned long)hr);
    b_done(&b);
}
TEST(aic_dec_nesting_maps_in_unknown_value) {
    AIC_REQ(); B b; b_init(&b, 4096);
    b_head(&b, 5, 4); b_uint(&b, 1); b_uint(&b, 1);
    b_uint(&b, 77); for (int i = 0; i < 200; i++) { b_head(&b, 5, 1); b_uint(&b, 0); } b_uint(&b, 0);
    b_uint(&b, 2); b_head(&b, 5, 1); b_text(&b, "id"); b_text(&b, "a");
    b_uint(&b, 3); b_head(&b, 5, 0);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, 0, "200 nested single-entry maps"); if (o) aic_free_dec(o);
    b_done(&b);
}

/* ---- decode-block offset rule: an allocation is refused when it starts above 0x4000 (or is itself > 0x4000) --- */
static void two_text(size_t idn, size_t namen, HRESULT want, const char *tag) {
    char *a = (char *)malloc(idn + 1), *c = (char *)malloc(namen + 1);
    memset(a, 'i', idn); a[idn] = 0; memset(c, 'n', namen); c[namen] = 0;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = a, .rname = c };
    B b; b_init(&b, idn + namen + 256); b_acct(&b, &s);
    AIC_ACCT *o = aic_expect_dec(b.d, b.n, want, tag);
    if (o) { CHECK(o->pRp->pwszName && (size_t)lstrlenW(o->pRp->pwszName) == namen); aic_free_dec(o); }
    b_done(&b); free(a); free(c);
}
TEST(aic_dec_offset_big_id_small_name_ok) { AIC_REQ(); two_text(8000, 1, 0, "id 8000 + name 1"); }
TEST(aic_dec_offset_big_id_small_name_at_edge_fails) { AIC_REQ(); two_text(8163, 1, HR_INVALID_DATA, "id 8163 + name 1: user struct past 0x4000"); }
TEST(aic_dec_offset_small_id_big_name_ok) { AIC_REQ(); two_text(1, 8100, 0, "id 1 + name 8100"); }
TEST(aic_dec_offset_two_4000_char_members_ok) { AIC_REQ(); two_text(4000, 4000, 0, "id 4000 + name 4000"); }
TEST(aic_dec_offset_two_8000_char_members_fail) { AIC_REQ(); two_text(8000, 8000, HR_INVALID_DATA, "id 8000 + name 8000"); }
TEST(aic_dec_offset_error_leaves_out_pointer_untouched) {
    AIC_REQ();
    char *t = (char *)malloc(8165); memset(t, 'x', 8164); t[8164] = 0;
    SPEC s = { .ver = 1, .has_rp = 1, .has_user = 1, .rid = t };
    B b; b_init(&b, 8500); b_acct(&b, &s);
    AIC_ACCT *o = (AIC_ACCT *)SENT_PTR; HRESULT hr = aic_dec_g(b.d, b.n, 1, &o);
    HR_EQ(hr, HR_INVALID_DATA); CHECK(o == SENT_PTR);
    b_done(&b); free(t);
}
