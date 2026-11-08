/* Malformed / unusual COSE_Key items inside attested credential data.
 * Reference behaviour (decompilation): the parser requires the item after the credential id to start with a
 * CBOR map or array head, and to be a complete, well formed CBOR item that fits in the buffer. It never looks at
 * the labels or values, so a key without kty/alg, with duplicate labels or with wrongly typed values still parses.
 */
#include "acd.h"

static void raw_ok(const char *hex, const char *what) {
    vec v; ad_raw(&v, ACD_AT | ACD_UP, 16, hex, 0);
    pres p = acd_parse(v.p, v.n);
    t_check(HRV(p.hr) == 0 && p.fl == 0x41 && p.sc == 0x01020304, __FILE__, __LINE__, what, "parse hr=%08lx fl=%02x sc=%08lx cose=%s", HRV(p.hr), p.fl, p.sc, hex);
    cres c = acd_credid(v.p, v.n);
    t_check(HRV(c.hr) == 0 && c.cb == 16 && c.off == 55, __FILE__, __LINE__, what, "credid hr=%08lx cb=%lu off=%lu cose=%s", HRV(c.hr), c.cb, c.off, hex);
    v_free(&v);
}
static void raw_fail(const char *hex, const char *what) {
    vec v; ad_raw(&v, ACD_AT | ACD_UP, 16, hex, 0);
    pres p = acd_parse(v.p, v.n);
    t_check(HRV(p.hr) == ACD_E_INVALID_DATA && p.fl == 0 && p.sc == 0, __FILE__, __LINE__, what, "parse hr=%08lx fl=%02x sc=%08lx cose=%s", HRV(p.hr), p.fl, p.sc, hex);
    expect_cred_fail(v.p, v.n, what);
    v_free(&v);
}
static void raw_note(const char *hex, const char *what) {
    vec v; ad_raw(&v, ACD_AT | ACD_UP, 16, hex, 0);
    pres p = acd_parse(v.p, v.n);
    t_note("%s [%s]: parse hr=0x%08lx", what, hex, HRV(p.hr));
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_empty_map_ok) {
    NEED_ALL();
    raw_ok("A0", "empty map");
}

TEST(ctap_authdata_cose_mal_missing_kty_ok) {
    NEED_ALL();
    raw_ok("A3 03 26 20 01 21 41 00", "no kty (label 1)");
    raw_ok("A1 03 26", "only alg");
}

TEST(ctap_authdata_cose_mal_missing_alg_ok) {
    NEED_ALL();
    raw_ok("A3 01 02 20 01 21 41 00", "no alg (label 3)");
    raw_ok("A1 01 02", "only kty");
}

TEST(ctap_authdata_cose_mal_missing_both_ok) {
    NEED_ALL();
    raw_ok("A1 20 01", "crv only");
    raw_ok("A2 21 41 00 22 41 01", "x,y only");
}

TEST(ctap_authdata_cose_mal_duplicate_labels_ok) {
    NEED_ALL();
    raw_ok("A2 01 02 01 03", "duplicate kty");
    raw_ok("A3 03 26 03 27 03 38 22", "duplicate alg");
    raw_ok("A4 20 01 20 02 20 03 20 04", "duplicate crv");
}

TEST(ctap_authdata_cose_mal_wrong_value_types_ok) {
    NEED_ALL();
    raw_ok("A1 01 61 78", "kty as text");
    raw_ok("A1 01 41 02", "kty as bstr");
    raw_ok("A1 03 41 26", "alg as bstr");
    raw_ok("A1 03 61 45", "alg as text");
    raw_ok("A1 03 A0", "alg as empty map");
    raw_ok("A1 03 80", "alg as empty array");
    raw_ok("A1 01 F6", "kty null");
    raw_ok("A1 01 F5", "kty true");
    raw_ok("A1 01 F4", "kty false");
    raw_ok("A1 20 41 01", "crv as bstr");
    raw_ok("A1 21 01", "x as uint");
    raw_ok("A1 22 61 79", "y as text");
}

TEST(ctap_authdata_cose_mal_wrong_label_types_ok) {
    NEED_ALL();
    raw_ok("A1 61 6B 02", "text label");
    raw_ok("A1 41 01 02", "bstr label");
    raw_ok("A2 62 6B 74 02 63 61 6C 67 26", "kt/alg text labels");
    raw_ok("A1 F6 02", "null label");
    raw_ok("A1 80 02", "array label");
}

TEST(ctap_authdata_cose_mal_nested_values_ok) {
    NEED_ALL();
    raw_ok("A1 01 A1 01 02", "nested map value");
    raw_ok("A1 01 82 01 02", "array value");
    raw_ok("A2 01 A1 02 A1 03 A0 04 80", "deeper nesting");
    raw_ok("A1 A1 01 02 03", "map as label");
}

TEST(ctap_authdata_cose_mal_extra_unknown_labels_ok) {
    NEED_ALL();
    raw_ok("A3 01 02 18 64 01 19 03 E8 61 7A", "unknown labels 100, 1000");
    raw_ok("A2 01 02 39 03 E7 41 00", "negative label -1000");
}

TEST(ctap_authdata_cose_mal_large_head_forms_ok) {
    NEED_ALL();
    raw_ok("A1 01 18 FF", "1-byte uint value");
    raw_ok("A1 01 19 01 00", "2-byte uint value");
    raw_ok("A1 01 1A 00 01 00 00", "4-byte uint value");
    raw_ok("A1 01 1B 00 00 00 01 00 00 00 00", "8-byte uint value");
    raw_ok("A1 01 3B FF FF FF FF FF FF FF FF", "most negative 64-bit");
    raw_ok("A1 01 58 00", "empty bstr with 1-byte length");
    raw_ok("A1 01 59 00 00", "empty bstr with 2-byte length");
    raw_ok("B8 01 01 02", "map with 1-byte count head");
    raw_ok("B9 00 01 01 02", "map with 2-byte count head");
    raw_ok("BA 00 00 00 01 01 02", "map with 4-byte count head");
}

TEST(ctap_authdata_cose_mal_map_24_entries_ok) {
    NEED_ALL();
    char hex[256] = "B8 18";
    for (int i = 0; i < 24; i++) strcat(hex, " 01 01");
    raw_ok(hex, "24 pairs");
}

TEST(ctap_authdata_cose_mal_map_23_entries_ok) {
    NEED_ALL();
    char hex[256] = "B7";
    for (int i = 0; i < 23; i++) strcat(hex, " 18 2A 01");
    raw_ok(hex, "23 pairs");
}

TEST(ctap_authdata_cose_mal_array_as_key_item) {
    NEED_ALL();
    /* the structural check accepts a CBOR array head as well as a map head */
    raw_note("80", "empty array");
    raw_note("82 01 02", "array of two ints");
}

/* ---- items that are not a map/array: rejected ------------------------------ */
TEST(ctap_authdata_cose_mal_scalar_item_rejected) {
    NEED_ALL();
    raw_fail("00", "uint 0");
    raw_fail("01", "uint 1");
    raw_fail("17", "uint 23");
    raw_fail("18 2A", "uint 42");
    raw_fail("19 01 00", "uint 256");
    raw_fail("20", "negint -1");
    raw_fail("38 20", "negint");
    raw_fail("F4", "false");
    raw_fail("F5", "true");
    raw_fail("F6", "null");
    raw_fail("F7", "undefined");
}

TEST(ctap_authdata_cose_mal_string_item_rejected) {
    NEED_ALL();
    raw_fail("40", "empty bstr");
    raw_fail("41 A0", "bstr containing A0");
    raw_fail("58 02 A0 A0", "bstr 2");
    raw_fail("60", "empty tstr");
    raw_fail("61 41", "tstr");
}

TEST(ctap_authdata_cose_mal_tagged_map_rejected) {
    NEED_ALL();
    raw_fail("C0 A0", "tag 0 + empty map");
    raw_fail("D8 18 A0", "tag 24 + empty map");
    raw_fail("C2 41 01", "bignum");
}

TEST(ctap_authdata_cose_mal_break_item_rejected) {
    NEED_ALL();
    raw_fail("FF", "stray break");
}

/* ---- incomplete / invalid CBOR ------------------------------------------- */
TEST(ctap_authdata_cose_mal_truncated_map_rejected) {
    NEED_ALL();
    raw_fail("A1", "1 pair promised, none present");
    raw_fail("A1 01", "value missing");
    raw_fail("A2 01 02", "second pair missing");
    raw_fail("A2 01 02 03", "second value missing");
    raw_fail("A5 01 02 03 26", "5 pairs, 2 present");
    raw_fail("A1 01 58 20 00", "bstr payload truncated");
    raw_fail("A1 01 61", "tstr payload missing");
    raw_fail("A1 58 20", "label bstr missing payload");
    raw_fail("A1 01 82 01", "array value truncated");
    raw_fail("A1 01 A1", "nested map truncated");
    raw_fail("A1 01 A1 01", "nested map value truncated");
}

TEST(ctap_authdata_cose_mal_truncated_heads_rejected) {
    NEED_ALL();
    raw_fail("B8", "1-byte count missing");
    raw_fail("B9", "2-byte count missing");
    raw_fail("B9 00", "2-byte count short");
    raw_fail("BA 00 00 00", "4-byte count short");
    raw_fail("BB 00 00 00 00 00 00 00", "8-byte count short");
    raw_fail("B8 01", "count present, content missing");
    raw_fail("A1 01 18", "uint head truncated");
    raw_fail("A1 01 19 01", "uint16 head truncated");
    raw_fail("A1 01 1A 00 00 00", "uint32 head truncated");
    raw_fail("A1 01 1B 00 00 00 00", "uint64 head truncated");
}

TEST(ctap_authdata_cose_mal_count_exceeds_content_rejected) {
    NEED_ALL();
    raw_fail("B9 FF FF 01 02", "65535 pairs promised");
    raw_fail("BA FF FF FF FF 01 02", "4G pairs promised");
    raw_fail("BB FF FF FF FF FF FF FF FF 01 02", "2^64-1 pairs promised");
    raw_fail("A1 01 59 FF FF 00", "bstr 65535 promised");
    raw_fail("A1 01 5A FF FF FF FF 00", "bstr 4G promised");
    raw_fail("A1 01 5B FF FF FF FF FF FF FF FF 00", "bstr 2^64-1 promised");
}

TEST(ctap_authdata_cose_mal_reserved_additional_info_rejected) {
    NEED_ALL();
    raw_fail("BC", "map, additional info 28");
    raw_fail("BD", "map, additional info 29");
    raw_fail("BE", "map, additional info 30");
    raw_fail("9C", "array, additional info 28");
    raw_fail("FC", "reserved simple");
}

TEST(ctap_authdata_cose_mal_reserved_info_nested_note) {
    NEED_ALL();
    raw_note("A1 01 1C", "value with additional info 28");
    raw_note("A1 1D 01", "label with additional info 29");
    raw_note("A1 01 1E", "value with additional info 30");
    raw_note("A1 FF 01", "break as a label");
    raw_note("A1 01 FF", "break as a value");
}

TEST(ctap_authdata_cose_mal_indefinite_length_note) {
    NEED_ALL();
    /* indefinite-length items are recorded, not asserted */
    raw_note("BF FF", "empty indefinite map");
    raw_note("BF 01 02 FF", "indefinite map, one pair");
    raw_note("BF 01 02", "indefinite map, missing break");
    raw_note("BF 01 FF", "indefinite map, odd item count");
    raw_note("9F FF", "empty indefinite array");
    raw_note("A1 01 5F 41 00 FF", "indefinite bstr value");
    raw_note("A1 01 7F 61 61 FF", "indefinite tstr value");
    raw_note("A1 01 5F 41 00", "indefinite bstr, no break");
}

TEST(ctap_authdata_cose_mal_float_and_simple_values_note) {
    NEED_ALL();
    raw_note("A1 01 F9 3C 00", "half float value");
    raw_note("A1 01 FA 3F 80 00 00", "single float value");
    raw_note("A1 01 FB 3F F0 00 00 00 00 00 00", "double float value");
    raw_note("A1 01 F8 20", "simple value 32 (1-byte)");
    raw_note("A1 01 F8 10", "simple value 16 encoded in 2 bytes (invalid)");
    raw_note("A1 01 C1 1A 51 4B 67 B0", "tagged epoch time");
}

TEST(ctap_authdata_cose_mal_deep_nesting) {
    NEED_ALL();
    static const int depths[] = { 10, 100, 500 };
    for (size_t k = 0; k < sizeof depths / sizeof depths[0]; k++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 16, 16, 1);
        for (int i = 0; i < depths[k]; i++) v_u8(&v, 0x81);
        v_u8(&v, 0x00);
        pres p = acd_parse(v.p, v.n);
        CHECKF(HRV(p.hr) == 0, "depth %d hr=%08lx", depths[k], HRV(p.hr));
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_mal_excessive_nesting_rejected) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 16, 16, 1);
    for (int i = 0; i < 1100; i++) v_u8(&v, 0x81);
    v_u8(&v, 0x00);
    expect_parse_fail(v.p, v.n, "nesting depth 1100");
    expect_cred_fail(v.p, v.n, "nesting depth 1100");
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_nesting_limit_boundary_note) {
    NEED_ALL();
    for (int d = 1022; d <= 1026; d++) {
        vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 16, 16, 1);
        for (int i = 0; i < d; i++) v_u8(&v, 0x81);
        v_u8(&v, 0x00);
        pres p = acd_parse(v.p, v.n);
        t_note("array nesting depth %d: parse hr=0x%08lx", d, HRV(p.hr));
        v_free(&v);
    }
}

TEST(ctap_authdata_cose_mal_unterminated_nesting_rejected) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1); ad_att(&v, 16, 16, 1);
    for (int i = 0; i < 50; i++) v_u8(&v, 0x81);       /* never reaches a leaf */
    expect_parse_fail(v.p, v.n, "arrays without leaf");
    v_free(&v);
}

/* ---- exactness of consumption --------------------------------------------- */
TEST(ctap_authdata_cose_mal_second_item_after_key_is_trailing) {
    NEED_ALL();
    vec v; ad_raw(&v, ACD_AT, 16, "A1 01 02 A0", 0);      /* a second, valid item follows the key */
    expect_parse_fail(v.p, v.n, "two items, no ED");
    v_free(&v);
    ad_raw(&v, ACD_AT | ACD_ED, 16, "A1 01 02 A0", 0);
    expect_parse_ok(v.p, v.n, ACD_AT | ACD_ED, 0x01020304, "two items, ED takes the second");
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_key_ends_exactly_at_buffer_end) {
    NEED_ALL();
    raw_ok("A1 01 02", "exact fit");
    vec v; ad_raw(&v, ACD_AT | ACD_UP, 16, "A1 01 02", 0);
    expect_parse_fail(v.p, v.n - 1, "one byte short");
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_zero_credid_with_minimal_key) {
    NEED_ALL();
    vec v; ad_raw(&v, ACD_AT, 0, "A0", 0);
    expect_parse_ok(v.p, v.n, ACD_AT, 0x01020304, "empty credId, empty map");
    expect_cred_fail(v.p, v.n, "empty credId is invalid for GetCredentialId");
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_credid_bytes_look_like_cbor) {
    NEED_ALL();
    /* the credential id may contain anything, including bytes that look like a COSE map */
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1);
    BYTE g[16] = { 0 }; v_put(&v, g, 16); v_be16(&v, 3); v_hex(&v, "A1 01 02");
    mk_es256(&v);
    expect_parse_ok(v.p, v.n, ACD_AT, 1, "cbor-looking credId");
    cres c = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(c.hr), 0); EXPECT_EQ(c.cb, 3); EXPECT_EQ(c.off, 55);
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_credid_all_byte_values) {
    NEED_ALL();
    vec v; v_init(&v); ad_header(&v, ACD_AT, 1);
    BYTE g[16] = { 0 }; v_put(&v, g, 16); v_be16(&v, 256);
    for (int i = 0; i < 256; i++) v_u8(&v, i);
    mk_es256(&v);
    cres c = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(c.hr), 0); EXPECT_EQ(c.cb, 256); EXPECT_EQ(c.off, 55);
    for (int i = 0; i < 256; i++) if (v.p[55 + i] != i) { CHECKF(0, "byte %d", i); break; }
    v_free(&v);
}

TEST(ctap_authdata_cose_mal_credidlen_big_endian_field) {
    NEED_ALL();
    /* 0x0100 = 256 (BE), not 1 (LE) */
    vec v; ad_full(&v, ACD_AT, 1, K_ES256, 256, 0);
    EXPECT_EQ(v.p[53], 0x01); EXPECT_EQ(v.p[54], 0x00);
    cres c = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(c.hr), 0); EXPECT_EQ(c.cb, 256);
    v_free(&v);
    ad_full(&v, ACD_AT, 1, K_ES256, 1, 0);
    EXPECT_EQ(v.p[53], 0x00); EXPECT_EQ(v.p[54], 0x01);
    c = acd_credid(v.p, v.n);
    EXPECT_EQ(HRV(c.hr), 0); EXPECT_EQ(c.cb, 1);
    v_free(&v);
}
