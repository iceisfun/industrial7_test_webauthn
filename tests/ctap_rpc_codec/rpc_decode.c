/* ctap_rpc_codec: response decoders and the assertion selection helpers.
 *
 * I_WebAuthNCtapDecodeMakeCredentialRpcResponse(txid, cb, pb, conveyance, &devResp, &attestation)
 * I_WebAuthNCtapDecodeGetAssertionRpcResponse(txid, cb, pb, allowDefault, cbSel, pbSel, &devResp, &assertion)
 * WebAuthNCtapRpcGetAssertionUserList(cbReq, pbReq, cbDev, pbDev, &rpId, &users)
 * WebAuthNCtapRpcSelectGetAssertion(cbDev, pbDev, index, &cbOut, &pbOut)
 *
 * Input is the device response envelope (see rpc.h): {"deviceInfo", "status", "response"} whose "response"
 * bstr is  <CTAP status byte> <CTAP CBOR payload>.  Behaviour below is taken from the Windows 10 reference
 * decompilation:
 *   - both output pointers are zeroed first (no NULL check on them);
 *   - empty/NULL input is rejected by the CBOR layer with 0x8007044C;
 *   - malformed CBOR / missing mandatory members map to HRESULT_FROM_WIN32(ERROR_INVALID_DATA) (0x8007000D);
 *   - a non-zero CTAP status byte, or an empty "response", is 0x8007000D;
 *   - results are LocalAlloc blocks (devResp, assertion, user list); attestation is released with
 *     WebAuthNFreeCredentialAttestation; the SelectGetAssertion buffer and the rp id are CoTaskMem blocks.
 */
#include "rpc.h"

/* ---- _WEBAUTHN_CREDENTIAL_ATTESTATION (version 3, x64) field offsets ---- */
#define ATT_VERSION     0x00
#define ATT_FORMAT      0x08
#define ATT_CB_AUTH     0x10
#define ATT_PB_AUTH     0x18
#define ATT_CB_STMT     0x20
#define ATT_PB_STMT     0x28
#define ATT_DECODE_TYPE 0x30
#define ATT_CB_OBJ      0x40
#define ATT_PB_OBJ      0x48
/* ---- _WEBAUTHN_ASSERTION ---- */
#define AS_VERSION      0x00
#define AS_CB_AUTH      0x04
#define AS_PB_AUTH      0x08
#define AS_CB_SIG       0x10
#define AS_PB_SIG       0x18
#define AS_CB_USERID    0x38
#define AS_PB_USERID    0x40
/* ---- _CTAPCBOR_DEVICE_RESPONSE_INFO ---- */
#define DR_VERSION      0x00
#define DR_DEVINFO      0x08
#define DR_STATUS       0x10
#define DR_CB_RESP      0x14
#define DR_PB_RESP      0x18

#define U32(p, off) (*(DWORD *)((BYTE *)(p) + (off)))
#define PTR(p, off) (*(BYTE **)((BYTE *)(p) + (off)))

static BYTE g_ad1[37], g_ad2[37], g_ad3[37];
static void init_ads(void) { make_authdata(g_ad1, 0x11); make_authdata(g_ad2, 0x22); make_authdata(g_ad3, 0x33); }
static const BYTE g_sig1[] = { 0x30, 0x44, 1, 2, 3, 4, 5, 6, 7, 8 };
static const BYTE g_sig2[] = { 0x30, 0x45, 9, 9, 9 };

/* ------------------- make-credential decode driver ------------------------- */
typedef struct { LONG hr; void *dev; void *att; } mcd_res;
static mcd_res mcd_call(const BYTE *p, size_t n, ULONG conveyance) {
    mcd_res r; GUID g = CRC_TXID;
    r.dev = (void *)(ULONG_PTR)0x11; r.att = (void *)(ULONG_PTR)0x22;   /* poison: must be zeroed first */
    BYTE *copy = (BYTE *)malloc(n ? n : 1); if (n) memcpy(copy, p, n);
    r.hr = UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)(&g, (ULONG)n, n ? copy : NULL, conveyance, &r.dev, &r.att);
    free(copy);
    return r;
}
static void mcd_free(mcd_res *r) {
    if (r->att) UN(WebAuthNFreeCredentialAttestation)(r->att);
    if (r->dev) LocalFree(r->dev);
    r->att = r->dev = NULL;
}
/* build a standard good make-credential envelope */
static size_t good_mc_envelope(cbuf *env, const char *fmt, int withStmt) {
    cbuf pl; BYTE ad[37]; make_authdata(ad, 0x11);
    mc_payload(&pl, fmt, ad, 37, withStmt);
    envelope(env, 0, pl.b, pl.n);
    return env->n;
}
#define MCD_FAIL_POINTERS(r) do { CHECK((r).dev == NULL); CHECK((r).att == NULL); } while (0)

/* ===== make-credential decode: negative inputs ===== */
TEST(ctaprpc_mcdec_empty_input) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    mcd_res r = mcd_call((const BYTE *)"", 0, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_CBOR_EMPTY); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_null_buffer_with_length) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    GUID g = CRC_TXID; void *dev = (void *)1, *att = (void *)1;
    LONG hr = UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)(&g, 32, NULL, 0, &dev, &att);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_CBOR_EMPTY); CHECK(dev == NULL); CHECK(att == NULL);
}
TEST(ctaprpc_mcdec_garbage_table) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    static const BYTE a[] = { 0xFF }, b[] = { 0x00 }, c[] = { 0xA0 }, d[] = { 0x80 }, e[] = { 0x01, 0x02, 0x03, 0x04 },
        f[] = { 0xA1, 0x6A, 'd', 'e', 'v', 'i', 'c', 'e', 'I', 'n', 'f', 'o' }, g[] = { 0xA3 }, h[] = { 0x59, 0xFF, 0xFF, 0x00 };
    static const struct { const BYTE *p; size_t n; const char *w; } t[] = {
        { a, 1, "break" }, { b, 1, "uint" }, { c, 1, "empty map" }, { d, 1, "empty array" }, { e, 4, "uints" },
        { f, sizeof f, "truncated map" }, { g, 1, "map(3) no body" }, { h, 4, "bstr longer than data" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        mcd_res r = mcd_call(t[i].p, t[i].n, 0);
        CHECKF(is_cbor_layer_error(r.hr), "%s: hr=0x%08lx", t[i].w, (unsigned long)r.hr);
        MCD_FAIL_POINTERS(r);
    }
}
TEST(ctaprpc_mcdec_envelope_without_response_member) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf c; c.n = 0; cb_map(&c, 2);
    cb_tstr(&c, "deviceInfo"); dev_info_map(&c, "TestProvider", "hid");
    cb_tstr(&c, "status"); cb_uint(&c, 0);
    mcd_res r = mcd_call(c.b, c.n, 0);
    CHECKF(is_cbor_layer_error(r.hr), "hr=0x%08lx", (unsigned long)r.hr); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_envelope_without_status_member) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1);
    c.n = 0; cb_map(&c, 2);
    cb_tstr(&c, "deviceInfo"); dev_info_map(&c, "TestProvider", "hid");
    cb_tstr(&c, "response"); cb_bstr(&c, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    t_note("mcdec without 'status': hr=0x%08lx", (unsigned long)r.hr);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_envelope_without_deviceinfo_member) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1);
    c.n = 0; cb_map(&c, 2);
    cb_tstr(&c, "status"); cb_uint(&c, 0);
    cb_tstr(&c, "response"); cb_bstr(&c, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    CHECKF(FAILED(r.hr), "hr=0x%08lx", (unsigned long)r.hr);
    if (FAILED(r.hr)) { CHECK(is_cbor_layer_error(r.hr)); MCD_FAIL_POINTERS(r); }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_deviceinfo_without_provider_name) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1);
    c.n = 0; cb_map(&c, 3);
    cb_tstr(&c, "deviceInfo"); dev_info_map(&c, NULL, "hid");
    cb_tstr(&c, "status"); cb_uint(&c, 0);
    cb_tstr(&c, "response"); cb_bstr(&c, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    CHECKF(FAILED(r.hr), "hr=0x%08lx", (unsigned long)r.hr);
    if (FAILED(r.hr)) { CHECK(is_cbor_layer_error(r.hr)); MCD_FAIL_POINTERS(r); }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_empty_response_bstr) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf c; envelope(&c, 0, (const BYTE *)"", 0);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_nonzero_ctap_status_byte) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    /* The first byte of "response" is the CTAP2 status; anything other than 0 is not decoded. */
    static const BYTE st[] = { 0x01, 0x02, 0x10, 0x2E, 0x36, 0x7F, 0xFF };
    for (size_t i = 0; i < sizeof st; i++) {
        cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1); pl.b[0] = st[i];
        envelope(&c, 0, pl.b, pl.n);
        mcd_res r = mcd_call(c.b, c.n, 0);
        CHECKF(r.hr == HR_INVALID_DATA, "status 0x%02x: hr=0x%08lx", st[i], (unsigned long)r.hr); MCD_FAIL_POINTERS(r);
    }
}
TEST(ctaprpc_mcdec_envelope_status_member_value_not_used) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    /* Only the CTAP byte inside "response" decides; the envelope "status" number is just copied. */
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1);
    envelope(&c, 0x1234, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.dev) CHECK(U32(r.dev, DR_STATUS) == 0x1234);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_payload_missing_fmt) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1);
    pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 2); cb_uint(&pl, 2); cb_bstr(&pl, ad, 37); cb_uint(&pl, 3); cb_map(&pl, 0);
    envelope(&c, 0, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_missing_authdata) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c;
    pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 2); cb_uint(&pl, 1); cb_tstr(&pl, "none"); cb_uint(&pl, 3); cb_map(&pl, 0);
    envelope(&c, 0, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_empty_authdata) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE none = 0;
    mc_payload(&pl, "none", &none, 0, 1);
    envelope(&c, 0, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_empty_fmt) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE ad[37]; make_authdata(ad, 1);
    mc_payload(&pl, "", ad, 37, 1);
    envelope(&c, 0, pl.b, pl.n);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_empty_map) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, c; BYTE b[2] = { 0x00, 0xA0 };
    (void)pl; envelope(&c, 0, b, 2);
    mcd_res r = mcd_call(c.b, c.n, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_only_status_byte) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf c; BYTE b[1] = { 0x00 };
    envelope(&c, 0, b, 1);
    mcd_res r = mcd_call(c.b, c.n, 0);
    /* nothing after the status byte: the CBOR layer reports an empty buffer */
    CHECKF(FAILED(r.hr) && is_cbor_layer_error(r.hr), "hr=0x%08lx", (unsigned long)r.hr);
    MCD_FAIL_POINTERS(r);
}
TEST(ctaprpc_mcdec_payload_not_a_map) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    static const BYTE bad[][3] = { { 0, 0x01, 0 }, { 0, 0x80, 0 }, { 0, 0x60, 0 }, { 0, 0x40, 0 }, { 0, 0xF6, 0 } };
    for (size_t i = 0; i < 5; i++) {
        cbuf c; envelope(&c, 0, bad[i], 2);
        mcd_res r = mcd_call(c.b, c.n, 0);
        CHECKF(FAILED(r.hr), "payload #%zu hr=0x%08lx", i, (unsigned long)r.hr);
        if (FAILED(r.hr)) MCD_FAIL_POINTERS(r);
        mcd_free(&r);
    }
}
TEST(ctaprpc_mcdec_every_envelope_truncation_fails) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res ok = mcd_call(env.b, env.n, 0); CHECK(ok.hr == 0); mcd_free(&ok);
    for (size_t n = 1; n < env.n; n++) {
        mcd_res r = mcd_call(env.b, n, 0);
        CHECKF(FAILED(r.hr), "prefix %zu hr=0x%08lx", n, (unsigned long)r.hr);
        if (FAILED(r.hr)) MCD_FAIL_POINTERS(r);
        mcd_free(&r);
    }
}
TEST(ctaprpc_mcdec_every_payload_truncation_fails) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse));
    cbuf pl, env; BYTE ad[37]; make_authdata(ad, 1); mc_payload(&pl, "none", ad, 37, 1);
    for (size_t n = 1; n < pl.n; n++) {
        envelope(&env, 0, pl.b, n);   /* valid envelope around a truncated CTAP payload */
        mcd_res r = mcd_call(env.b, env.n, 0);
        CHECKF(FAILED(r.hr), "payload prefix %zu hr=0x%08lx", n, (unsigned long)r.hr);
        if (FAILED(r.hr)) { CHECKF(is_cbor_layer_error(r.hr), "payload prefix %zu hr=0x%08lx", n, (unsigned long)r.hr); MCD_FAIL_POINTERS(r); }
        mcd_free(&r);
    }
}

/* ===== make-credential decode: positive ===== */
TEST(ctaprpc_mcdec_valid_none_attestation) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    EXPECT_EQ((ULONG)r.hr, 0);
    CHECK(r.dev != NULL); CHECK(r.att != NULL);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_attestation_fields) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    if (r.hr == 0 && r.att) {
        CHECK(U32(r.att, ATT_VERSION) == 3);
        const WCHAR *fmt = *(const WCHAR **)((BYTE *)r.att + ATT_FORMAT);
        CHECK(fmt != NULL && !lstrcmpW(fmt, L"none"));
        CHECK(U32(r.att, ATT_CB_AUTH) == 37);
        CHECK(PTR(r.att, ATT_PB_AUTH) != NULL && !memcmp(PTR(r.att, ATT_PB_AUTH), g_ad1, 37));
        CHECK(U32(r.att, ATT_CB_STMT) == 1);
        CHECK(PTR(r.att, ATT_PB_STMT) != NULL && PTR(r.att, ATT_PB_STMT)[0] == 0xA0);
        t_note("attestation decode type=%lu transport=0x%lx", (unsigned long)U32(r.att, ATT_DECODE_TYPE), (unsigned long)U32(r.att, 0x70));
    }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_attestation_object_is_text_keyed_map) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    if (r.hr == 0 && r.att) {
        const BYTE *o = PTR(r.att, ATT_PB_OBJ); DWORD n = U32(r.att, ATT_CB_OBJ);
        CHECK(o != NULL && n > 37);
        if (o) {
            char keys[64]; size_t end = 0; int cnt = cr_text_keys(o, n, keys, sizeof keys, &end);
            CHECK(cnt == 3); EXPECT_STR(keys, "fmt,attStmt,authData"); CHECK(end == n);
            const BYTE *s; size_t sl;
            CHECK(cr_text_bytes(o, n, "fmt", &s, &sl) && sl == 4 && !memcmp(s, "none", 4));
            CHECK(cr_text_bytes(o, n, "authData", &s, &sl) && sl == 37 && !memcmp(s, g_ad1, 37));
            size_t vo, vl; CHECK(cr_text_find(o, n, "attStmt", &vo, &vl) && vl == 1 && o[vo] == 0xA0);
        }
    }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_device_response_info_fields) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    if (r.hr == 0 && r.dev) {
        CHECK(LocalSize(r.dev) != 0);
        CHECK(U32(r.dev, DR_VERSION) == 1);
        CHECK(U32(r.dev, DR_STATUS) == 0);
        CHECK(U32(r.dev, DR_CB_RESP) > 38 && PTR(r.dev, DR_PB_RESP) != NULL && PTR(r.dev, DR_PB_RESP)[0] == 0);
        BYTE *di = PTR(r.dev, DR_DEVINFO);
        CHECK(di != NULL);
        if (di) {
            CHECK(U32(di, 0) == 1);
            const WCHAR *name = *(const WCHAR **)(di + 0x10);
            CHECK(name != NULL && !lstrcmpW(name, L"TestProvider"));
            const WCHAR *type = *(const WCHAR **)(di + 0x08);
            CHECK(type != NULL && !lstrcmpW(type, L"hid"));
        }
    }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_device_response_pointer_is_localalloc) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    if (r.hr == 0 && r.dev) {
        CHECK(LocalSize(r.dev) != 0);
        void *dev = r.dev; r.dev = NULL;
        CHECK(LocalFree(dev) == NULL);
    }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_text_keyed_payload_accepted) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    /* A map keyed by "fmt"/"authData"/"attStmt" (the form used for the re-encoded attestation object). */
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_tstr(&pl, "fmt"); cb_tstr(&pl, "none");
    cb_tstr(&pl, "attStmt"); cb_map(&pl, 0);
    cb_tstr(&pl, "authData"); cb_bstr(&pl, g_ad1, 37);
    envelope(&env, 0, pl.b, pl.n);
    mcd_res r = mcd_call(env.b, env.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.att) { const WCHAR *f = *(const WCHAR **)((BYTE *)r.att + ATT_FORMAT); CHECK(f && !lstrcmpW(f, L"none")); CHECK(U32(r.att, ATT_CB_AUTH) == 37); }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_noncanonical_key_order_accepted) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_uint(&pl, 3); cb_map(&pl, 0);
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 1); cb_tstr(&pl, "none");
    envelope(&env, 0, pl.b, pl.n);
    mcd_res r = mcd_call(env.b, env.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_unknown_payload_keys_skipped) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 5);
    cb_uint(&pl, 1); cb_tstr(&pl, "none");
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_map(&pl, 0);
    cb_uint(&pl, 4); cb_uint(&pl, 1);                 /* epAtt */
    cb_uint(&pl, 5); cb_bstr(&pl, "\x01\x02\x03", 3); /* largeBlobKey */
    envelope(&env, 0, pl.b, pl.n);
    mcd_res r = mcd_call(env.b, env.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_missing_attstmt_defaults_to_empty_map) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 0);
    mcd_res r = mcd_call(env.b, env.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.att && PTR(r.att, ATT_PB_OBJ)) {
        size_t vo, vl; const BYTE *o = PTR(r.att, ATT_PB_OBJ); DWORD n = U32(r.att, ATT_CB_OBJ);
        CHECK(cr_text_find(o, n, "attStmt", &vo, &vl) && vl == 1 && o[vo] == 0xA0);
    }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_other_formats_decode) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    static const char *fmts[] = { "packed", "fido-u2f", "tpm", "android-key", "apple" };
    for (size_t i = 0; i < 5; i++) {
        cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
        cb_uint(&pl, 1); cb_tstr(&pl, fmts[i]);
        cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
        cb_uint(&pl, 3); cb_map(&pl, 1); cb_tstr(&pl, "alg"); cb_nint(&pl, -7);
        envelope(&env, 0, pl.b, pl.n);
        mcd_res r = mcd_call(env.b, env.n, 0);
        CHECKF(r.hr == 0, "fmt %s: hr=0x%08lx", fmts[i], (unsigned long)r.hr);
        if (r.hr == 0 && r.att) {
            const WCHAR *f = *(const WCHAR **)((BYTE *)r.att + ATT_FORMAT); WCHAR w[32]; MultiByteToWideChar(CP_UTF8, 0, fmts[i], -1, w, 32);
            CHECKF(f && !lstrcmpW(f, w), "fmt %s", fmts[i]);
            CHECK(U32(r.att, ATT_CB_STMT) > 1);
        }
        mcd_free(&r);
    }
}
TEST(ctaprpc_mcdec_conveyance_none_only_rewrites_non_none) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    /* conveyance==1 ("none" requested) leaves a "none" statement untouched. */
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res a = mcd_call(env.b, env.n, 0), b = mcd_call(env.b, env.n, 1);
    CHECK(a.hr == 0); CHECK(b.hr == 0);
    if (a.att && b.att) {
        CHECK(U32(a.att, ATT_CB_OBJ) == U32(b.att, ATT_CB_OBJ));
        if (U32(a.att, ATT_CB_OBJ) == U32(b.att, ATT_CB_OBJ)) CHECK(!memcmp(PTR(a.att, ATT_PB_OBJ), PTR(b.att, ATT_PB_OBJ), U32(a.att, ATT_CB_OBJ)));
    }
    mcd_free(&a); mcd_free(&b);
}
TEST(ctaprpc_mcdec_conveyance_none_with_packed_statement) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    /* conveyance==1 with a non-"none" statement triggers the "none attestation" rewrite; result recorded. */
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_uint(&pl, 1); cb_tstr(&pl, "packed");
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_map(&pl, 1); cb_tstr(&pl, "alg"); cb_nint(&pl, -7);
    envelope(&env, 0, pl.b, pl.n);
    mcd_res r = mcd_call(env.b, env.n, 1);
    t_note("mcdec conveyance=1 packed: hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.att) { const WCHAR *f = *(const WCHAR **)((BYTE *)r.att + ATT_FORMAT); t_note("   fmt=%ls cbStmt=%lu", f ? f : L"(null)", (unsigned long)U32(r.att, ATT_CB_STMT)); }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_outputs_independent_between_calls) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res a = mcd_call(env.b, env.n, 0), b = mcd_call(env.b, env.n, 0);
    CHECK(a.att && b.att && a.att != b.att); CHECK(a.dev && b.dev && a.dev != b.dev);
    mcd_free(&a);
    if (b.att) CHECK(U32(b.att, ATT_CB_AUTH) == 37);    /* b survives a's release */
    mcd_free(&b);
}
TEST(ctaprpc_mcdec_input_buffer_not_referenced_after_return) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    /* mcd_call frees its input copy before returning; the outputs must be self-contained. */
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res r = mcd_call(env.b, env.n, 0);
    if (r.hr == 0 && r.att) { CHECK(!memcmp(PTR(r.att, ATT_PB_AUTH), g_ad1, 37)); CHECK(*(WCHAR **)((BYTE *)r.att + ATT_FORMAT) != NULL); }
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_large_attstmt) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    static BYTE sig[3000]; memset(sig, 0x5A, sizeof sig);
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_uint(&pl, 1); cb_tstr(&pl, "packed");
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_map(&pl, 1); cb_tstr(&pl, "sig"); cb_bstr(&pl, sig, sizeof sig);
    envelope(&env, 0, pl.b, pl.n);
    mcd_res r = mcd_call(env.b, env.n, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.att) CHECK(U32(r.att, ATT_CB_STMT) > 3000);
    mcd_free(&r);
}
TEST(ctaprpc_mcdec_repeated_calls_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf env; good_mc_envelope(&env, "none", 1);
    mcd_res w = mcd_call(env.b, env.n, 0); mcd_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 20000; i++) { mcd_res r = mcd_call(env.b, env.n, 0); if (r.hr != 0) bad++; mcd_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d failures", bad);
    if (before && after) { CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before); t_note("mcdec x20000 private-bytes growth within bound"); }
}
TEST(ctaprpc_mcdec_failure_path_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); init_ads();
    cbuf pl, env; BYTE ad[37]; make_authdata(ad, 1);
    pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 2); cb_uint(&pl, 2); cb_bstr(&pl, ad, 37); cb_uint(&pl, 3); cb_map(&pl, 0);   /* missing fmt */
    envelope(&env, 0, pl.b, pl.n);
    mcd_res w = mcd_call(env.b, env.n, 0); mcd_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 20000; i++) { mcd_res r = mcd_call(env.b, env.n, 0); if (r.hr != HR_INVALID_DATA || r.att || r.dev) bad++; mcd_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unexpected results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}
TEST(ctaprpc_mcdec_roundtrip_from_encoder_payload_is_not_a_response) {
    REQUIRE(UN(I_WebAuthNCtapDecodeMakeCredentialRpcResponse)); REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* An encoded RPC *request* fed in as a response lacks the envelope members. */
    mc_args a; mc_args_init(&a); enc_res e = mc_encode(&a, 0, 0, 0, NULL, NULL, NULL);
    if (e.pb) { mcd_res r = mcd_call(e.pb, e.cb, 0); CHECKF(FAILED(r.hr) && is_cbor_layer_error(r.hr), "hr=0x%08lx", (unsigned long)r.hr); MCD_FAIL_POINTERS(r); }
    enc_free(&e);
}

/* ------------------- get-assertion decode driver ----------------------------- */
typedef struct { LONG hr; void *dev; void *as; } gad_res;
static gad_res gad_call(const BYTE *p, size_t n, int allowDefault, const BYTE *sel, ULONG selLen) {
    gad_res r; GUID g = CRC_TXID;
    r.dev = (void *)(ULONG_PTR)0x11; r.as = (void *)(ULONG_PTR)0x22;
    BYTE *copy = (BYTE *)malloc(n ? n : 1); if (n) memcpy(copy, p, n);
    r.hr = UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)(&g, (ULONG)n, n ? copy : NULL, allowDefault, selLen, sel, &r.dev, &r.as);
    free(copy);
    return r;
}
static void gad_free(gad_res *r) { if (r->as) LocalFree(r->as); if (r->dev) LocalFree(r->dev); r->as = r->dev = NULL; }
#define GAD_FAIL_POINTERS(r) do { CHECK((r).dev == NULL); CHECK((r).as == NULL); } while (0)

/* envelope around status 0 + one assertion map */
static void ga_single_env(cbuf *env, const BYTE *ad, const BYTE *sig, size_t siglen, const BYTE *uid, size_t uidlen) {
    cbuf pl; pl.n = 0; cb_byte(&pl, 0); ga_item(&pl, ad, 37, sig, siglen, uid, uidlen);
    envelope(env, 0, pl.b, pl.n);
}
/* envelope around status 0 + array of assertions */
static void ga_array_env(cbuf *env, int n, const BYTE *const *ads, const BYTE *const *uids) {
    cbuf pl; pl.n = 0; cb_byte(&pl, 0); cb_arr(&pl, n);
    for (int i = 0; i < n; i++) ga_item(&pl, ads[i], 37, g_sig1, sizeof g_sig1, uids ? uids[i] : NULL, 4);
    envelope(env, 0, pl.b, pl.n);
}

TEST(ctaprpc_gadec_empty_input) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    gad_res r = gad_call((const BYTE *)"", 0, 0, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_CBOR_EMPTY); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_null_buffer_with_length) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    GUID g = CRC_TXID; void *dev = (void *)1, *as = (void *)1;
    LONG hr = UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)(&g, 40, NULL, 0, 0, NULL, &dev, &as);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_CBOR_EMPTY); CHECK(dev == NULL); CHECK(as == NULL);
}
TEST(ctaprpc_gadec_garbage_table) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    static const BYTE a[] = { 0xFF }, b[] = { 0x00 }, c[] = { 0xA0 }, d[] = { 0x80 }, e[] = { 0xA3, 0x01 }, f[] = { 0x5A, 0xFF, 0xFF, 0xFF, 0xFF };
    static const struct { const BYTE *p; size_t n; const char *w; } t[] = {
        { a, 1, "break" }, { b, 1, "uint" }, { c, 1, "empty map" }, { d, 1, "empty array" }, { e, 2, "truncated" }, { f, 5, "huge bstr" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        gad_res r = gad_call(t[i].p, t[i].n, 1, NULL, 0);
        CHECKF(is_cbor_layer_error(r.hr), "%s: hr=0x%08lx", t[i].w, (unsigned long)r.hr); GAD_FAIL_POINTERS(r);
    }
}
TEST(ctaprpc_gadec_empty_response_bstr) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    cbuf c; envelope(&c, 0, (const BYTE *)"", 0);
    gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_nonzero_ctap_status_byte) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    static const BYTE st[] = { 0x01, 0x2E, 0x36, 0xFF };
    for (size_t i = 0; i < sizeof st; i++) {
        cbuf pl, c; pl.n = 0; cb_byte(&pl, st[i]); ga_item(&pl, g_ad1, 37, g_sig1, sizeof g_sig1, NULL, 0);
        envelope(&c, 0, pl.b, pl.n);
        gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
        CHECKF(r.hr == HR_INVALID_DATA, "status 0x%02x hr=0x%08lx", st[i], (unsigned long)r.hr); GAD_FAIL_POINTERS(r);
    }
}
TEST(ctaprpc_gadec_missing_authdata) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    cbuf pl, c; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 1); cb_uint(&pl, 3); cb_bstr(&pl, g_sig1, sizeof g_sig1);
    envelope(&c, 0, pl.b, pl.n);
    gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_missing_signature) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, c; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 1); cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    envelope(&c, 0, pl.b, pl.n);
    gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_empty_map_payload) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    cbuf c; BYTE b[2] = { 0x00, 0xA0 }; envelope(&c, 0, b, 2);
    gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_DATA); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_only_status_byte) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    cbuf c; BYTE b[1] = { 0 }; envelope(&c, 0, b, 1);
    gad_res r = gad_call(c.b, c.n, 1, NULL, 0);
    CHECKF(FAILED(r.hr) && is_cbor_layer_error(r.hr), "hr=0x%08lx", (unsigned long)r.hr); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_every_envelope_truncation_fails) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, (const BYTE *)"\x01\x02\x03\x04", 4);
    gad_res ok = gad_call(env.b, env.n, 1, NULL, 0); CHECK(ok.hr == 0); gad_free(&ok);
    for (size_t n = 1; n < env.n; n++) {
        gad_res r = gad_call(env.b, n, 1, NULL, 0);
        CHECKF(FAILED(r.hr), "prefix %zu hr=0x%08lx", n, (unsigned long)r.hr);
        if (FAILED(r.hr)) GAD_FAIL_POINTERS(r);
        gad_free(&r);
    }
}
TEST(ctaprpc_gadec_every_payload_truncation_fails) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); ga_item(&pl, g_ad1, 37, g_sig1, sizeof g_sig1, (const BYTE *)"\x01\x02\x03\x04", 4);
    for (size_t n = 1; n < pl.n; n++) {
        envelope(&env, 0, pl.b, n);
        gad_res r = gad_call(env.b, env.n, 1, NULL, 0);
        CHECKF(FAILED(r.hr), "payload prefix %zu hr=0x%08lx", n, (unsigned long)r.hr);
        if (FAILED(r.hr)) GAD_FAIL_POINTERS(r);
        gad_free(&r);
    }
}

/* ===== get-assertion decode: single assertion ===== */
TEST(ctaprpc_gadec_single_assertion) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, 0);
    CHECK(r.as != NULL && r.dev != NULL);
    if (r.hr == 0 && r.as) {
        t_note("assertion dwVersion=%lu", (unsigned long)U32(r.as, AS_VERSION)); CHECK(U32(r.as, AS_VERSION) != 0);
        CHECK(U32(r.as, AS_CB_AUTH) == 37); CHECK(PTR(r.as, AS_PB_AUTH) && !memcmp(PTR(r.as, AS_PB_AUTH), g_ad1, 37));
        CHECK(U32(r.as, AS_CB_SIG) == sizeof g_sig1); CHECK(PTR(r.as, AS_PB_SIG) && !memcmp(PTR(r.as, AS_PB_SIG), g_sig1, sizeof g_sig1));
        CHECK(U32(r.as, AS_CB_USERID) == 0);
    }
    gad_free(&r);
}
TEST(ctaprpc_gadec_assertion_is_localalloc_block) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); REQUIRE(UN(WebAuthNFreeAssertion)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    if (r.hr == 0 && r.as) {
        CHECK(LocalSize(r.as) != 0);
        UN(WebAuthNFreeAssertion)(r.as); r.as = NULL;   /* WebAuthNFreeAssertion == LocalFree of the block */
    }
    gad_free(&r);
}
TEST(ctaprpc_gadec_allow_default_flag_ignored_for_single_map) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    for (int flag = 0; flag <= 1; flag++) {
        gad_res r = gad_call(env.b, env.n, flag, NULL, 0);
        CHECKF(r.hr == 0, "flag=%d hr=0x%08lx", flag, (unsigned long)r.hr);
        gad_free(&r);
    }
}
TEST(ctaprpc_gadec_single_assertion_with_user) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    static const BYTE uid[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4 };
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, uid, sizeof uid);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) {
        CHECK(U32(r.as, AS_CB_USERID) == sizeof uid);
        CHECK(PTR(r.as, AS_PB_USERID) && !memcmp(PTR(r.as, AS_PB_USERID), uid, sizeof uid));
    }
    gad_free(&r);
}
TEST(ctaprpc_gadec_user_without_id_rejected) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_bstr(&pl, g_sig1, sizeof g_sig1);
    cb_uint(&pl, 4); cb_map(&pl, 1); cb_tstr(&pl, "name"); cb_tstr(&pl, "alice");
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    CHECKF(FAILED(r.hr), "hr=0x%08lx", (unsigned long)r.hr);
    if (FAILED(r.hr)) { CHECK(is_cbor_layer_error(r.hr)); GAD_FAIL_POINTERS(r); }
    gad_free(&r);
}
TEST(ctaprpc_gadec_credential_member_decoded) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    static const BYTE cid[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 3);
    cb_uint(&pl, 1); cb_map(&pl, 2); cb_tstr(&pl, "id"); cb_bstr(&pl, cid, 4); cb_tstr(&pl, "type"); cb_tstr(&pl, "public-key");
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_bstr(&pl, g_sig1, sizeof g_sig1);
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) {
        /* WEBAUTHN_CREDENTIAL at +0x20: dwVersion, cbId, pbId, pwszCredentialType */
        t_note("assertion credential: ver=%lu cbId=%lu type=%ls", (unsigned long)U32(r.as, 0x20), (unsigned long)U32(r.as, 0x24),
               *(WCHAR **)((BYTE *)r.as + 0x30) ? *(WCHAR **)((BYTE *)r.as + 0x30) : L"(null)");
        if (U32(r.as, 0x24) == 4) CHECK(!memcmp(PTR(r.as, 0x28), cid, 4));
    }
    gad_free(&r);
}
TEST(ctaprpc_gadec_unknown_keys_skipped) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 5);
    cb_uint(&pl, 9); cb_tstr(&pl, "ignored");
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    cb_uint(&pl, 3); cb_bstr(&pl, g_sig1, sizeof g_sig1);
    cb_uint(&pl, 5); cb_uint(&pl, 2);      /* numberOfCredentials */
    cb_uint(&pl, 7); cb_bstr(&pl, "\x01", 1);
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    gad_free(&r);
}
TEST(ctaprpc_gadec_noncanonical_order_accepted) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_map(&pl, 2);
    cb_uint(&pl, 3); cb_bstr(&pl, g_sig1, sizeof g_sig1);
    cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    gad_free(&r);
}
TEST(ctaprpc_gadec_device_response_info_fields) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    if (r.hr == 0 && r.dev) {
        CHECK(U32(r.dev, DR_VERSION) == 1); CHECK(U32(r.dev, DR_STATUS) == 0);
        CHECK(U32(r.dev, DR_CB_RESP) > 40 && PTR(r.dev, DR_PB_RESP) && PTR(r.dev, DR_PB_RESP)[0] == 0);
        BYTE *di = PTR(r.dev, DR_DEVINFO); CHECK(di != NULL);
        if (di) { const WCHAR *n = *(const WCHAR **)(di + 0x10); CHECK(n && !lstrcmpW(n, L"TestProvider")); }
    }
    gad_free(&r);
}

/* ===== get-assertion decode: arrays (multiple assertions) ===== */
TEST(ctaprpc_gadec_array_requires_selection_hint) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    gad_res r = gad_call(env.b, env.n, 0, NULL, 0);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_NO_MATCH); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_array_allow_default_selects_first) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    gad_res r = gad_call(env.b, env.n, 1, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) { CHECK(U32(r.as, AS_CB_AUTH) == 37); CHECK(!memcmp(PTR(r.as, AS_PB_AUTH), g_ad1, 37)); }
    gad_free(&r);
}
TEST(ctaprpc_gadec_array_select_by_user_id) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[3] = { g_ad1, g_ad2, g_ad3 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }, u3[] = { 3, 3, 3, 3 }; const BYTE *us[3] = { u1, u2, u3 };
    cbuf env; ga_array_env(&env, 3, ads, us);
    const BYTE *want[3] = { u1, u2, u3 }; const BYTE *wad[3] = { g_ad1, g_ad2, g_ad3 };
    for (int i = 0; i < 3; i++) {
        gad_res r = gad_call(env.b, env.n, 0, want[i], 4);
        CHECKF(r.hr == 0, "sel %d hr=0x%08lx", i, (unsigned long)r.hr);
        if (r.hr == 0 && r.as) CHECKF(!memcmp(PTR(r.as, AS_PB_AUTH), wad[i], 37), "sel %d picked wrong assertion", i);
        gad_free(&r);
    }
}
TEST(ctaprpc_gadec_array_select_unknown_user_falls_back_to_first) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }, nope[] = { 9, 9, 9, 9 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    gad_res r = gad_call(env.b, env.n, 0, nope, 4);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) CHECK(!memcmp(PTR(r.as, AS_PB_AUTH), g_ad1, 37));
    gad_free(&r);
}
TEST(ctaprpc_gadec_array_select_prefix_of_user_id) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    /* The comparison is memcmp over the caller's length against the stored id (stored length >= caller length). */
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    gad_res r = gad_call(env.b, env.n, 0, u2, 2);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) CHECK(!memcmp(PTR(r.as, AS_PB_AUTH), g_ad2, 37));
    gad_free(&r);
    gad_res r2 = gad_call(env.b, env.n, 0, u2, 5);   /* longer than the stored id: never matches */
    if (r2.hr == 0 && r2.as) CHECK(!memcmp(PTR(r2.as, AS_PB_AUTH), g_ad1, 37));
    gad_free(&r2);
}
TEST(ctaprpc_gadec_empty_array) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse));
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_arr(&pl, 0);
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 1, NULL, 0);
    /* no element can be selected: NTE no-match is expected, exact value recorded */
    t_note("gadec empty array: hr=0x%08lx", (unsigned long)r.hr);
    CHECK(FAILED(r.hr)); GAD_FAIL_POINTERS(r);
}
TEST(ctaprpc_gadec_array_element_missing_signature) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_arr(&pl, 1); cb_map(&pl, 1); cb_uint(&pl, 2); cb_bstr(&pl, g_ad1, 37);
    envelope(&env, 0, pl.b, pl.n);
    gad_res r = gad_call(env.b, env.n, 1, NULL, 0);
    t_note("gadec array element missing signature: hr=0x%08lx", (unsigned long)r.hr);
    CHECK(FAILED(r.hr));
    if (FAILED(r.hr)) GAD_FAIL_POINTERS(r);
    gad_free(&r);
}
TEST(ctaprpc_gadec_array_of_one) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[1] = { g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }; const BYTE *us[1] = { u1 };
    cbuf env; ga_array_env(&env, 1, ads, us);
    gad_res r = gad_call(env.b, env.n, 1, NULL, 0);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr == 0 && r.as) CHECK(!memcmp(PTR(r.as, AS_PB_AUTH), g_ad2, 37));
    gad_free(&r);
}
TEST(ctaprpc_gadec_repeated_calls_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, (const BYTE *)"\x01\x02", 2);
    gad_res w = gad_call(env.b, env.n, 0, NULL, 0); gad_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 20000; i++) { gad_res r = gad_call(env.b, env.n, 0, NULL, 0); if (r.hr != 0) bad++; gad_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d failures", bad);
    if (before && after) { CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before); t_note("gadec x20000 private-bytes growth within bound"); }
}
TEST(ctaprpc_gadec_array_path_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    gad_res w = gad_call(env.b, env.n, 0, u2, 4); gad_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 10000; i++) { gad_res r = gad_call(env.b, env.n, 0, u2, 4); if (r.hr != 0) bad++; gad_free(&r); gad_res f = gad_call(env.b, env.n, 0, NULL, 0); if (f.hr != HR_NO_MATCH || f.as || f.dev) bad++; gad_free(&f); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unexpected results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}

/* ------------------- WebAuthNCtapRpcSelectGetAssertion ------------------------ */
typedef struct { ULONGLONG hr; ULONG cb; BYTE *pb; } sel_res;
static sel_res sel_call(const BYTE *p, size_t n, ULONG index) {
    sel_res r; r.cb = 0xDEADBEEF; r.pb = (BYTE *)(ULONG_PTR)1;
    BYTE *copy = (BYTE *)malloc(n ? n : 1); if (n) memcpy(copy, p, n);
    r.hr = UN(WebAuthNCtapRpcSelectGetAssertion)((ULONG)n, n ? copy : NULL, index, &r.cb, &r.pb);
    free(copy);
    return r;
}
static void sel_free(sel_res *r) { if (r->pb && r->pb != (BYTE *)(ULONG_PTR)1) { CoTaskMemFree_pfn f = crc_cotaskfree(); if (f) f(r->pb); } r->pb = NULL; }
#define SEL_HR(r) ((ULONG)(r).hr)
#define SEL_OUT_ZERO(r) do { CHECK((r).cb == 0); CHECK((r).pb == NULL); } while (0)

TEST(ctaprpc_select_empty_input) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion));
    sel_res r = sel_call((const BYTE *)"", 0, 0);
    EXPECT_EQ(SEL_HR(r), (ULONG)HR_CBOR_EMPTY); SEL_OUT_ZERO(r);
}
TEST(ctaprpc_select_garbage_table) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion));
    static const BYTE a[] = { 0xFF }, b[] = { 0x00 }, c[] = { 0xA0 }, d[] = { 0xA3, 0x6A }, e[] = { 0x81, 0x01 };
    static const struct { const BYTE *p; size_t n; const char *w; } t[] = { { a, 1, "break" }, { b, 1, "uint" }, { c, 1, "empty map" }, { d, 2, "truncated" }, { e, 2, "array" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        sel_res r = sel_call(t[i].p, t[i].n, 0);
        CHECKF(is_cbor_layer_error((LONG)SEL_HR(r)), "%s: hr=0x%08lx", t[i].w, (unsigned long)SEL_HR(r)); SEL_OUT_ZERO(r);
    }
}
TEST(ctaprpc_select_empty_response_bstr) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion));
    cbuf c; envelope(&c, 0, (const BYTE *)"", 0);
    sel_res r = sel_call(c.b, c.n, 0);
    EXPECT_EQ(SEL_HR(r), (ULONG)HR_INVALID_DATA); SEL_OUT_ZERO(r);
}
TEST(ctaprpc_select_nonzero_ctap_status) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    BYTE b[3] = { 0x2E, 0xA0, 0 }; cbuf c; envelope(&c, 0, b, 2);
    sel_res r = sel_call(c.b, c.n, 0);
    EXPECT_EQ(SEL_HR(r), (ULONG)HR_INVALID_DATA); SEL_OUT_ZERO(r);
}
TEST(ctaprpc_select_index_out_of_range) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    static const ULONG idx[] = { 2, 3, 100, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof idx / sizeof idx[0]; i++) {
        sel_res r = sel_call(env.b, env.n, idx[i]);
        CHECKF(SEL_HR(r) == (ULONG)HR_NO_MATCH, "index %lu hr=0x%08lx", idx[i], (unsigned long)SEL_HR(r)); SEL_OUT_ZERO(r);
    }
}
TEST(ctaprpc_select_empty_array_any_index) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion));
    cbuf pl, env; pl.n = 0; cb_byte(&pl, 0); cb_arr(&pl, 0); envelope(&env, 0, pl.b, pl.n);
    sel_res r = sel_call(env.b, env.n, 0);
    t_note("select on empty array: hr=0x%08lx", (unsigned long)SEL_HR(r));
    CHECK(FAILED((LONG)SEL_HR(r))); SEL_OUT_ZERO(r);
}
TEST(ctaprpc_select_payload_not_array) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    cbuf env; ga_single_env(&env, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    sel_res r = sel_call(env.b, env.n, 0);
    CHECKF(FAILED((LONG)SEL_HR(r)), "hr=0x%08lx", (unsigned long)SEL_HR(r));
    t_note("select with single-map payload: hr=0x%08lx", (unsigned long)SEL_HR(r));
    SEL_OUT_ZERO(r);
}
TEST(ctaprpc_select_each_index_returns_envelope) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); REQUIRE(UN(I_WebAuthNCtapDecodeGetAssertionRpcResponse)); init_ads();
    const BYTE *ads[3] = { g_ad1, g_ad2, g_ad3 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }, u3[] = { 3, 3, 3, 3 }; const BYTE *us[3] = { u1, u2, u3 };
    cbuf env; ga_array_env(&env, 3, ads, us);
    for (ULONG i = 0; i < 3; i++) {
        sel_res r = sel_call(env.b, env.n, i);
        CHECKF(SEL_HR(r) == 0, "index %lu hr=0x%08lx", i, (unsigned long)SEL_HR(r));
        if (SEL_HR(r) == 0 && r.pb) {
            CHECK(r.cb > 0);
            char keys[64]; size_t end = 0; int cnt = cr_text_keys(r.pb, r.cb, keys, sizeof keys, &end);
            CHECK(cnt == 3); EXPECT_STR(keys, "deviceInfo,status,response"); CHECK(end == r.cb);
            unsigned long long st = 99; CHECK(cr_text_uint(r.pb, r.cb, "status", &st) && st == 0);
            const BYTE *resp; size_t rl; CHECK(cr_text_bytes(r.pb, r.cb, "response", &resp, &rl) && rl > 1 && resp[0] == 0);
            /* the produced envelope must itself be decodable and carry the selected assertion */
            gad_res d = gad_call(r.pb, r.cb, 1, NULL, 0);
            CHECKF(d.hr == 0, "index %lu re-decode hr=0x%08lx", i, (unsigned long)d.hr);
            if (d.hr == 0 && d.as) CHECKF(!memcmp(PTR(d.as, AS_PB_AUTH), ads[i], 37), "index %lu selected wrong assertion", i);
            gad_free(&d);
        }
        sel_free(&r);
    }
}
TEST(ctaprpc_select_output_is_cotaskmem) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    CoTaskMemFree_pfn f = crc_cotaskfree(); REQUIRE(f);
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    sel_res r = sel_call(env.b, env.n, 1);
    CHECK(SEL_HR(r) == 0 && r.pb != NULL);
    if (r.pb) { HANDLE h = GetProcessHeap(); (void)h; f(r.pb); r.pb = NULL; }
    sel_free(&r);
}
TEST(ctaprpc_select_deviceinfo_preserved) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; const BYTE *us[2] = { (const BYTE *)"\1\1\1\1", (const BYTE *)"\2\2\2\2" };
    cbuf env; ga_array_env(&env, 2, ads, us);
    sel_res r = sel_call(env.b, env.n, 0);
    if (SEL_HR(r) == 0 && r.pb) {
        size_t o, l; CHECK(cr_text_find(r.pb, r.cb, "deviceInfo", &o, &l));
        const BYTE *s; size_t sl;
        CHECK(cr_text_bytes(r.pb + o, l, "providerName", &s, &sl) && sl == 12 && !memcmp(s, "TestProvider", 12));
    }
    sel_free(&r);
}
TEST(ctaprpc_select_repeat_no_leak) {
    REQUIRE(UN(WebAuthNCtapRpcSelectGetAssertion)); init_ads();
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf env; ga_array_env(&env, 2, ads, us);
    sel_res w = sel_call(env.b, env.n, 1); sel_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 10000; i++) {
        sel_res r = sel_call(env.b, env.n, 1); if (SEL_HR(r) != 0) bad++; sel_free(&r);
        sel_res f = sel_call(env.b, env.n, 7); if (SEL_HR(f) != (ULONG)HR_NO_MATCH || f.pb) bad++; sel_free(&f);
    }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unexpected results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}

/* ------------------- WebAuthNCtapRpcGetAssertionUserList ---------------------- */
typedef struct { ULONG hr; WCHAR *rpid; void *users; } ul_res;
static ul_res ul_call(const BYTE *rq, size_t rqn, const BYTE *dv, size_t dvn) {
    ul_res r; r.rpid = (WCHAR *)(ULONG_PTR)1; r.users = (void *)(ULONG_PTR)1;
    BYTE *c1 = (BYTE *)malloc(rqn ? rqn : 1), *c2 = (BYTE *)malloc(dvn ? dvn : 1);
    if (rqn) memcpy(c1, rq, rqn);
    if (dvn) memcpy(c2, dv, dvn);
    r.hr = UN(WebAuthNCtapRpcGetAssertionUserList)((ULONG)rqn, rqn ? c1 : NULL, (ULONG)dvn, dvn ? c2 : NULL, &r.rpid, &r.users);
    free(c1); free(c2);
    return r;
}
static void ul_free(ul_res *r) {
    if (r->rpid && r->rpid != (WCHAR *)(ULONG_PTR)1) { CoTaskMemFree_pfn f = crc_cotaskfree(); if (f) f(r->rpid); }
    if (r->users && r->users != (void *)(ULONG_PTR)1) LocalFree(r->users);
    r->rpid = NULL; r->users = NULL;
}
#define UL_OUT_ZERO(r) do { CHECK((r).rpid == NULL); CHECK((r).users == NULL); } while (0)
/* A genuine get-assertion RPC request as produced by the encoder. */
static int ga_request(cbuf *c) {
    ga_args a; ga_args_init(&a); enc_res r = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL);
    c->n = 0; if (r.hr == 0 && r.pb && r.cb <= sizeof c->b) { cb_put(c, r.pb, r.cb); enc_free(&r); return 1; }
    enc_free(&r); return 0;
}

TEST(ctaprpc_userlist_empty_request) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList));
    ul_res r = ul_call((const BYTE *)"", 0, (const BYTE *)"", 0);
    EXPECT_EQ(r.hr, (ULONG)HR_CBOR_EMPTY); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_request_not_getassertion) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList));
    /* request[0] must be 0x02; the device response is not even looked at. */
    static const BYTE ctap[] = { 0x01, 0xA0, 0x03, 0x00, 0xFF };
    for (size_t i = 0; i < sizeof ctap; i++) {
        BYTE rb[2] = { ctap[i], 0xA0 }; cbuf rq; BYTE tx[16] = { 1 };
        rpc_request(&rq, 0, 0, 0, tx, 16, rb, 2);
        ul_res r = ul_call(rq.b, rq.n, (const BYTE *)"", 0);
        CHECKF(r.hr == (ULONG)HR_NOT_FOUND, "ctap=0x%02x hr=0x%08lx", ctap[i], (unsigned long)r.hr); UL_OUT_ZERO(r);
    }
}
TEST(ctaprpc_userlist_request_without_request_member) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList));
    cbuf rq; BYTE tx[16] = { 1 }; rpc_request(&rq, 0, 0, 0, tx, 16, NULL, 0);
    ul_res r = ul_call(rq.b, rq.n, (const BYTE *)"", 0);
    EXPECT_EQ(r.hr, (ULONG)HR_INVALID_DATA); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_empty_device_response) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    cbuf rq; CHECK(ga_request(&rq));
    ul_res r = ul_call(rq.b, rq.n, (const BYTE *)"", 0);
    EXPECT_EQ(r.hr, (ULONG)HR_CBOR_EMPTY); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_device_response_status_byte_nonzero) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    cbuf rq; CHECK(ga_request(&rq));
    BYTE b[3] = { 0x2E, 0x80, 0 }; cbuf dv; envelope(&dv, 0, b, 2);
    ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n);
    EXPECT_EQ(r.hr, (ULONG)HR_INVALID_DATA); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_device_response_empty_response) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    cbuf rq; CHECK(ga_request(&rq));
    cbuf dv; envelope(&dv, 0, (const BYTE *)"", 0);
    ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n);
    EXPECT_EQ(r.hr, (ULONG)HR_INVALID_DATA); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_payload_not_array) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    cbuf rq; CHECK(ga_request(&rq));
    cbuf dv; ga_single_env(&dv, g_ad1, g_sig1, sizeof g_sig1, NULL, 0);
    ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n);
    EXPECT_EQ(r.hr, (ULONG)HR_NOT_FOUND); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_element_without_user_rejected) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    cbuf rq; CHECK(ga_request(&rq));
    const BYTE *ads[2] = { g_ad1, g_ad2 }; cbuf dv; ga_array_env(&dv, 2, ads, NULL);   /* no user members */
    ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n);
    EXPECT_EQ(r.hr, (ULONG)HR_INVALID_DATA); UL_OUT_ZERO(r);
}
TEST(ctaprpc_userlist_two_users) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    cbuf rq; CHECK(ga_request(&rq));
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf dv; ga_array_env(&dv, 2, ads, us);
    ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n);
    EXPECT_EQ(r.hr, 0);
    CHECK(r.rpid != NULL && r.rpid != (WCHAR *)1); CHECK(r.users != NULL && r.users != (void *)1);
    if (r.hr == 0 && r.rpid && r.users) {
        CHECK(!lstrcmpW(r.rpid, L"example.com"));
        CHECK(LocalSize(r.users) != 0);
        CHECK(U32(r.users, 0) == 2);                     /* count */
        BYTE **arr = *(BYTE ***)((BYTE *)r.users + 8);   /* array of USER_ENTITY_INFORMATION* */
        CHECK(arr != NULL);
        if (arr) {
            for (int i = 0; i < 2; i++) {
                const BYTE *ui = arr[i]; CHECKF(ui != NULL, "user %d", i);
                if (!ui) continue;
                CHECK(U32(ui, 0) == 1); CHECK(U32(ui, 4) == 4);
                CHECK(!memcmp(*(BYTE **)(ui + 8), i ? u2 : u1, 4));
            }
        }
    }
    ul_free(&r);
}
TEST(ctaprpc_userlist_rpid_is_cotaskmem_copy) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    CoTaskMemFree_pfn f = crc_cotaskfree(); REQUIRE(f);
    cbuf rq; CHECK(ga_request(&rq));
    const BYTE *ads[1] = { g_ad1 }; static const BYTE u1[] = { 1, 1, 1, 1 }; const BYTE *us[1] = { u1 };
    cbuf dv; ga_array_env(&dv, 1, ads, us);
    ul_res a = ul_call(rq.b, rq.n, dv.b, dv.n), b = ul_call(rq.b, rq.n, dv.b, dv.n);
    CHECK(a.hr == 0 && b.hr == 0);
    if (a.rpid && b.rpid) { CHECK(a.rpid != b.rpid); CHECK(!lstrcmpW(a.rpid, b.rpid)); }
    ul_free(&a); ul_free(&b);
}
TEST(ctaprpc_userlist_rpid_follows_request) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    static const WCHAR *ids[] = { L"a.example", L"login.example.org" };
    const BYTE *ads[1] = { g_ad1 }; static const BYTE u1[] = { 1, 1, 1, 1 }; const BYTE *us[1] = { u1 };
    cbuf dv; ga_array_env(&dv, 1, ads, us);
    for (int i = 0; i < 2; i++) {
        ga_args a; ga_args_init(&a); enc_res e = ga_encode(&a, ids[i], 0, 0, 0, NULL, NULL, NULL);
        CHECK(e.hr == 0);
        if (e.pb) {
            ul_res r = ul_call(e.pb, e.cb, dv.b, dv.n);
            CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
            if (r.hr == 0 && r.rpid) CHECKF(!lstrcmpW(r.rpid, ids[i]), "rpid %d", i);
            ul_free(&r);
        }
        enc_free(&e);
    }
}
TEST(ctaprpc_userlist_makecredential_request_is_rejected) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)); init_ads();
    mc_args a; mc_args_init(&a); enc_res e = mc_encode(&a, 0, 0, 0, NULL, NULL, NULL);
    const BYTE *ads[1] = { g_ad1 }; static const BYTE u1[] = { 1, 1, 1, 1 }; const BYTE *us[1] = { u1 };
    cbuf dv; ga_array_env(&dv, 1, ads, us);
    if (e.pb) { ul_res r = ul_call(e.pb, e.cb, dv.b, dv.n); EXPECT_EQ(r.hr, (ULONG)HR_NOT_FOUND); UL_OUT_ZERO(r); }
    enc_free(&e);
}
TEST(ctaprpc_userlist_repeat_no_leak) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    cbuf rq; CHECK(ga_request(&rq));
    const BYTE *ads[2] = { g_ad1, g_ad2 }; static const BYTE u1[] = { 1, 1, 1, 1 }, u2[] = { 2, 2, 2, 2 }; const BYTE *us[2] = { u1, u2 };
    cbuf dv; ga_array_env(&dv, 2, ads, us);
    ul_res w = ul_call(rq.b, rq.n, dv.b, dv.n); ul_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 10000; i++) { ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n); if (r.hr != 0) bad++; ul_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d failures", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}
TEST(ctaprpc_userlist_failure_path_no_leak) {
    REQUIRE(UN(WebAuthNCtapRpcGetAssertionUserList)); REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); init_ads();
    cbuf rq; CHECK(ga_request(&rq));
    const BYTE *ads[2] = { g_ad1, g_ad2 }; cbuf dv; ga_array_env(&dv, 2, ads, NULL);
    ul_res w = ul_call(rq.b, rq.n, dv.b, dv.n); ul_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 10000; i++) { ul_res r = ul_call(rq.b, rq.n, dv.b, dv.n); if (r.hr != (ULONG)HR_INVALID_DATA || r.rpid || r.users) bad++; ul_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unexpected results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}
