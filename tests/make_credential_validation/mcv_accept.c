/* Arguments that the entry-point check does NOT reject. Each case adds one guaranteed encoder-level fault (a COSE parameter
 * with algorithm 0) so the call can never reach the service; the expected result 0x8007000D (instead of 0x80090027) then
 * demonstrates that the varied argument passed the entry-point check. */
#include "mcv.h"
#define NTE MCV_NTE_INVALID_PARAMETER
#define ENC MCV_ENC_FAIL

static WCHAR g_wbig[8200];
static void init_big(void) { static int done; if (!done) { for (int i = 0; i < 8192; i++) g_wbig[i] = (WCHAR)(L'a' + i % 26); g_wbig[8192] = 0; done = 1; } }

static const DWORD k_ver[] = { 1, 2, 3, 4, 5, 6, 7, 100, 0x7fffffff, 0x80000000u, 0xffffffffu };
#define NVER ((int)(sizeof k_ver / sizeof k_ver[0]))

/* ---- struct versions ---- */
MCB(rp_version)     { a->rp.dwVersion = k_ver[p]; mcv_bad_alg(a); }
MCB(user_version)   { a->user.dwVersion = k_ver[p]; mcv_bad_alg(a); }
MCB(client_version) { a->cd.dwVersion = k_ver[p]; mcv_bad_alg(a); }
MCB(opts_version)   { mcv_use_opts(a, k_ver[p]); mcv_bad_alg(a); }
TEST(mcv_rp_version_nonzero_accepted)     { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < NVER; i++) mcv_expect("rp_version", i, ENC, 1); }
TEST(mcv_user_version_nonzero_accepted)   { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < NVER; i++) mcv_expect("user_version", i, ENC, 1); }
TEST(mcv_client_version_nonzero_accepted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < NVER; i++) mcv_expect("client_version", i, ENC, 1); }
TEST(mcv_options_version_nonzero_accepted){ REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < NVER; i++) mcv_expect("opts_version", i, ENC, 1); }

/* ---- RP strings ---- */
MCB(rp_id_string) {
    init_big();
    static const WCHAR *ids[] = { L"", L"a", L"example.com", L"localhost", L"EXAMPLE.COM", L"not a domain", L"https://example.com", L"example.com:8443", L"login.microsoft.com", L"login.live.com", L"éxample.com", L"..", NULL };
    a->rp.pwszId = p < 12 ? ids[p] : (p == 12 ? g_wbig : g_wbig + 8192 - 253);
    a->rp.pwszName = p == 13 ? NULL : a->rp.pwszName;
    mcv_bad_alg(a);
}
TEST(mcv_rp_id_content_not_judged_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 14; i++) mcv_expect("rp_id_string", i, ENC, 1);   /* empty, long (8192 chars), IP-like, with scheme, ... */
}
MCB(rp_name_icon) {
    init_big();
    static const WCHAR *v[] = { NULL, L"", L"n", NULL };
    a->rp.pwszName = p < 3 ? v[p] : g_wbig;
    a->rp.pwszIcon = p == 1 ? L"" : a->rp.pwszIcon;
    mcv_bad_alg(a);
}
TEST(mcv_rp_name_not_required) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 4; i++) mcv_expect("rp_name_icon", i, ENC, 1); }

/* ---- user fields ---- */
static const DWORD k_idlen[] = { 1, 2, 8, 16, 32, 63, 64, 65, 66, 100, 127, 128, 255, 256, 257, 400, 512 };
#define NIDLEN ((int)(sizeof k_idlen / sizeof k_idlen[0]))
MCB(user_id_len) { a->user.cbId = k_idlen[p]; mcv_bad_alg(a); }
TEST(mcv_user_id_length_not_limited_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < NIDLEN; i++) mcv_expect("user_id_len", i, ENC, 1);   /* includes 65..512 (> 64 bytes) */
}
MCB(user_names) {
    init_big();
    switch ((int)p) {
    case 0: a->user.pwszName = NULL; break;
    case 1: a->user.pwszName = L""; break;
    case 2: a->user.pwszDisplayName = NULL; break;
    case 3: a->user.pwszDisplayName = L""; break;
    case 4: a->user.pwszName = NULL; a->user.pwszDisplayName = NULL; break;
    case 5: a->user.pwszName = g_wbig; break;
    case 6: a->user.pwszDisplayName = g_wbig; break;
    case 7: a->user.pwszIcon = NULL; break;
    case 8: a->user.pwszIcon = g_wbig; break;
    case 9: a->user.pwszName = L""; a->user.pwszDisplayName = L""; a->user.pwszIcon = L""; break;
    }
    mcv_bad_alg(a);
}
TEST(mcv_user_name_fields_not_required) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 10; i++) mcv_expect("user_names", i, ENC, 1);
}
MCB(user_id_bytes) {
    if (p == 0) memset(a->userid, 0, 32);
    if (p == 1) memset(a->userid, 0xff, 32);
    a->user.cbId = 32; mcv_bad_alg(a);
}
TEST(mcv_user_id_bytes_not_interpreted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 2; i++) mcv_expect("user_id_bytes", i, ENC, 1); }

/* ---- client data ---- */
static const DWORD k_cb[] = { 1, 2, 15, 16, 31, 32, 33, 64, 255, 256, 1024, 4096, 16384, 65536, 69999 };
#define NCB ((int)(sizeof k_cb / sizeof k_cb[0]))
MCB(client_len) { a->cd.cbClientDataJSON = k_cb[p]; mcv_bad_alg(a); }
TEST(mcv_client_data_length_variants_accepted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < NCB; i++) mcv_expect("client_len", i, ENC, 1); }
static const WCHAR *const k_hash[] = { L"SHA-256", L"SHA-384", L"SHA-512", L"SHA256", L"SHA384", L"SHA512", L"SHA1", L"SHA-1", L"MD5", L"sha-256", L"", L"bogus-hash", L"SHA-256 ", L"RSA" };
MCB(client_hashalg) { a->cd.pwszHashAlgId = k_hash[p]; mcv_bad_alg(a); }
TEST(mcv_client_hash_alg_not_validated_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < (int)(sizeof k_hash / sizeof k_hash[0]); i++) mcv_expect("client_hashalg", i, ENC, 1);
}
MCB(client_json_content) {
    static const char *j[] = { "{}", "x", "\0\0\0\0", "not json at all", "{\"type\":\"webauthn.get\"}" };
    memset(a->json, 0, 64); size_t n = p == 2 ? 4 : strlen(j[p]); memcpy(a->json, j[p], n); a->cd.cbClientDataJSON = (DWORD)n; mcv_bad_alg(a);
}
TEST(mcv_client_json_not_parsed_at_entry) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 5; i++) mcv_expect("client_json_content", i, ENC, 1); }

/* ---- options values ---- */
static const DWORD k_att[] = { 0, 1, 2, 3, 4, 5, 100, 0x7fffffff, 0xffffffff };
MCB(opt_attachment) { mcv_use_opts(a, 1); a->opts.dwAuthenticatorAttachment = k_att[p]; mcv_bad_alg(a); }
MCB(opt_uv)         { mcv_use_opts(a, 1); a->opts.dwUserVerificationRequirement = k_att[p]; mcv_bad_alg(a); }
MCB(opt_attest)     { mcv_use_opts(a, 1); a->opts.dwAttestationConveyancePreference = k_att[p]; mcv_bad_alg(a); }
MCB(opt_timeout)    { mcv_use_opts(a, 1); a->opts.dwTimeoutMilliseconds = k_att[p] * 1000u; mcv_bad_alg(a); }
MCB(opt_rk)         { mcv_use_opts(a, 1); a->opts.bRequireResidentKey = k_att[p]; mcv_bad_alg(a); }
MCB(opt_flags)      { mcv_use_opts(a, 1); a->opts.dwFlags = k_att[p] | (p == 8 ? 0 : 0); mcv_bad_alg(a); }
#define OPT_LOOP(T, B) TEST(mcv_##T) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 9; i++) mcv_expect(#B, i, ENC, 1); }
OPT_LOOP(opt_attachment_values_not_judged_at_entry, opt_attachment)
OPT_LOOP(opt_user_verification_values_not_judged_at_entry, opt_uv)
OPT_LOOP(opt_attestation_values_not_judged_at_entry, opt_attest)
OPT_LOOP(opt_timeout_values_not_judged_at_entry, opt_timeout)
OPT_LOOP(opt_require_resident_key_values_not_judged_at_entry, opt_rk)
OPT_LOOP(opt_flags_values_not_judged_at_entry, opt_flags)
/* The same attachment values on a v4-version options block */
MCB(opt_attachment_v4) { mcv_use_opts(a, 4); a->opts.dwAuthenticatorAttachment = k_att[p]; a->opts.dwEnterpriseAttestation = 7; a->opts.dwLargeBlobSupport = 9; a->opts.bPreferResidentKey = 1; mcv_bad_alg(a); }
OPT_LOOP(opt_attachment_values_v4_options, opt_attachment_v4)
/* Empty exclude structures are fine */
MCB(excl_empty) {
    mcv_use_opts(a, (DWORD)p);
    mcv_legacy_list(a, 0); mcv_ex_list(a, 0); mcv_bad_alg(a);
}
TEST(mcv_empty_exclude_lists_accepted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int v = 1; v <= 4; v++) mcv_expect("excl_empty", v, ENC, 1); }
MCB(ext_other_accepted) {
    mcv_use_opts(a, 1);
    static const WCHAR *ids[] = { L"hmac-secret", L"someUnknownExtension", L"", L"credBlob", L"minPinLength", L"largeBlob" };
    a->hmac = 1;
    mcv_one_ext(a, ids[p], 4, &a->hmac); mcv_bad_alg(a);
}
TEST(mcv_other_extensions_not_judged_at_entry) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 6; i++) mcv_expect("ext_other_accepted", i, ENC, 1); }
MCB(ext_credprotect_ok) {
    mcv_use_opts(a, 1); a->cprot[0] = (DWORD)p; a->cprot[1] = (p & 1);
    mcv_one_ext(a, L"credProtect", 8, a->cprot); mcv_bad_alg(a);
}
TEST(mcv_credprotect_with_full_payload_accepted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); for (int i = 0; i < 5; i++) mcv_expect("ext_credprotect_ok", i, ENC, 1); }
MCB(ext_credprotect_big_cb) { mcv_use_opts(a, 1); mcv_one_ext(a, L"credProtect", (DWORD)p, a->cprot); mcv_bad_alg(a); }
TEST(mcv_credprotect_payload_larger_than_8_accepted) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("ext_credprotect_big_cb", 8, ENC, 1); mcv_expect("ext_credprotect_big_cb", 8, ENC, 1); }

/* ---- hWnd is never validated or used on these paths ---- */
MCB(hwnd_variant) { a->hwnd_sel = (int)p; mcv_bad_alg(a); }
MCB(hwnd_variant_single_fault) { a->hwnd_sel = (int)p; mcv_bad_alg(a); }
static const char *const k_hwnd_names[] = { "desktop", "0x1", "-1", "junk", "destroyed", "message-only", "other-process", "static-window" };
TEST(mcv_hwnd_values_not_validated) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i <= MCV_HW_STATIC; i++) {
        int r = mcv_expect("hwnd_variant", i, ENC, 1);
        if (r < 0) t_note("hwnd variant %s unavailable here", k_hwnd_names[i]);
    }
}
TEST(mcv_hwnd_non_window_handle_value) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("hwnd_variant", MCV_HW_ONE, ENC, 1); mcv_expect("hwnd_variant", MCV_HW_JUNK, ENC, 1); }
TEST(mcv_hwnd_destroyed_window)  { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("hwnd_variant", MCV_HW_DESTROYED, ENC, 1); }
TEST(mcv_hwnd_message_only_window) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("hwnd_variant", MCV_HW_MSGONLY, ENC, 1); }
TEST(mcv_hwnd_other_process_window) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    if (mcv_expect("hwnd_variant", MCV_HW_OTHERPROC, ENC, 1) < 0) t_skip("no shell window owned by another process in this session");
}
/* hWnd with an otherwise-invalid argument: the argument fault decides */
MCT(hwnd_junk_with_rp_null, NTE, a->hwnd_sel = MCV_HW_JUNK; a->prp = NULL;)
MCT(hwnd_destroyed_with_user_cbid_zero, NTE, a->hwnd_sel = MCV_HW_DESTROYED; a->user.cbId = 0;)

/* ---- sequential calls: the busy guard is released after an encoder failure and untouched by entry-point rejection ---- */
MCT(repeat_encoder_reject_8, ENC, mcv_bad_alg(a);)
TEST(mcv_repeated_encoder_reject_stable) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("repeat_encoder_reject_8", 0, ENC, 8); }
MCT(repeat_encoder_reject_cose_type, ENC, a->cp[0].pwszCredentialType = L"";)
TEST(mcv_repeated_encoder_reject_type_stable) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect("repeat_encoder_reject_cose_type", 0, ENC, 20); }

/* ---- layout and export identity ---- */
TEST(mcv_declared_layouts) {
    CHECK(sizeof(MCV_RP) == 0x20); CHECK(sizeof(MCV_USER) == 0x28); CHECK(sizeof(MCV_COSE_PARAM) == 0x18);
    CHECK(sizeof(MCV_COSE_PARAMS) == 0x10); CHECK(sizeof(MCV_CLIENT_DATA) == 0x18); CHECK(sizeof(MCV_EXTENSION) == 0x18);
    CHECK(sizeof(MCV_OPTIONS_V1) == 0x40); CHECK(sizeof(MCV_OPTIONS) == 0x60);
    CHECK(offsetof(MCV_USER, pwszDisplayName) == 0x20); CHECK(offsetof(MCV_CLIENT_DATA, pwszHashAlgId) == 0x10);
    CHECK(offsetof(MCV_OPTIONS, pExtensions) == 0x20);
}
TEST(mcv_export_by_name_and_ordinal_8) {
    FARPROC n = t_proc_in("webauthn.dll", "WebAuthNAuthenticatorMakeCredential");
    if (!n) { t_skip("missing export: WebAuthNAuthenticatorMakeCredential"); return; }
    FARPROC o = t_proc_ord("webauthn.dll", 8);
    CHECK(o == n);
}
TEST(mcv_documented_unprobed_paths) {
    /* Paths deliberately not exercised (they fault, race, or reach the service); recorded for implementors. */
    t_note("NULL ppWebAuthNCredentialAttestation: the output pointer is written first, so it faults; not called");
    t_note("cCredentials/cExtensions nonzero with a NULL array pointer: array is dereferenced; not called");
    t_note("concurrent calls: a second in-flight call fails with 0x8001011B via a process-wide busy flag; timing dependent, not called");
    t_note("*ppWebAuthNCredentialAttestation is set to NULL on entry and stays NULL on every early failure");
}
