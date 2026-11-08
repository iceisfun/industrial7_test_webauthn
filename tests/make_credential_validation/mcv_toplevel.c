/* Entry-point argument checks: every case here returns NTE_INVALID_PARAMETER (0x80090027) before anything is encoded.
 * The checked conditions: RP non-NULL, dwVersion != 0, pwszId != NULL; user non-NULL, dwVersion != 0, cbId != 0,
 * pbId != NULL; no "http://" icon URL on RP or user; COSE params non-NULL with count != 0 and array != NULL;
 * client data non-NULL, dwVersion != 0, cbClientDataJSON != 0, pbClientDataJSON != NULL, pwszHashAlgId != NULL;
 * hWnd != NULL; options (when non-NULL) dwVersion != 0. */
#include "mcv.h"
#define NTE MCV_NTE_INVALID_PARAMETER
#define ENC MCV_ENC_FAIL

/* ---- RP ---- */
MCT(rp_null,              NTE, a->prp = NULL;)
MCT(rp_version_zero,      NTE, a->rp.dwVersion = 0;)
MCT(rp_id_null,           NTE, a->rp.pwszId = NULL;)
MCT(rp_zeroed,            NTE, memset(&a->rp, 0, sizeof a->rp);)
MCT(rp_version_zero_id_null, NTE, a->rp.dwVersion = 0; a->rp.pwszId = NULL;)
MCT(rp_name_null_accepted, ENC, a->rp.pwszName = NULL; mcv_bad_alg(a);)
MCT(rp_icon_null_accepted, ENC, a->rp.pwszIcon = NULL; mcv_bad_alg(a);)

/* ---- user ---- */
MCT(user_null,            NTE, a->puser = NULL;)
MCT(user_version_zero,    NTE, a->user.dwVersion = 0;)
MCT(user_cbid_zero,       NTE, a->user.cbId = 0;)
MCT(user_pbid_null,       NTE, a->user.pbId = NULL;)
MCT(user_id_zero_and_null, NTE, a->user.cbId = 0; a->user.pbId = NULL;)
MCT(user_zeroed,          NTE, memset(&a->user, 0, sizeof a->user);)
MCT(user_version_zero_cbid_zero, NTE, a->user.dwVersion = 0; a->user.cbId = 0;)

/* ---- COSE parameters ---- */
MCT(cose_null,            NTE, a->pcose = NULL;)
MCT(cose_count_zero,      NTE, a->cose.cCredentialParameters = 0;)
MCT(cose_array_null_count1, NTE, a->cose.pCredentialParameters = NULL;)
MCT(cose_array_null_count2, NTE, a->cose.cCredentialParameters = 2; a->cose.pCredentialParameters = NULL;)
MCT(cose_array_null_count_large, NTE, a->cose.cCredentialParameters = 0x7fffffff; a->cose.pCredentialParameters = NULL;)
MCT(cose_array_null_count_max, NTE, a->cose.cCredentialParameters = 0xffffffff; a->cose.pCredentialParameters = NULL;)
MCT(cose_zeroed,          NTE, memset(&a->cose, 0, sizeof a->cose);)

/* ---- client data ---- */
MCT(client_null,          NTE, a->pcd = NULL;)
MCT(client_version_zero,  NTE, a->cd.dwVersion = 0;)
MCT(client_cb_zero,       NTE, a->cd.cbClientDataJSON = 0;)
MCT(client_json_null,     NTE, a->cd.pbClientDataJSON = NULL;)
MCT(client_hashalg_null,  NTE, a->cd.pwszHashAlgId = NULL;)
MCT(client_zeroed,        NTE, memset(&a->cd, 0, sizeof a->cd);)
MCT(client_cb_zero_json_null, NTE, a->cd.cbClientDataJSON = 0; a->cd.pbClientDataJSON = NULL;)
MCT(client_version_zero_hash_null, NTE, a->cd.dwVersion = 0; a->cd.pwszHashAlgId = NULL;)

/* ---- hWnd ---- */

/* ---- options ---- */
MCT(options_version_zero, NTE, mcv_use_opts(a, 0);)
MCT(options_version_zero_with_fields, NTE, mcv_use_opts(a, 0); a->opts.dwTimeoutMilliseconds = 60000; a->opts.dwUserVerificationRequirement = 1;)
MCT(options_null_is_accepted, ENC, a->popts = NULL; mcv_bad_alg(a);)

/* ---- everything NULL ---- */
MCT(all_structs_null, NTE, a->prp = NULL; a->puser = NULL; a->pcose = NULL; a->pcd = NULL; a->popts = NULL;)

/* ---- icon URL scheme check ---- */
static const WCHAR *const k_http_icons[] = {
    L"http://example.com/icon.png", L"HTTP://example.com/icon.png", L"Http://example.com/i", L"hTTp://a", L"http://", L"http://x",
};
MCB(user_icon_http) { a->user.pwszIcon = k_http_icons[p]; }
MCB(rp_icon_http)   { a->rp.pwszIcon = k_http_icons[p]; }
MCB(both_icon_http) { a->rp.pwszIcon = k_http_icons[p]; a->user.pwszIcon = k_http_icons[(p + 1) % 6]; }
MCB(user_icon_http_bad_alg) { a->user.pwszIcon = k_http_icons[p]; mcv_bad_alg(a); }
MCB(rp_icon_http_bad_alg)   { a->rp.pwszIcon = k_http_icons[p]; mcv_bad_alg(a); }
TEST(mcv_user_icon_http_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 6; i++) mcv_expect("user_icon_http", i, NTE, 1);
}
TEST(mcv_rp_icon_http_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 6; i++) mcv_expect("rp_icon_http", i, NTE, 1);
}
TEST(mcv_both_icon_http_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 6; i++) mcv_expect("both_icon_http", i, NTE, 1);
}
/* The scheme check precedes request encoding: an http icon wins over an encoder-level fault. */
TEST(mcv_icon_http_checked_before_encoder) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 6; i++) { mcv_expect("user_icon_http_bad_alg", i, NTE, 1); mcv_expect("rp_icon_http_bad_alg", i, NTE, 1); }
}
/* Other URL forms are not rejected by the entry-point check: the encoder fault is what is reported. */
static const WCHAR *const k_ok_icons[] = {
    L"https://example.com/icon.png", L"HTTPS://example.com/i", L"data:image/png;base64,AAAA", L" http://example.com/leading-space", L"ftp://example.com/i",
    L"file:///c:/x.png", L"icon.png", L"", L"htt", L"ttp://example.com", L"xhttp://example.com", L"https://",
};
MCB(user_icon_ok_bad_alg) { a->user.pwszIcon = k_ok_icons[p]; mcv_bad_alg(a); }
MCB(rp_icon_ok_bad_alg)   { a->rp.pwszIcon = k_ok_icons[p]; mcv_bad_alg(a); }
TEST(mcv_user_icon_non_http_not_rejected_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 12; i++) mcv_expect("user_icon_ok_bad_alg", i, ENC, 1);
}
/* The comparison length is not visible in the decomp (assumed 7 for "http://"); prefixes such as "http:/" are therefore not asserted. */
TEST(mcv_rp_icon_non_http_not_rejected_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 12; i++) mcv_expect("rp_icon_ok_bad_alg", i, ENC, 1);
}

/* ---- ordering: entry-point faults win over encoder faults ---- */
MCT(order_rp_null_over_bad_alg,       NTE, a->prp = NULL; mcv_bad_alg(a);)
MCT(order_user_null_over_bad_alg,     NTE, a->puser = NULL; mcv_bad_alg(a);)
MCT(order_client_null_over_bad_alg,   NTE, a->pcd = NULL; mcv_bad_alg(a);)
MCT(order_options_v0_over_bad_alg,    NTE, mcv_use_opts(a, 0); mcv_bad_alg(a);)
MCT(order_json_null_over_bad_alg,     NTE, a->cd.pbClientDataJSON = NULL; mcv_bad_alg(a);)
MCT(order_hashalg_null_over_bad_alg,  NTE, a->cd.pwszHashAlgId = NULL; mcv_bad_alg(a);)
MCT(order_rp_v0_and_user_v0,          NTE, a->rp.dwVersion = 0; a->user.dwVersion = 0;)
MCT(order_all_scalar_faults,          NTE, a->rp.dwVersion = 0; a->user.cbId = 0; a->cd.cbClientDataJSON = 0; a->cose.cCredentialParameters = 0;)
MCT(order_every_pointer_null_with_options_v0_struct, NTE, a->prp = NULL; a->puser = NULL; a->pcose = NULL; a->pcd = NULL; mcv_use_opts(a, 0);)

/* ---- hWnd == NULL ---- */
static void bld_hw0(mcv_args *a, long long p) { (void)p; a->hwnd_sel = -1; }
static void __attribute__((constructor)) regb_hw0(void) { mcv_register("hwnd_null", bld_hw0); }
TEST(mcv_hwnd_null_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    mcv_expect("hwnd_null", 0, NTE, 1);
}
static void bld_hw0_alg(mcv_args *a, long long p) { (void)p; a->hwnd_sel = -1; mcv_bad_alg(a); }
static void __attribute__((constructor)) regb_hw0a(void) { mcv_register("hwnd_null_bad_alg", bld_hw0_alg); }
TEST(mcv_hwnd_null_checked_before_encoder) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    mcv_expect("hwnd_null_bad_alg", 0, NTE, 1);
}

/* ---- repeated rejected calls: the entry-point rejection must leave no residue (busy guard untouched) ---- */
MCT(repeat_toplevel_reject_5, NTE, a->rp.pwszId = NULL;)
TEST(mcv_repeated_toplevel_reject_stable) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    mcv_expect("repeat_toplevel_reject_5", 0, NTE, 5);
}
