/* Request-encoder rejections. After the entry-point check the DLL builds the CTAP request; malformed COSE parameters,
 * exclude-list entries and credProtect extension data make that fail with HRESULT_FROM_WIN32(ERROR_INVALID_DATA)
 * (0x8007000D) before anything is sent to the service. Single-fault cases (everything else valid) prove rejection. */
#include "mcv.h"
#define NTE MCV_NTE_INVALID_PARAMETER
#define ENC MCV_ENC_FAIL

/* ---- COSE credential parameter elements (24-byte elements: version, type, alg) ---- */
MCT(cose_alg_zero,           ENC, a->cp[0].lAlg = 0;)
MCT(cose_type_null,          ENC, a->cp[0].pwszCredentialType = NULL;)
MCT(cose_type_empty,         ENC, a->cp[0].pwszCredentialType = L"";)
MCT(cose_element_version_zero, ENC, a->cp[0].dwVersion = 0;)
MCT(cose_element_zeroed,     ENC, memset(&a->cp[0], 0, sizeof a->cp[0]);)
MCT(cose_second_alg_zero,    ENC, a->cose.cCredentialParameters = 2; a->cp[1].lAlg = 0;)
MCT(cose_second_type_null,   ENC, a->cose.cCredentialParameters = 2; a->cp[1].pwszCredentialType = NULL;)
MCT(cose_second_type_empty,  ENC, a->cose.cCredentialParameters = 2; a->cp[1].pwszCredentialType = L"";)
MCT(cose_second_version_zero, ENC, a->cose.cCredentialParameters = 2; a->cp[1].dwVersion = 0;)
MCT(cose_third_alg_zero,     ENC, a->cose.cCredentialParameters = 3; a->cp[2].lAlg = 0;)
MCT(cose_fourth_version_zero, ENC, a->cose.cCredentialParameters = 4; a->cp[3].dwVersion = 0;)
MCT(cose_first_bad_second_ok, ENC, a->cose.cCredentialParameters = 2; a->cp[0].lAlg = 0;)
MCT(cose_all_four_bad,       ENC, a->cose.cCredentialParameters = 4; for (int i = 0; i < 4; i++) a->cp[i].lAlg = 0;)
MCT(cose_one_bad_in_four_valid_around, ENC, a->cose.cCredentialParameters = 4; a->cp[2].pwszCredentialType = L"";)

/* Algorithm / type values the encoder does not judge (the second element is the guaranteed fault, so a result of
 * ENC rather than NTE shows the first element was not rejected at entry). */
static const LONG k_algs[] = { -7, -8, -35, -36, -37, -38, -39, -257, -258, -259, 1, 2, 3, 7, -1, -9999, 0x7fffffff, (LONG)0x80000000, -65536, 100000 };
MCB(cose_alg_values_not_judged) { a->cose.cCredentialParameters = 2; a->cp[0].lAlg = k_algs[p]; a->cp[1].lAlg = 0; }
TEST(mcv_cose_alg_values_not_judged_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < (int)(sizeof k_algs / sizeof k_algs[0]); i++) mcv_expect("cose_alg_values_not_judged", i, ENC, 1);
}
static const WCHAR *const k_types[] = { L"public-key", L"PUBLIC-KEY", L"ScopedCred", L"scopedcred", L"bogus", L"x", L"public-key ", L"password", L"webauthn.create" };
MCB(cose_type_values_not_judged) { a->cose.cCredentialParameters = 2; a->cp[0].pwszCredentialType = k_types[p]; a->cp[1].lAlg = 0; }
TEST(mcv_cose_type_values_not_judged_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < (int)(sizeof k_types / sizeof k_types[0]); i++) mcv_expect("cose_type_values_not_judged", i, ENC, 1);
}
/* element version values other than 0 are not examined */
static const DWORD k_vers[] = { 1, 2, 3, 4, 5, 100, 0x7fffffff, 0xffffffff };
MCB(cose_element_version_not_judged) { a->cose.cCredentialParameters = 2; a->cp[0].dwVersion = k_vers[p]; a->cp[1].lAlg = 0; }
TEST(mcv_cose_element_version_nonzero_accepted) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 8; i++) mcv_expect("cose_element_version_not_judged", i, ENC, 1);
}
/* one alg value alone as the only element: only 0 is rejected by the encoder; all single non-zero values go further,
 * so only the rejected one is asserted */
MCB(cose_single_alg_zero_with_type) { a->cp[0].pwszCredentialType = k_types[p]; a->cp[0].lAlg = 0; }
TEST(mcv_cose_alg_zero_rejected_for_every_type_string) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < (int)(sizeof k_types / sizeof k_types[0]); i++) mcv_expect("cose_single_alg_zero_with_type", i, ENC, 1);
}

/* ---- exclude list, legacy form (options v1/v2; also v3/v4 when pExcludeCredentialList is NULL) ---- */
MCB(excl_legacy_cb0)        { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 1); a->legacy[0].cbId = 0; }
MCB(excl_legacy_type_null)  { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 1); a->legacy[0].pwszCredentialType = NULL; }
MCB(excl_legacy_type_empty) { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 1); a->legacy[0].pwszCredentialType = L""; }
MCB(excl_legacy_second_cb0) { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 2); a->legacy[1].cbId = 0; }
MCB(excl_legacy_third_type_empty) { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 3); a->legacy[2].pwszCredentialType = L""; }
MCB(excl_legacy_first_cb0_of_two) { mcv_use_opts(a, (DWORD)p); mcv_legacy_list(a, 2); a->legacy[0].cbId = 0; }
#define LEGACY_LOOP(T, B) TEST(mcv_##T) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); \
    for (int v = 1; v <= 4; v++) mcv_expect(#B, v, ENC, 1); }
LEGACY_LOOP(exclude_legacy_cbid_zero_rejected, excl_legacy_cb0)
LEGACY_LOOP(exclude_legacy_type_null_rejected, excl_legacy_type_null)
LEGACY_LOOP(exclude_legacy_type_empty_rejected, excl_legacy_type_empty)
LEGACY_LOOP(exclude_legacy_second_entry_bad_rejected, excl_legacy_second_cb0)
LEGACY_LOOP(exclude_legacy_third_entry_bad_rejected, excl_legacy_third_type_empty)
LEGACY_LOOP(exclude_legacy_first_entry_bad_rejected, excl_legacy_first_cb0_of_two)

/* ---- exclude list, v3 form (options dwVersion >= 3, pExcludeCredentialList non-NULL: array of EX pointers) ---- */
MCB(excl_ex_version0)   { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 1); a->ex[0].dwVersion = 0; }
MCB(excl_ex_cb0)        { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 1); a->ex[0].cbId = 0; }
MCB(excl_ex_type_null)  { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 1); a->ex[0].pwszCredentialType = NULL; }
MCB(excl_ex_type_empty) { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 1); a->ex[0].pwszCredentialType = L""; }
MCB(excl_ex_second_bad) { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 2); a->ex[1].cbId = 0; }
MCB(excl_ex_fourth_bad) { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 4); a->ex[3].dwVersion = 0; }
MCB(excl_ex_zeroed)     { mcv_use_opts(a, (DWORD)p); mcv_ex_list(a, 1); memset(&a->ex[0], 0, sizeof a->ex[0]); }
static const long long k_v3plus[] = { 3, 4, 5, 6, 100 };
#define EX_LOOP(T, B) TEST(mcv_##T) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); \
    for (int i = 0; i < 5; i++) mcv_expect(#B, k_v3plus[i], ENC, 1); }
EX_LOOP(exclude_v3_entry_version_zero_rejected, excl_ex_version0)
EX_LOOP(exclude_v3_entry_cbid_zero_rejected, excl_ex_cb0)
EX_LOOP(exclude_v3_entry_type_null_rejected, excl_ex_type_null)
EX_LOOP(exclude_v3_entry_type_empty_rejected, excl_ex_type_empty)
EX_LOOP(exclude_v3_second_entry_bad_rejected, excl_ex_second_bad)
EX_LOOP(exclude_v3_fourth_entry_bad_rejected, excl_ex_fourth_bad)
EX_LOOP(exclude_v3_entry_zeroed_rejected, excl_ex_zeroed)

/* ---- credProtect extension payload: needs >= 8 bytes of data ---- */
MCB(ext_credprotect_short) { mcv_use_opts(a, 1); mcv_one_ext(a, L"credProtect", (DWORD)p, a->cprot); }
MCB(ext_credprotect_null_data) { mcv_use_opts(a, 1); mcv_one_ext(a, L"credProtect", (DWORD)p, NULL); }
MCB(ext_credprotect_case) { mcv_use_opts(a, 1); static const WCHAR *ids[] = { L"CREDPROTECT", L"credprotect", L"CredProtect", L"cREDpROTECT" }; mcv_one_ext(a, ids[p], 4, a->cprot); }
TEST(mcv_ext_credprotect_short_data_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int cb = 0; cb < 8; cb++) mcv_expect("ext_credprotect_short", cb, ENC, 1);
}
TEST(mcv_ext_credprotect_null_data_rejected) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int cb = 0; cb <= 16; cb += 4) mcv_expect("ext_credprotect_null_data", cb, ENC, 1);
}
TEST(mcv_ext_credprotect_identifier_case_insensitive) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int i = 0; i < 4; i++) mcv_expect("ext_credprotect_case", i, ENC, 1);
}
/* options version is irrelevant for extensions (read from every options version) */
MCB(ext_credprotect_short_ver) { mcv_use_opts(a, (DWORD)p); mcv_one_ext(a, L"credProtect", 4, a->cprot); }
TEST(mcv_ext_credprotect_short_data_any_options_version) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (int v = 1; v <= 6; v++) mcv_expect("ext_credprotect_short_ver", v, ENC, 1);
}
/* the first credProtect entry that is invalid, after an unrelated extension */
MCB(ext_second_is_credprotect_bad) {
    mcv_use_opts(a, 1); a->hmac = 0;
    a->ext[0].pwszExtensionIdentifier = L"hmac-secret"; a->ext[0].cbExtension = 4; a->ext[0].pvExtension = &a->hmac;
    a->ext[1].pwszExtensionIdentifier = L"credProtect"; a->ext[1].cbExtension = 0; a->ext[1].pvExtension = NULL;
    a->opts.cExtensions = 2; a->opts.pExtensions = a->ext;
}
MCB(ext_unknown_then_credprotect_bad) {
    mcv_use_opts(a, 1);
    a->ext[0].pwszExtensionIdentifier = L"someUnknownExtension"; a->ext[0].cbExtension = 0; a->ext[0].pvExtension = NULL;
    a->ext[1].pwszExtensionIdentifier = L"credProtect"; a->ext[1].cbExtension = 7; a->ext[1].pvExtension = a->cprot;
    a->opts.cExtensions = 2; a->opts.pExtensions = a->ext;
}
MCB(ext_bad_credprotect_then_good) {
    mcv_use_opts(a, 1);
    a->cprot[0] = 3; a->cprot[1] = 0;
    a->ext[0].pwszExtensionIdentifier = L"credProtect"; a->ext[0].cbExtension = 2; a->ext[0].pvExtension = a->cprot;
    a->ext[1].pwszExtensionIdentifier = L"credProtect"; a->ext[1].cbExtension = 8; a->ext[1].pvExtension = a->cprot;
    a->opts.cExtensions = 2; a->opts.pExtensions = a->ext;
}
MCT(ext_hmac_secret_before_bad_credprotect, ENC, bld_ext_second_is_credprotect_bad(a, 0);)
MCT(ext_unknown_before_bad_credprotect,     ENC, bld_ext_unknown_then_credprotect_bad(a, 0);)
MCT(ext_bad_credprotect_first_of_two,       ENC, bld_ext_bad_credprotect_then_good(a, 0);)
