#include "cd.h"
/* WebAuthNCtapMakeCredential(hwnd, flags, rp, user, cose, clientData, options, ppAttestation, transactionId,
 *                            pinA, pinB, pOut1, pOut2)
 *
 * Reference behaviour relied on:
 *  - *ppAttestation = NULL is written first (required pointer). *pOut1 / *pOut2 (optional) are set to 0 on every
 *    early failure. The rp record is read (+8) and the COSE parameter record is read (count, then, if the count is
 *    non-zero, the array) while the stop event is logged, so both must point to readable records; with a non-zero
 *    count the array pointer must be valid. These two pointers are therefore never NULL in these tests.
 *  - pinA and pinB both non-NULL: both buffers are wiped (strlen*2 bytes) and the call returns 0x80090027 immediately,
 *    whatever the other arguments hold.
 *  - Both PINs NULL: the request is encoded without a device record. The encoder rejects (0x80090027) when any of
 *    these hold: rp->dwVersion == 0, rp->pwszId == NULL, user == NULL, user->cbId == 0, user->pbId == NULL,
 *    cose->count == 0, cose->array == NULL, clientData == NULL, clientData->dwVersion == 0, ->cbClientDataJSON == 0,
 *    ->pbClientDataJSON == NULL, ->pwszHashAlgId == NULL, options != NULL && options->dwVersion == 0.
 *    A request that passes every one of these goes to the authenticator service, so every call below carries at
 *    least one such defect, and the helper refuses to call otherwise.
 *  - Exactly one PIN set sends the request to device selection: never exercised.
 */

typedef struct {
    CD_RP rp; CD_USER user; CD_COSE_PARAM cp[2]; CD_COSE_PARAMS cose; CD_CLIENT_DATA cd;
    BYTE uid[16]; BYTE json[48]; BYTE opt[0x100];
    int userNull, cdNull, useOpt;
} mcs;

static void mcs_init(mcs *s) {
    memset(s, 0, sizeof *s);
    for (int i = 0; i < 16; i++) s->uid[i] = (BYTE)(i + 1);
    { static const char j[] = "{\"type\":\"webauthn.create\",\"challenge\":\"AAAA\"}"; memcpy(s->json, j, sizeof j - 1); s->cd.cbClientDataJSON = sizeof j - 1; }
    s->rp.dwVersion = 1; s->rp.pwszId = L"example.com"; s->rp.pwszName = L"Example";
    s->user.dwVersion = 1; s->user.cbId = 16; s->user.pbId = s->uid; s->user.pwszName = L"alice"; s->user.pwszDisplayName = L"Alice";
    s->cp[0].dwVersion = 1; s->cp[0].pwszCredentialType = L"public-key"; s->cp[0].lAlg = -7;
    s->cp[1].dwVersion = 1; s->cp[1].pwszCredentialType = L"public-key"; s->cp[1].lAlg = -257;
    s->cose.cCredentialParameters = 2; s->cose.pCredentialParameters = s->cp;
    s->cd.dwVersion = 1; s->cd.pbClientDataJSON = s->json; s->cd.pwszHashAlgId = L"SHA-256";
    *(DWORD *)s->opt = 1;
}
/* Mirror of the encoder's request validation; nonzero means "the request would be accepted". */
static int mcs_accepted(const mcs *s) {
    if (!s->rp.dwVersion || !s->rp.pwszId) return 0;
    if (s->userNull || !s->user.cbId || !s->user.pbId) return 0;
    if (!s->cose.cCredentialParameters || !s->cose.pCredentialParameters) return 0;
    if (s->cdNull || !s->cd.dwVersion || !s->cd.cbClientDataJSON || !s->cd.pbClientDataJSON || !s->cd.pwszHashAlgId) return 0;
    if (s->useOpt && *(const DWORD *)s->opt == 0) return 0;
    return 1;
}
static CDHR mcs_call(mcs *s, ULONG flags, const GUID *g, WCHAR *pa, WCHAR *pb, void **att, DWORD *o1, DWORD *o2, int *called) {
    *called = 0;
    if (!pa || !pb) {   /* PIN-less path: refuse anything the encoder would accept */
        if (mcs_accepted(s)) { CHECK(!"fixture error: request would be accepted; not calling"); return 0xDEADDEAD; }
    }
    if ((!pa) != (!pb)) { CHECK(!"fixture error: single PIN would select a device; not calling"); return 0xDEADDEAD; }
    *called = 1;
    return UN(WebAuthNCtapMakeCredential)(NULL, flags, &s->rp, s->userNull ? NULL : &s->user, &s->cose, s->cdNull ? NULL : &s->cd,
                                          s->useOpt ? s->opt : NULL, att, g, pa, pb, o1, o2);
}

typedef void (*mcs_mut)(mcs *);
#define MUT(n, body) static void mut_##n(mcs *s) { body; }
MUT(rp_version0,        s->rp.dwVersion = 0)
MUT(rp_id_null,         s->rp.pwszId = NULL)
MUT(user_null,          s->userNull = 1)
MUT(user_cbid0,         s->user.cbId = 0)
MUT(user_pbid_null,     s->user.pbId = NULL)
MUT(cose_count0,        s->cose.cCredentialParameters = 0)
MUT(cose_count0_nullp,  s->cose.cCredentialParameters = 0; s->cose.pCredentialParameters = NULL)
MUT(cd_null,            s->cdNull = 1)
MUT(cd_version0,        s->cd.dwVersion = 0)
MUT(cd_cb0,             s->cd.cbClientDataJSON = 0)
MUT(cd_pb_null,         s->cd.pbClientDataJSON = NULL)
MUT(cd_hashalg_null,    s->cd.pwszHashAlgId = NULL)
MUT(opt_version0,       s->useOpt = 1; *(DWORD *)s->opt = 0)
MUT(rp_user_cd_all_bad, s->rp.pwszId = NULL; s->user.cbId = 0; s->cd.cbClientDataJSON = 0)
MUT(everything_zeroed,  memset(&s->rp, 0, sizeof s->rp); memset(&s->user, 0, sizeof s->user); memset(&s->cd, 0, sizeof s->cd); s->cose.cCredentialParameters = 0)
static const struct { const char *n; mcs_mut f; } k_mut[] = {
#define E(n) { #n, mut_##n }
    E(rp_version0), E(rp_id_null), E(user_null), E(user_cbid0), E(user_pbid_null), E(cose_count0), E(cose_count0_nullp),
    E(cd_null), E(cd_version0), E(cd_cb0), E(cd_pb_null), E(cd_hashalg_null), E(opt_version0), E(rp_user_cd_all_bad), E(everything_zeroed),
#undef E
};
#define NMUT (sizeof k_mut / sizeof k_mut[0])

TEST(ctapdev_mc_each_invalid_field_rejected) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        void *att = (void *)(ULONG_PTR)1; DWORD o1 = 0xCCCCCCCCu, o2 = 0xCCCCCCCCu; int called;
        CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, &o1, &o2, &called);
        if (!called) continue;
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "%s r=0x%lx", k_mut[i].n, (unsigned long)r);
    }
}
TEST(ctapdev_mc_attestation_output_cleared) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        void *att = (void *)(ULONG_PTR)0x1234; int called;
        mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
        if (called) CHECKF(att == NULL, "%s", k_mut[i].n);
    }
}
TEST(ctapdev_mc_optional_counters_zeroed) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        void *att = NULL; DWORD o1 = 0xAAAAAAAA, o2 = 0x55555555; int called;
        mcs_call(&s, 0, NULL, NULL, NULL, &att, &o1, &o2, &called);
        if (called) CHECKF(o1 == 0 && o2 == 0, "%s o1=0x%lx o2=0x%lx", k_mut[i].n, (unsigned long)o1, (unsigned long)o2);
    }
}
TEST(ctapdev_mc_optional_counters_may_be_null) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        void *att = NULL; int called;
        CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
        if (called) CHECKF(r == CD_NTE_INVALID_PARAMETER, "%s", k_mut[i].n);
    }
}
TEST(ctapdev_mc_one_counter_only) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    mcs s; mcs_init(&s); mut_cd_cb0(&s); void *att; DWORD o = 0x77777777; int called;
    CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, &o, NULL, &called);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); EXPECT_EQ(o, 0);
    o = 0x77777777;
    r = mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, &o, &called);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); EXPECT_EQ(o, 0);
}
TEST(ctapdev_mc_input_structures_not_modified) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        mcs before = s; void *att; int called;
        mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
        if (called) CHECKF(!memcmp(&before, &s, sizeof s), "%s", k_mut[i].n);
    }
}
TEST(ctapdev_mc_flags_do_not_change_validation) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    static const ULONG fl[] = { 0, 1, 2, 4, 0x100000, 0x400000, 0x800000, 0x2000000, 0x4000000, 0x80000000, 0xFFFFFFFF };
    for (size_t f = 0; f < sizeof fl / sizeof fl[0]; f++) {
        mcs s; mcs_init(&s); mut_user_cbid0(&s); void *att; int called;
        CDHR r = mcs_call(&s, fl[f], NULL, NULL, NULL, &att, NULL, NULL, &called);
        if (called) CHECKF(r == CD_NTE_INVALID_PARAMETER, "flags=0x%lx r=0x%lx", (unsigned long)fl[f], (unsigned long)r);
    }
}
TEST(ctapdev_mc_transaction_id_forms) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    GUID g = { 0xAABBCCDD, 1, 2, { 3, 4, 5, 6, 7, 8, 9, 10 } }, z; memset(&z, 0, sizeof z); GUID copy = g;
    const GUID *forms[] = { NULL, &g, &z };
    for (int i = 0; i < 3; i++) {
        mcs s; mcs_init(&s); mut_rp_id_null(&s); void *att; int called;
        CDHR r = mcs_call(&s, 0, forms[i], NULL, NULL, &att, NULL, NULL, &called);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "form %d", i);
    }
    CHECK(!memcmp(&g, &copy, sizeof g));
}
TEST(ctapdev_mc_window_handle_not_validated) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    static const ULONG_PTR hw[] = { 0, 1, 0xDEADBEEF };
    for (size_t i = 0; i < 3; i++) {
        mcs s; mcs_init(&s); mut_cd_pb_null(&s); void *att = NULL;
        if (mcs_accepted(&s)) continue;
        CDHR r = UN(WebAuthNCtapMakeCredential)((HWND)hw[i], 0, &s.rp, &s.user, &s.cose, &s.cd, NULL, &att, NULL, NULL, NULL, NULL, NULL);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "hwnd=%p", (void *)hw[i]);
    }
}
TEST(ctapdev_mc_options_version_zero_with_other_fields_set) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    mcs s; mcs_init(&s); s.useOpt = 1; memset(s.opt, 0xFF, sizeof s.opt); *(DWORD *)s.opt = 0;   /* dwVersion 0, rest arbitrary */
    void *att; int called;
    CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
    CHECK(called); EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
}
TEST(ctapdev_mc_cose_count_zero_array_valid) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    mcs s; mcs_init(&s); s.cose.cCredentialParameters = 0; void *att; int called;
    CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
    CHECK(called); EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
}
TEST(ctapdev_mc_repeatable) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (int i = 0; i < 200; i++) {
        mcs s; mcs_init(&s); mut_user_pbid_null(&s); void *att; int called;
        CDHR r = mcs_call(&s, 0, NULL, NULL, NULL, &att, NULL, NULL, &called);
        if (r != CD_NTE_INVALID_PARAMETER) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); break; }
    }
}

/* ---- two PINs: rejected before the request is even looked at ---- */
static CDHR mc_pins(WCHAR *a, WCHAR *b, void **att, DWORD *o1, DWORD *o2) {
    mcs s; mcs_init(&s);    /* completely valid arguments: the two-PIN check precedes everything */
    return UN(WebAuthNCtapMakeCredential)(NULL, 0, &s.rp, &s.user, &s.cose, &s.cd, NULL, att, NULL, a, b, o1, o2);
}
TEST(ctapdev_mc_two_pins_rejected_with_valid_request) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    WCHAR a[16], b[16]; cd_pin_fill(a, 16, 6, L'1'); cd_pin_fill(b, 16, 8, L'2'); void *att = (void *)(ULONG_PTR)1; DWORD o1 = 9, o2 = 9;
    CDHR r = mc_pins(a, b, &att, &o1, &o2);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(a, 6)); CHECK(cd_pin_tail_intact(a, 7, 16));
    CHECK(cd_pin_wiped(b, 8)); CHECK(cd_pin_tail_intact(b, 9, 16));
    CHECK(att == NULL); EXPECT_EQ(o1, 0); EXPECT_EQ(o2, 0);
}
TEST(ctapdev_mc_two_pins_length_table) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    static const size_t ns[] = { 0, 1, 3, 4, 63, 64, 65, 300, 2000 };
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++)
        for (size_t j = 0; j < sizeof ns / sizeof ns[0]; j += 3) {
            size_t na = ns[i], nb = ns[j]; WCHAR *a = (WCHAR *)LocalAlloc(LPTR, (na + 20) * 2), *b = (WCHAR *)LocalAlloc(LPTR, (nb + 20) * 2);
            cd_pin_fill(a, na + 20, na, L'a'); cd_pin_fill(b, nb + 20, nb, L'b'); void *att; DWORD o1, o2;
            CDHR r = mc_pins(a, b, &att, &o1, &o2);
            CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(a, na) && cd_pin_wiped(b, nb) && cd_pin_tail_intact(a, na + 1, na + 20) && cd_pin_tail_intact(b, nb + 1, nb + 20),
                   "na=%zu nb=%zu r=0x%lx", na, nb, (unsigned long)r);
            LocalFree(a); LocalFree(b);
        }
}
TEST(ctapdev_mc_two_pins_embedded_nul) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    WCHAR a[12], b[12]; cd_pin_fill(a, 12, 0, 0); cd_pin_fill(b, 12, 0, 0);
    a[0] = L'x'; a[1] = 0; a[2] = L'y'; a[3] = 0; b[0] = L'p'; b[1] = L'q'; b[2] = 0; b[3] = L'r'; b[4] = 0;
    void *att; DWORD o1, o2;
    CDHR r = mc_pins(a, b, &att, &o1, &o2);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(a[0] == 0 && a[2] == L'y'); CHECK(b[0] == 0 && b[1] == 0 && b[3] == L'r');
}
TEST(ctapdev_mc_two_pins_same_buffer) {
    /* The same buffer for both PINs is wiped once (second wipe sees an empty string). */
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    WCHAR a[12]; cd_pin_fill(a, 12, 5, L'k'); void *att; DWORD o1, o2;
    CDHR r = mc_pins(a, a, &att, &o1, &o2);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(a, 5));
}
TEST(ctapdev_mc_two_pins_with_invalid_request_same_code) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    for (size_t i = 0; i < NMUT; i++) {
        mcs s; mcs_init(&s); k_mut[i].f(&s);
        WCHAR a[8], b[8]; cd_pin_fill(a, 8, 4, L'1'); cd_pin_fill(b, 8, 4, L'2'); void *att; int called;
        CDHR r = mcs_call(&s, 0, NULL, a, b, &att, NULL, NULL, &called);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(a, 4) && cd_pin_wiped(b, 4), "%s", k_mut[i].n);
    }
}
TEST(ctapdev_mc_two_pins_counters_optional) {
    REQUIRE(UN(WebAuthNCtapMakeCredential));
    WCHAR a[8], b[8]; cd_pin_fill(a, 8, 4, L'1'); cd_pin_fill(b, 8, 4, L'2'); void *att;
    CDHR r = mc_pins(a, b, &att, NULL, NULL);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
}
