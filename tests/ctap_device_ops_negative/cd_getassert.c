#include "cd.h"
/* WebAuthNCtapGetAssertion(hwnd, flags, rpId, clientData, options, ppAssertion, transactionId, pin, pcbHmac, pbHmac,
 *                          ppSelectedDevice, p12, p13)
 *
 * Reference behaviour relied on:
 *  - *ppAssertion = NULL is written first (required). If pcbHmac is non-NULL its value is read and then reset to 0;
 *    only the value 0 is used here (a non-zero length sends the call down the HMAC-secret branch).
 *  - ppSelectedDevice (optional): the record is read and the slot cleared; the record is released on return.
 *  - pin == NULL and *pcbHmac == 0: with no device record the request is encoded and rejected with 0x80090027 when
 *    rpId == NULL, clientData == NULL, clientData->dwVersion == 0, ->pbClientDataJSON == NULL, ->cbClientDataJSON == 0,
 *    ->pwszHashAlgId == NULL, or options != NULL && options->dwVersion == 0. Everything else is sent to the service,
 *    so every such call carries at least one defect (checked by a mirror before calling).
 *  - With a device record that is not complete (see cd.h) the call returns 0x80090027 before encoding, whatever the
 *    other arguments hold.
 *  - pin != NULL: the PIN is protected and the caller's buffer wiped; without a complete device record the result is
 *    0x80090027, whatever the other arguments hold.
 */

typedef struct {
    WCHAR rpId[32]; CD_CLIENT_DATA cd; BYTE json[48]; BYTE opt[0x100];
    int rpNull, cdNull, useOpt;
} gas;

static void gas_init(gas *s) {
    memset(s, 0, sizeof *s);
    lstrcpyW(s->rpId, L"example.com");
    static const char j[] = "{\"type\":\"webauthn.get\",\"challenge\":\"AAAA\"}";
    memcpy(s->json, j, sizeof j - 1);
    s->cd.dwVersion = 1; s->cd.cbClientDataJSON = sizeof j - 1; s->cd.pbClientDataJSON = s->json; s->cd.pwszHashAlgId = L"SHA-256";
    *(DWORD *)s->opt = 1;
}
static int gas_accepted(const gas *s) {
    if (s->rpNull || s->cdNull || !s->cd.dwVersion || !s->cd.pbClientDataJSON || !s->cd.cbClientDataJSON || !s->cd.pwszHashAlgId) return 0;
    if (s->useOpt && *(const DWORD *)s->opt == 0) return 0;
    return 1;
}
/* guard: if every PIN/device condition leads to the encoder, the request must be defective */
static CDHR gas_call(gas *s, ULONG flags, const GUID *g, WCHAR *pin, DWORD *pcb, void **pdev, void **pasr, int *called) {
    *called = 0;
    int deviceRejects = pdev && *pdev && !cd_dev_complete(*pdev);
    if (!pin && !deviceRejects && gas_accepted(s)) { CHECK(!"fixture error: request would be accepted; not calling"); return 0xDEADDEAD; }
    if (pdev && *pdev && cd_dev_complete(*pdev)) { CHECK(!"fixture error: complete device record; not calling"); return 0xDEADDEAD; }
    *called = 1;
    return UN(WebAuthNCtapGetAssertion)(NULL, flags, s->rpNull ? NULL : s->rpId, s->cdNull ? NULL : &s->cd, s->useOpt ? s->opt : NULL,
                                        pasr, g, pin, pcb, NULL, pdev, 0, NULL);
}

typedef void (*gas_mut)(gas *);
#define MUT(n, body) static void mut_##n(gas *s) { body; }
MUT(rp_null,        s->rpNull = 1)
MUT(cd_null,        s->cdNull = 1)
MUT(cd_version0,    s->cd.dwVersion = 0)
MUT(cd_pb_null,     s->cd.pbClientDataJSON = NULL)
MUT(cd_cb0,         s->cd.cbClientDataJSON = 0)
MUT(cd_hashalg_null,s->cd.pwszHashAlgId = NULL)
MUT(opt_version0,   s->useOpt = 1; *(DWORD *)s->opt = 0)
MUT(opt_version0_noise, s->useOpt = 1; memset(s->opt, 0xEE, sizeof s->opt); *(DWORD *)s->opt = 0)
MUT(all_bad,        s->rpNull = 1; s->cd.dwVersion = 0; s->cd.cbClientDataJSON = 0)
MUT(cd_zeroed,      memset(&s->cd, 0, sizeof s->cd))
static const struct { const char *n; gas_mut f; } k_mut[] = {
#define E(n) { #n, mut_##n }
    E(rp_null), E(cd_null), E(cd_version0), E(cd_pb_null), E(cd_cb0), E(cd_hashalg_null), E(opt_version0), E(opt_version0_noise), E(all_bad), E(cd_zeroed),
#undef E
};
#define NMUT (sizeof k_mut / sizeof k_mut[0])

TEST(ctapdev_ga_each_invalid_field_rejected) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        gas s; gas_init(&s); k_mut[i].f(&s); void *asr = (void *)(ULONG_PTR)1; int called;
        CDHR r = gas_call(&s, 0, NULL, NULL, NULL, NULL, &asr, &called);
        if (called) CHECKF(r == CD_NTE_INVALID_PARAMETER, "%s r=0x%lx", k_mut[i].n, (unsigned long)r);
    }
}
TEST(ctapdev_ga_assertion_output_cleared) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        gas s; gas_init(&s); k_mut[i].f(&s); void *asr = (void *)(ULONG_PTR)0x1234; int called;
        gas_call(&s, 0, NULL, NULL, NULL, NULL, &asr, &called);
        if (called) CHECKF(asr == NULL, "%s", k_mut[i].n);
    }
}
TEST(ctapdev_ga_hmac_length_zero_stays_zero) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        gas s; gas_init(&s); k_mut[i].f(&s); void *asr = NULL; DWORD cb = 0; int called;
        CDHR r = gas_call(&s, 0, NULL, NULL, &cb, NULL, &asr, &called);
        if (called) CHECKF(r == CD_NTE_INVALID_PARAMETER && cb == 0, "%s", k_mut[i].n);
    }
}
TEST(ctapdev_ga_input_structures_not_modified) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        gas s; gas_init(&s); k_mut[i].f(&s); gas before = s; void *asr; int called;
        gas_call(&s, 0, NULL, NULL, NULL, NULL, &asr, &called);
        if (called) CHECKF(!memcmp(&before, &s, sizeof s), "%s", k_mut[i].n);
    }
}
TEST(ctapdev_ga_flags_do_not_change_validation) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    static const ULONG fl[] = { 0, 1, 2, 4, 0x100000, 0x400000, 0x800000, 0x1000000, 0x10000000, 0x2000000, 0x80000000, 0xFFFFFFFF };
    for (size_t f = 0; f < sizeof fl / sizeof fl[0]; f++) {
        gas s; gas_init(&s); mut_cd_cb0(&s); void *asr; int called;
        CDHR r = gas_call(&s, fl[f], NULL, NULL, NULL, NULL, &asr, &called);
        if (called) CHECKF(r == CD_NTE_INVALID_PARAMETER, "flags=0x%lx", (unsigned long)fl[f]);
    }
}
TEST(ctapdev_ga_transaction_id_forms) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    GUID g = { 0xAABBCCDD, 1, 2, { 3, 4, 5, 6, 7, 8, 9, 10 } }, z; memset(&z, 0, sizeof z); GUID copy = g;
    const GUID *forms[] = { NULL, &g, &z };
    for (int i = 0; i < 3; i++) {
        gas s; gas_init(&s); mut_rp_null(&s); void *asr; int called;
        CDHR r = gas_call(&s, 0, forms[i], NULL, NULL, NULL, &asr, &called);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "form %d", i);
    }
    CHECK(!memcmp(&g, &copy, sizeof g));
}
TEST(ctapdev_ga_empty_rpid_is_not_an_early_failure_note) {
    /* An empty (not NULL) rpId passes the NULL check; it is deliberately not called (it would be sent). Resolve-only. */
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    t_note("GetAssertion rpId \"\" is accepted by the request encoder (only NULL is rejected); not exercised");
}
TEST(ctapdev_ga_window_handle_not_validated) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    static const ULONG_PTR hw[] = { 0, 1, 0xDEADBEEF };
    for (size_t i = 0; i < 3; i++) {
        gas s; gas_init(&s); mut_cd_pb_null(&s); void *asr = NULL;
        if (gas_accepted(&s)) continue;
        CDHR r = UN(WebAuthNCtapGetAssertion)((HWND)hw[i], 0, s.rpId, &s.cd, NULL, &asr, NULL, NULL, NULL, NULL, NULL, 0, NULL);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "hwnd=%p", (void *)hw[i]);
    }
}
TEST(ctapdev_ga_repeatable) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (int i = 0; i < 200; i++) {
        gas s; gas_init(&s); mut_rp_null(&s); void *asr; int called;
        CDHR r = gas_call(&s, 0, NULL, NULL, NULL, NULL, &asr, &called);
        if (r != CD_NTE_INVALID_PARAMETER) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); break; }
    }
}

/* ---- incomplete device record: rejected before encoding, even with a fully valid request ---- */
static const struct { const char *tag; DWORD kind; int p20, p28; } k_devs[] = {
    { "all zero", 0, 0, 0 }, { "kind only", 1, 0, 0 }, { "kind+p20", 1, 1, 0 }, { "kind+p28", 1, 0, 1 },
    { "p20+p28 no kind", 0, 1, 1 }, { "p20 only", 0, 1, 0 }, { "p28 only", 0, 0, 1 },
};
TEST(ctapdev_ga_incomplete_device_valid_request) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    BYTE dummy[16];
    for (size_t i = 0; i < sizeof k_devs / sizeof k_devs[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, k_devs[i].kind, k_devs[i].p20 ? dummy : NULL, k_devs[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); continue; }
        gas s; gas_init(&s); void *asr = (void *)(ULONG_PTR)1; int called;   /* request is fully valid on purpose */
        CDHR r = gas_call(&s, 0, NULL, NULL, NULL, &dev, &asr, &called);
        CHECKF(called && r == CD_NTE_INVALID_PARAMETER, "%s r=0x%lx", k_devs[i].tag, (unsigned long)r);
        CHECKF(dev == NULL && asr == NULL, "%s: slot and output cleared", k_devs[i].tag);
    }
}
TEST(ctapdev_ga_incomplete_device_with_invalid_request_same_code) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        void *dev = cd_dev_alloc(); gas s; gas_init(&s); k_mut[i].f(&s); void *asr; int called;
        CDHR r = gas_call(&s, 0, NULL, NULL, NULL, &dev, &asr, &called);
        CHECKF(called && r == CD_NTE_INVALID_PARAMETER && dev == NULL, "%s", k_mut[i].n);
    }
}
TEST(ctapdev_ga_empty_device_slot_behaves_like_no_slot) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    gas s; gas_init(&s); mut_cd_cb0(&s); void *dev = NULL, *asr; int called;
    CDHR r = gas_call(&s, 0, NULL, NULL, NULL, &dev, &asr, &called);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(dev == NULL);
}

/* ---- PIN ---- */
TEST(ctapdev_ga_pin_without_device_wiped_and_rejected_valid_request) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    gas s; gas_init(&s); WCHAR pin[16]; cd_pin_fill(pin, 16, 6, L'3'); void *asr = (void *)(ULONG_PTR)1; int called;
    CDHR r = gas_call(&s, 0, NULL, pin, NULL, NULL, &asr, &called);
    CHECK(called); EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(pin, 6)); CHECK(cd_pin_tail_intact(pin, 7, 16)); CHECK(asr == NULL);
}
TEST(ctapdev_ga_pin_length_table) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    static const size_t ns[] = { 0, 1, 3, 4, 63, 64, 65, 200, 1000, 4000 };
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        size_t n = ns[i], cap = n + 20; WCHAR *p = (WCHAR *)LocalAlloc(LPTR, cap * 2); gas s; gas_init(&s); void *asr; int called;
        cd_pin_fill(p, cap, n, L'6');
        CDHR r = gas_call(&s, 0, NULL, p, NULL, NULL, &asr, &called);
        CHECKF(called && r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(p, n) && cd_pin_tail_intact(p, n + 1, cap), "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(p);
    }
}
TEST(ctapdev_ga_pin_with_each_defect_same_code) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    for (size_t i = 0; i < NMUT; i++) {
        gas s; gas_init(&s); k_mut[i].f(&s); WCHAR pin[8]; cd_pin_fill(pin, 8, 4, L'1'); void *asr; int called;
        CDHR r = gas_call(&s, 0, NULL, pin, NULL, NULL, &asr, &called);
        CHECKF(called && r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(pin, 4), "%s", k_mut[i].n);
    }
}
TEST(ctapdev_ga_pin_embedded_nul) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    gas s; gas_init(&s); WCHAR p[12]; cd_pin_fill(p, 12, 0, 0); void *asr; int called;
    p[0] = L'1'; p[1] = L'2'; p[2] = 0; p[3] = L'3'; p[4] = 0;
    CDHR r = gas_call(&s, 0, NULL, p, NULL, NULL, &asr, &called);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(p[0] == 0 && p[1] == 0 && p[3] == L'3');
}
TEST(ctapdev_ga_pin_surrogates_not_validated) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    static const WCHAR pins[][4] = { { 0xD800, 0 }, { 0xDC00, 0xD800, 0 }, { 0xD83D, 0xDD11, 0 } };
    for (size_t i = 0; i < 3; i++) {
        gas s; gas_init(&s); WCHAR w[8]; cd_pin_fill(w, 8, 0, 0); size_t n = lstrlenW(pins[i]); memcpy(w, pins[i], (n + 1) * 2); void *asr; int called;
        CDHR r = gas_call(&s, 0, NULL, w, NULL, NULL, &asr, &called);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(w, n), "pin #%zu", i);
    }
}
TEST(ctapdev_ga_pin_with_incomplete_device) {
    REQUIRE(UN(WebAuthNCtapGetAssertion));
    BYTE dummy[16];
    for (size_t i = 0; i < sizeof k_devs / sizeof k_devs[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, k_devs[i].kind, k_devs[i].p20 ? dummy : NULL, k_devs[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); continue; }
        gas s; gas_init(&s); WCHAR pin[8]; cd_pin_fill(pin, 8, 4, L'7'); void *asr; int called;
        CDHR r = gas_call(&s, 0, NULL, pin, NULL, &dev, &asr, &called);
        CHECKF(called && r == CD_NTE_INVALID_PARAMETER && dev == NULL && cd_pin_wiped(pin, 4), "%s", k_devs[i].tag);
    }
}
