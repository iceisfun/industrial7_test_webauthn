/* bcrypt.dll context/provider configuration exports: argument validation order and status mapping,
 * provider registration and resolution queries (read only), change-notification events.
 * Only calls that fail in the user-mode argument validation (before the configuration driver is
 * reached) or that merely read configuration are made here; mutating calls live in dx_gap_01. */
#include "gap1.h"

#define SENT_PB ((PUCHAR)(ULONG_PTR)0x1)

/* ---- BCryptQueryContextFunctionProperty ---------------------------------------------------- */
static NTSTATUS qcfp(ULONG tab, LPCWSTR ctx, ULONG ifc, LPCWSTR fn, LPCWSTR prop, ULONG *pcb, PUCHAR *ppb) {
    return B(BCryptQueryContextFunctionProperty)(tab, ctx, ifc, fn, prop, pcb, ppb);
}

TEST(gap1_qcfp_bad_table) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    static const ULONG tabs[] = { 0, 3, 4, 0x10, 0x100, 0x10000, 0x80000000, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof tabs / sizeof *tabs; i++) {
        ULONG cb = 0x1234; PUCHAR pb = SENT_PB;
        NTSTATUS st = qcfp(tabs[i], L"Default", BCRYPT_RNG_INTERFACE, L"RNG", L"Prop", &cb, &pb);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "table 0x%lx st=0x%08lx", (unsigned long)tabs[i], (unsigned long)st);
        EXPECT_EQ(cb, 0x1234);
        EXPECT_EQ(pb, SENT_PB);
    }
}

TEST(gap1_qcfp_bad_interface) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    /* interface 0 (all) is not accepted by this export; 1..7 and 0x10001..0x10004 are the valid ids. */
    static const ULONG ifs[] = { 0, 8, 9, 0x10, 0xFF, 0x10000, 0x10005, 0x20001, 0x80000000, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        ULONG cb = 0; PUCHAR pb = SENT_PB;
        NTSTATUS st = qcfp(CRYPT_LOCAL, L"Default", ifs[i], L"RNG", L"Prop", &cb, &pb);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "iface 0x%lx st=0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
    }
}

TEST(gap1_qcfp_bad_function) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    ULONG cb = 0; PUCHAR pb = SENT_PB;
    EXPECT_EQ((DWORD)qcfp(CRYPT_LOCAL, L"Default", BCRYPT_RNG_INTERFACE, NULL, L"Prop", &cb, &pb), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)qcfp(CRYPT_LOCAL, L"Default", BCRYPT_RNG_INTERFACE, L"", L"Prop", &cb, &pb), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)qcfp(CRYPT_DOMAIN, L"Default", BCRYPT_RNG_INTERFACE, NULL, L"Prop", &cb, &pb), G_ST_INVALID_PARAMETER);
}

TEST(gap1_qcfp_bad_property) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    ULONG cb = 0; PUCHAR pb = SENT_PB;
    EXPECT_EQ((DWORD)qcfp(CRYPT_LOCAL, L"Default", BCRYPT_RNG_INTERFACE, L"RNG", NULL, &cb, &pb), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)qcfp(CRYPT_LOCAL, L"Default", BCRYPT_RNG_INTERFACE, L"RNG", L"", &cb, &pb), G_ST_INVALID_PARAMETER);
}

TEST(gap1_qcfp_null_pcb) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    PUCHAR pb = SENT_PB;
    EXPECT_EQ((DWORD)qcfp(CRYPT_LOCAL, L"Default", BCRYPT_RNG_INTERFACE, L"RNG", L"Prop", NULL, &pb), G_ST_INVALID_PARAMETER);
    EXPECT_EQ(pb, SENT_PB);
}

TEST(gap1_qcfp_valid_ids_pass_validation) {
    REQUIRE(B(BCryptQueryContextFunctionProperty));
    /* A nonexistent property must not be reported as a parameter error for any valid table/interface
     * pair: it passes the user-mode checks and fails (or not) in the configuration lookup. The exact
     * status of the lookup is recorded, not asserted. */
    static const ULONG ifs[] = { 1, 2, 3, 4, 5, 6, 7, 0x10001, 0x10002, 0x10003, 0x10004 };
    for (ULONG tab = 1; tab <= 2; tab++)
        for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
            ULONG cb = 0; PUCHAR pb = NULL;
            NTSTATUS st = qcfp(tab, L"gap1_no_such_context", ifs[i], L"gap1_no_such_function", L"gap1_no_such_property", &cb, &pb);
            CHECKF(G_NT_FAIL(st), "tab %lu iface 0x%lx unexpectedly succeeded", (unsigned long)tab, (unsigned long)ifs[i]);
            CHECK(pb == NULL);
            if (tab == 1 && i == 0) t_note("QueryContextFunctionProperty(nonexistent) -> 0x%08lx", (unsigned long)st);
            if (!G_NT_FAIL(st) && pb) B(BCryptFreeBuffer)(pb);
        }
}

/* ---- BCryptSetContextFunctionProperty / BCryptRemoveContextFunction (validation only) ------- */
TEST(gap1_scfp_bad_table) {
    REQUIRE(B(BCryptSetContextFunctionProperty));
    static const ULONG tabs[] = { 0, 3, 0x10, 0xFFFFFFFF };
    UCHAR v[2] = { 1, 0 };
    for (size_t i = 0; i < sizeof tabs / sizeof *tabs; i++) {
        NTSTATUS st = B(BCryptSetContextFunctionProperty)(tabs[i], L"gap1_ctx", BCRYPT_RNG_INTERFACE, L"gap1_fn", L"gap1_prop", sizeof v, v);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "table 0x%lx st=0x%08lx", (unsigned long)tabs[i], (unsigned long)st);
    }
}
TEST(gap1_scfp_bad_interface) {
    REQUIRE(B(BCryptSetContextFunctionProperty));
    static const ULONG ifs[] = { 0, 8, 0x10, 0x10000, 0x10005, 0xFFFFFFFF };
    UCHAR v[2] = { 1, 0 };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        NTSTATUS st = B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"gap1_ctx", ifs[i], L"gap1_fn", L"gap1_prop", sizeof v, v);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "iface 0x%lx st=0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
    }
}
TEST(gap1_scfp_bad_names) {
    REQUIRE(B(BCryptSetContextFunctionProperty));
    UCHAR v[2] = { 1, 0 };
    EXPECT_EQ((DWORD)B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, NULL, L"gap1_prop", 2, v), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, L"", L"gap1_prop", 2, v), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, L"gap1_fn", NULL, 2, v), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, L"gap1_fn", L"", 2, v), G_ST_INVALID_PARAMETER);
}

TEST(gap1_rcf_bad_args) {
    REQUIRE(B(BCryptRemoveContextFunction));
    static const ULONG tabs[] = { 0, 3, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof tabs / sizeof *tabs; i++)
        EXPECT_EQ((DWORD)B(BCryptRemoveContextFunction)(tabs[i], L"gap1_ctx", BCRYPT_RNG_INTERFACE, L"gap1_fn"), G_ST_INVALID_PARAMETER);
    static const ULONG ifs[] = { 0, 8, 0x10, 0x10000, 0x10005, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++)
        EXPECT_EQ((DWORD)B(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"gap1_ctx", ifs[i], L"gap1_fn"), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)B(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, NULL), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)B(BCryptRemoveContextFunction)(CRYPT_LOCAL, L"gap1_ctx", BCRYPT_RNG_INTERFACE, L""), G_ST_INVALID_PARAMETER);
}

/* ---- BCryptQueryProviderRegistration ------------------------------------------------------- */
static NTSTATUS qpr(LPCWSTR prov, ULONG mode, ULONG ifc, ULONG *pcb, PCRYPT_PROVIDER_REG *pp) {
    return B(BCryptQueryProviderRegistration)(prov, mode, ifc, pcb, pp);
}

TEST(gap1_qpr_null_empty_provider) {
    REQUIRE(B(BCryptQueryProviderRegistration));
    ULONG cb = 0x77; PCRYPT_PROVIDER_REG r = (PCRYPT_PROVIDER_REG)(ULONG_PTR)0x1;
    EXPECT_EQ((DWORD)qpr(NULL, CRYPT_UM, 0, &cb, &r), G_ST_INVALID_PARAMETER);
    EXPECT_EQ((DWORD)qpr(L"", CRYPT_UM, 0, &cb, &r), G_ST_INVALID_PARAMETER);
    EXPECT_EQ(cb, 0x77);
}

TEST(gap1_qpr_bad_mode) {
    REQUIRE(B(BCryptQueryProviderRegistration));
    /* valid modes here are CRYPT_UM(1), CRYPT_KM(2), CRYPT_MM(3), CRYPT_ANY(4); 0 and > 4 are rejected. */
    static const ULONG modes[] = { 0, 5, 6, 7, 0x10, 0x100, 0x80000000, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof modes / sizeof *modes; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
        NTSTATUS st = qpr(MS_PRIMITIVE_PROVIDER, modes[i], 0, &cb, &r);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "mode 0x%lx st=0x%08lx", (unsigned long)modes[i], (unsigned long)st);
        CHECK(r == NULL);
    }
}

TEST(gap1_qpr_bad_interface) {
    REQUIRE(B(BCryptQueryProviderRegistration));
    static const ULONG ifs[] = { 8, 9, 0x10, 0xFFFF, 0x10000, 0x10005, 0x20000, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
        NTSTATUS st = qpr(MS_PRIMITIVE_PROVIDER, CRYPT_UM, ifs[i], &cb, &r);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "iface 0x%lx st=0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
    }
}

TEST(gap1_qpr_null_pcb) {
    REQUIRE(B(BCryptQueryProviderRegistration));
    PCRYPT_PROVIDER_REG r = NULL;
    EXPECT_EQ((DWORD)qpr(MS_PRIMITIVE_PROVIDER, CRYPT_UM, 0, NULL, &r), G_ST_INVALID_PARAMETER);
    CHECK(r == NULL);
}

TEST(gap1_qpr_primitive_provider) {
    REQUIRE(B(BCryptQueryProviderRegistration)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    NTSTATUS st = qpr(MS_PRIMITIVE_PROVIDER, CRYPT_UM, 0, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st != 0) return;
    CHECK(r != NULL);
    CHECK(cb >= sizeof(CRYPT_PROVIDER_REG));
    if (r) {
        CHECK(r->pUM != NULL);
        if (r->pUM) {
            CHECK(r->pUM->pszImage != NULL && r->pUM->pszImage[0] != 0);
            CHECK(r->pUM->cInterfaces >= 1);
            if (r->pUM->pszImage) t_note("primitive provider UM image: %ls", r->pUM->pszImage);
        }
        t_note("primitive provider aliases: %lu, KM image: %s", (unsigned long)r->cAliases, r->pKM ? "present" : "none");
        B(BCryptFreeBuffer)(r);
    }
}

TEST(gap1_qpr_primitive_each_interface) {
    REQUIRE(B(BCryptQueryProviderRegistration)); REQUIRE(B(BCryptFreeBuffer));
    /* The primitive provider registers cipher, hash, asymmetric, secret agreement, signature, rng and
     * key-derivation functions; querying with one of those interface ids must not be a parameter error. */
    static const ULONG ifs[] = { 1, 2, 3, 4, 5, 6, 7 };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
        NTSTATUS st = qpr(MS_PRIMITIVE_PROVIDER, CRYPT_UM, ifs[i], &cb, &r);
        CHECKF((DWORD)st != G_ST_INVALID_PARAMETER, "iface %lu -> 0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
        if (st == 0 && r) B(BCryptFreeBuffer)(r);
        else t_note("QueryProviderRegistration(primitive, iface %lu) -> 0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
    }
}

TEST(gap1_qpr_ksp_storage_interface) {
    REQUIRE(B(BCryptQueryProviderRegistration)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    NTSTATUS st = qpr(MS_KEY_STORAGE_PROVIDER, CRYPT_UM, 0x10001, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st == 0 && r) {
        CHECK(r->pUM != NULL);
        if (r->pUM && r->pUM->pszImage) t_note("software KSP UM image: %ls", r->pUM->pszImage);
        B(BCryptFreeBuffer)(r);
    }
}

TEST(gap1_qpr_unknown_provider) {
    REQUIRE(B(BCryptQueryProviderRegistration));
    ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
    NTSTATUS st = qpr(L"gap1 No Such Provider", CRYPT_UM, 0, &cb, &r);
    CHECKF(G_NT_FAIL(st), "st=0x%08lx", (unsigned long)st);
    CHECK(r == NULL);
    t_note("QueryProviderRegistration(unknown) -> 0x%08lx", (unsigned long)st);
}

TEST(gap1_qpr_modes_valid) {
    REQUIRE(B(BCryptQueryProviderRegistration)); REQUIRE(B(BCryptFreeBuffer));
    for (ULONG m = 1; m <= 4; m++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REG r = NULL;
        NTSTATUS st = qpr(MS_PRIMITIVE_PROVIDER, m, 0, &cb, &r);
        CHECKF((DWORD)st != G_ST_INVALID_PARAMETER, "mode %lu -> 0x%08lx", (unsigned long)m, (unsigned long)st);
        t_note("QueryProviderRegistration(primitive, mode %lu) -> 0x%08lx", (unsigned long)m, (unsigned long)st);
        if (st == 0 && r) B(BCryptFreeBuffer)(r);
    }
}

/* ---- BCryptResolveProviders ---------------------------------------------------------------- */
static NTSTATUS rp(LPCWSTR ctx, ULONG ifc, LPCWSTR fn, LPCWSTR prov, ULONG mode, ULONG fl, ULONG *pcb, PCRYPT_PROVIDER_REFS *pp) {
    return B(BCryptResolveProviders)(ctx, ifc, fn, prov, mode, fl, pcb, pp);
}

TEST(gap1_rp_bad_interface) {
    REQUIRE(B(BCryptResolveProviders));
    static const ULONG ifs[] = { 8, 0x10, 0xFFFF, 0x10000, 0x10005, 0x20001, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof ifs / sizeof *ifs; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
        NTSTATUS st = rp(NULL, ifs[i], NULL, NULL, CRYPT_UM, 0, &cb, &r);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "iface 0x%lx st=0x%08lx", (unsigned long)ifs[i], (unsigned long)st);
        CHECK(r == NULL);
    }
}

TEST(gap1_rp_bad_mode) {
    REQUIRE(B(BCryptResolveProviders));
    /* this export accepts CRYPT_UM(1), CRYPT_KM(2) and CRYPT_MM(3) only; 0 and CRYPT_ANY(4) are rejected. */
    static const ULONG modes[] = { 0, 4, 5, 6, 0x10, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof modes / sizeof *modes; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
        NTSTATUS st = rp(NULL, BCRYPT_RNG_INTERFACE, NULL, NULL, modes[i], 0, &cb, &r);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "mode 0x%lx st=0x%08lx", (unsigned long)modes[i], (unsigned long)st);
        CHECK(r == NULL);
    }
}

TEST(gap1_rp_null_pcb) {
    REQUIRE(B(BCryptResolveProviders));
    PCRYPT_PROVIDER_REFS r = NULL;
    EXPECT_EQ((DWORD)rp(NULL, BCRYPT_RNG_INTERFACE, NULL, NULL, CRYPT_UM, 0, NULL, &r), G_ST_INVALID_PARAMETER);
    CHECK(r == NULL);
}

TEST(gap1_rp_bad_flags) {
    REQUIRE(B(BCryptResolveProviders));
    /* only CRYPT_ALL_FUNCTIONS(1) and CRYPT_ALL_PROVIDERS(2) are defined; any other bit is a parameter error. */
    static const ULONG fl[] = { 4, 8, 0x10, 0x100, 0x80000000, 0xFFFFFFFC, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
        NTSTATUS st = rp(NULL, BCRYPT_RNG_INTERFACE, NULL, NULL, CRYPT_UM, fl[i], &cb, &r);
        CHECKF((DWORD)st == G_ST_INVALID_PARAMETER, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        CHECK(r == NULL);
    }
}

static void check_refs(const PCRYPT_PROVIDER_REFS r) {
    CHECK(r->cProviders >= 1);
    for (ULONG i = 0; i < r->cProviders && i < 64; i++) {
        PCRYPT_PROVIDER_REF p = r->rgpProviders[i];
        CHECK(p != NULL);
        if (!p) continue;
        CHECK(p->pszProvider != NULL && p->pszProvider[0] != 0);
        if (p->pszProvider) t_note("resolved[%lu]: %ls", (unsigned long)i, p->pszProvider);
    }
}

TEST(gap1_rp_default_rng_user_mode) {
    REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = rp(L"Default", BCRYPT_RNG_INTERFACE, NULL, NULL, CRYPT_UM, 0, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st != 0) return;
    CHECK(r != NULL);
    CHECK(cb > 0);
    if (r) { check_refs(r); B(BCryptFreeBuffer)(r); }
}

TEST(gap1_rp_all_providers_flag) {
    REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = rp(L"Default", BCRYPT_RNG_INTERFACE, NULL, NULL, CRYPT_UM, 2 /* CRYPT_ALL_PROVIDERS */, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st == 0 && r) { check_refs(r); B(BCryptFreeBuffer)(r); }
}

TEST(gap1_rp_all_functions_flag) {
    REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = rp(L"Default", BCRYPT_RNG_INTERFACE, NULL, NULL, CRYPT_UM, 1 /* CRYPT_ALL_FUNCTIONS */, &cb, &r);
    CHECKF((DWORD)st != G_ST_INVALID_PARAMETER, "st=0x%08lx", (unsigned long)st);
    t_note("ResolveProviders(Default, RNG, ALL_FUNCTIONS) -> 0x%08lx", (unsigned long)st);
    if (st == 0 && r) B(BCryptFreeBuffer)(r);
}

TEST(gap1_rp_storage_provider_list_nonempty) {
    REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    /* the exact arguments NCryptEnumStorageProviders issues */
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = rp(NULL, 0x10001, L"KEY_STORAGE", NULL, CRYPT_UM, 2, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st == 0 && r) {
        CHECK(r->cProviders >= 1);
        int found = 0;
        for (ULONG i = 0; i < r->cProviders; i++)
            if (r->rgpProviders[i]->pszProvider && !lstrcmpW(r->rgpProviders[i]->pszProvider, MS_KEY_STORAGE_PROVIDER)) found = 1;
        CHECK(found);
        B(BCryptFreeBuffer)(r);
    }
}

TEST(gap1_rp_unknown_provider_name) {
    REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = rp(L"Default", BCRYPT_RNG_INTERFACE, NULL, L"gap1 No Such Provider", CRYPT_UM, 0, &cb, &r);
    t_note("ResolveProviders(unknown provider) -> 0x%08lx", (unsigned long)st);
    CHECKF((DWORD)st != G_ST_INVALID_PARAMETER, "valid arguments rejected as parameter error");
    if (st == 0 && r) B(BCryptFreeBuffer)(r);
}

/* ---- BCryptRegisterConfigChangeNotify / BCryptUnregisterConfigChangeNotify ------------------ */
TEST(gap1_notify_register_null) {
    REQUIRE(B(BCryptRegisterConfigChangeNotify));
    EXPECT_EQ((DWORD)B(BCryptRegisterConfigChangeNotify)(NULL), G_ST_INVALID_PARAMETER);
}

TEST(gap1_notify_unregister_null) {
    REQUIRE(B(BCryptUnregisterConfigChangeNotify));
    EXPECT_EQ((DWORD)B(BCryptUnregisterConfigChangeNotify)(NULL), G_ST_INVALID_PARAMETER);
}

TEST(gap1_notify_register_unregister) {
    REQUIRE(B(BCryptRegisterConfigChangeNotify)); REQUIRE(B(BCryptUnregisterConfigChangeNotify));
    HANDLE h = (HANDLE)(ULONG_PTR)0x1;
    NTSTATUS st = B(BCryptRegisterConfigChangeNotify)(&h);
    if (st != 0) { CHECK(h == NULL); t_note("RegisterConfigChangeNotify -> 0x%08lx", (unsigned long)st); return; }
    CHECK(h != NULL && h != (HANDLE)(ULONG_PTR)0x1);
    if (!h || h == (HANDLE)(ULONG_PTR)0x1) return;
    /* the API creates an auto-reset, initially non-signalled event */
    EXPECT_EQ(WaitForSingleObject(h, 0), WAIT_TIMEOUT);
    DWORD hf = 0;
    CHECK(GetHandleInformation(h, &hf));
    EXPECT_EQ((DWORD)B(BCryptUnregisterConfigChangeNotify)(h), 0);
    /* a successful unregister closes the event handle */
    SET_ERR(0);
    CHECK(!GetHandleInformation(h, &hf));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(gap1_notify_register_distinct_handles) {
    REQUIRE(B(BCryptRegisterConfigChangeNotify)); REQUIRE(B(BCryptUnregisterConfigChangeNotify));
    HANDLE a = NULL, b = NULL;
    if (B(BCryptRegisterConfigChangeNotify)(&a) != 0) { t_skip("register unavailable"); return; }
    if (B(BCryptRegisterConfigChangeNotify)(&b) != 0) { B(BCryptUnregisterConfigChangeNotify)(a); t_skip("second register unavailable"); return; }
    CHECK(a != NULL && b != NULL && a != b);
    EXPECT_EQ((DWORD)B(BCryptUnregisterConfigChangeNotify)(a), 0);
    EXPECT_EQ((DWORD)B(BCryptUnregisterConfigChangeNotify)(b), 0);
}

TEST(gap1_notify_unregister_unregistered_event) {
    REQUIRE(B(BCryptUnregisterConfigChangeNotify));
    HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(h != NULL);
    if (!h) return;
    NTSTATUS st = B(BCryptUnregisterConfigChangeNotify)(h);
    t_note("UnregisterConfigChangeNotify(never registered) -> 0x%08lx", (unsigned long)st);
    DWORD hf;
    if (G_NT_FAIL(st)) {
        /* on failure the handle is left open; the caller still owns it */
        CHECK(GetHandleInformation(h, &hf));
        CloseHandle(h);
    } else {
        SET_ERR(0);
        if (GetHandleInformation(h, &hf)) CloseHandle(h);
    }
}
