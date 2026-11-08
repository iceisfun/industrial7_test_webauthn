#include "gap0.h"

static int g0_has_alg(BCRYPT_ALGORITHM_IDENTIFIER *l, ULONG n, const wchar_t *name, ULONG cls) {
    for (ULONG i = 0; i < n; i++) if (!lstrcmpiW(l[i].pszName, name)) return cls == 0 || l[i].dwClass == cls;
    return 0;
}

/* ---- BCryptEnumAlgorithms ----------------------------------------------- */
TEST(gap0_enumalg_all_contains_basics) {
    REQUIRE(U(BCryptEnumAlgorithms)); REQUIRE(U(BCryptFreeBuffer));
    ULONG n = 0; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
    G0_OKST(U(BCryptEnumAlgorithms)(0, &n, &l, 0));
    CHECK(n >= 10 && l != NULL);
    CHECK(g0_has_alg(l, n, L"AES", 1)); CHECK(g0_has_alg(l, n, L"SHA256", 2)); CHECK(g0_has_alg(l, n, L"SHA1", 2));
    CHECK(g0_has_alg(l, n, L"RSA", 3)); CHECK(g0_has_alg(l, n, L"ECDH_P256", 4)); CHECK(g0_has_alg(l, n, L"ECDSA_P256", 5));
    CHECK(g0_has_alg(l, n, L"RNG", 6));
    for (ULONG i = 0; i < n; i++) { CHECK(l[i].pszName != NULL && l[i].pszName[0]); CHECK(l[i].dwClass >= 1 && l[i].dwClass <= 7); }
    U(BCryptFreeBuffer)(l);
}
TEST(gap0_enumalg_filter_by_operation) {
    REQUIRE(U(BCryptEnumAlgorithms)); REQUIRE(U(BCryptFreeBuffer));
    static const struct { ULONG op, cls; const wchar_t *must; } t[] = {
        { BCRYPT_CIPHER_OPERATION, 1, L"AES" }, { BCRYPT_HASH_OPERATION, 2, L"SHA256" },
        { BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, 3, L"RSA" }, { BCRYPT_SECRET_AGREEMENT_OPERATION, 4, L"ECDH_P256" },
        { BCRYPT_SIGNATURE_OPERATION, 5, L"ECDSA_P256" }, { BCRYPT_RNG_OPERATION, 6, L"RNG" },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        ULONG n = 0; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
        G0_OKST(U(BCryptEnumAlgorithms)(t[i].op, &n, &l, 0));
        CHECK(n > 0);
        CHECK(g0_has_alg(l, n, t[i].must, t[i].cls));
        for (ULONG k = 0; k < n; k++) CHECKF(l[k].dwClass == t[i].cls, "op 0x%lx returned class %lu (%ls)", (unsigned long)t[i].op, (unsigned long)l[k].dwClass, l[k].pszName);
        U(BCryptFreeBuffer)(l);
    }
}
TEST(gap0_enumalg_combined_ops_are_additive) {
    REQUIRE(U(BCryptEnumAlgorithms)); REQUIRE(U(BCryptFreeBuffer));
    ULONG n1 = 0, n2 = 0, n12 = 0, nall = 0; BCRYPT_ALGORITHM_IDENTIFIER *l;
    G0_OKST(U(BCryptEnumAlgorithms)(BCRYPT_CIPHER_OPERATION, &n1, &l, 0)); U(BCryptFreeBuffer)(l);
    G0_OKST(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, &n2, &l, 0)); U(BCryptFreeBuffer)(l);
    G0_OKST(U(BCryptEnumAlgorithms)(BCRYPT_CIPHER_OPERATION | BCRYPT_HASH_OPERATION, &n12, &l, 0)); U(BCryptFreeBuffer)(l);
    EXPECT_EQ(n12, n1 + n2);
    G0_OKST(U(BCryptEnumAlgorithms)(0, &nall, &l, 0)); U(BCryptFreeBuffer)(l);
    G0_OKST(U(BCryptEnumAlgorithms)(0x7f, &n12, &l, 0)); U(BCryptFreeBuffer)(l);
    EXPECT_EQ(nall, n12);                                    /* 0 and "all seven bits" are equivalent */
}
TEST(gap0_enumalg_invalid_arguments) {
    REQUIRE(U(BCryptEnumAlgorithms));
    ULONG n = 77; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
    ST(U(BCryptEnumAlgorithms)(0, NULL, &l, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumAlgorithms)(0, &n, NULL, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumAlgorithms)(0, &n, &l, 1), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumAlgorithms)(0x80, &n, &l, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumAlgorithms)(0xFFFFFFFF, &n, &l, 0), G0_INVALID_PARAMETER);
    EXPECT_EQ(n, 77); CHECK(l == NULL);
}
TEST(gap0_enumalg_names_resolve_to_providers) {
    REQUIRE(U(BCryptEnumAlgorithms)); REQUIRE(U(BCryptFreeBuffer)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    ULONG n = 0; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
    G0_OKST(U(BCryptEnumAlgorithms)(BCRYPT_HASH_OPERATION, &n, &l, 0));
    for (ULONG i = 0; i < n; i++) {
        BCRYPT_ALG_HANDLE a; NTSTATUS st = g0_open(&a, l[i].pszName, 0);
        CHECKF(st >= 0, "hash algorithm %ls enumerated but not openable: 0x%08lx", l[i].pszName, (unsigned long)st);
        if (st >= 0) g0_close(a);
    }
    U(BCryptFreeBuffer)(l);
}

/* ---- BCryptEnumProviders -------------------------------------------------- */
TEST(gap0_enumproviders_sha256) {
    REQUIRE(U(BCryptEnumProviders)); REQUIRE(U(BCryptFreeBuffer));
    ULONG n = 0; BCRYPT_PROVIDER_NAME *l = NULL;
    G0_OKST(U(BCryptEnumProviders)(L"SHA256", &n, &l, 0));
    CHECK(n >= 1 && l != NULL);
    for (ULONG i = 0; i < n; i++) { CHECK(l[i].pszProviderName && l[i].pszProviderName[0]); t_note("SHA256 provider %lu: %ls", (unsigned long)i, l[i].pszProviderName); }
    U(BCryptFreeBuffer)(l);
}
TEST(gap0_enumproviders_provider_names_are_openable) {
    REQUIRE(U(BCryptEnumProviders)); REQUIRE(U(BCryptFreeBuffer)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    static const wchar_t *ids[] = {L"AES", L"SHA1", L"RSA", L"ECDH_P256", L"RNG"};
    for (int k = 0; k < 5; k++) {
        ULONG n = 0; BCRYPT_PROVIDER_NAME *l = NULL;
        NTSTATUS st = U(BCryptEnumProviders)(ids[k], &n, &l, 0);
        G0_OKST(st); if (st < 0 || !l) continue;
        CHECK(n >= 1);
        for (ULONG i = 0; i < n; i++) {
            BCRYPT_ALG_HANDLE a = NULL; NTSTATUS os = U(BCryptOpenAlgorithmProvider)(&a, ids[k], l[i].pszProviderName, 0);
            t_note("%ls via %ls -> 0x%08lx", ids[k], l[i].pszProviderName, (unsigned long)os);
            if (a) g0_close(a);
        }
        U(BCryptFreeBuffer)(l);
    }
}
TEST(gap0_enumproviders_invalid_arguments) {
    REQUIRE(U(BCryptEnumProviders));
    ULONG n = 55; BCRYPT_PROVIDER_NAME *l = NULL;
    ST(U(BCryptEnumProviders)(NULL, &n, &l, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumProviders)(L"", &n, &l, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumProviders)(L"SHA256", NULL, &l, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumProviders)(L"SHA256", &n, NULL, 0), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumProviders)(L"SHA256", &n, &l, 1), G0_INVALID_PARAMETER);
    EXPECT_EQ(n, 55); CHECK(l == NULL);
}
TEST(gap0_enumproviders_unknown_algorithm_note) {
    REQUIRE(U(BCryptEnumProviders));
    ULONG n = 55; BCRYPT_PROVIDER_NAME *l = NULL;
    NTSTATUS st = U(BCryptEnumProviders)(L"NO_SUCH_ALGORITHM_ID", &n, &l, 0);
    t_note("EnumProviders(unknown) -> 0x%08lx count=%lu list=%p", (unsigned long)st, (unsigned long)n, (void *)l);
    if (st >= 0 && l) U(BCryptFreeBuffer)(l);
    if (st < 0) CHECK(l == NULL);
}

/* ---- BCryptEnumRegisteredProviders ------------------------------------------ */
TEST(gap0_enumregisteredproviders_basic) {
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptFreeBuffer));
    ULONG cb = 0; CRYPT_PROVIDERS *p = NULL;
    G0_OKST(U(BCryptEnumRegisteredProviders)(&cb, &p));
    CHECK(p != NULL && cb > 0);
    if (p) {
        t_note("registered providers: %lu", (unsigned long)p->cProviders);
        CHECK(p->cProviders >= 1 && p->rgpszProviders != NULL);
        int prim = 0;
        for (ULONG i = 0; i < p->cProviders; i++) { CHECK(p->rgpszProviders[i] && p->rgpszProviders[i][0]); t_note("  %ls", p->rgpszProviders[i]); if (!lstrcmpiW(p->rgpszProviders[i], L"Microsoft Primitive Provider")) prim = 1; }
        CHECK(prim);
        U(BCryptFreeBuffer)(p);
    }
}
TEST(gap0_enumregisteredproviders_null_size_pointer) {
    REQUIRE(U(BCryptEnumRegisteredProviders));
    CRYPT_PROVIDERS *p = NULL;
    ST(U(BCryptEnumRegisteredProviders)(NULL, &p), G0_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(gap0_enumregisteredproviders_repeatable) {
    REQUIRE(U(BCryptEnumRegisteredProviders)); REQUIRE(U(BCryptFreeBuffer));
    ULONG c1 = 0, c2 = 0; CRYPT_PROVIDERS *p1 = NULL, *p2 = NULL;
    G0_OKST(U(BCryptEnumRegisteredProviders)(&c1, &p1)); G0_OKST(U(BCryptEnumRegisteredProviders)(&c2, &p2));
    if (p1 && p2) CHECK(p1->cProviders == p2->cProviders);
    U(BCryptFreeBuffer)(p1); U(BCryptFreeBuffer)(p2);
}

/* ---- Context configuration queries (read-only) ---------------------------------- */
static const ULONG g0_bad_tables[] = { 0, 3, 4, 0x10, 0x80000000u, 0xFFFFFFFFu };
TEST(gap0_enumcontexts_invalid_table_and_pointer) {
    REQUIRE(U(BCryptEnumContexts));
    CRYPT_CONTEXTS *c = NULL; ULONG cb = 0;
    for (size_t i = 0; i < sizeof g0_bad_tables / sizeof *g0_bad_tables; i++) ST(U(BCryptEnumContexts)(g0_bad_tables[i], &cb, &c), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumContexts)(CRYPT_LOCAL, NULL, &c), G0_INVALID_PARAMETER);
    CHECK(c == NULL);
}
TEST(gap0_enumcontexts_local_and_domain) {
    REQUIRE(U(BCryptEnumContexts)); REQUIRE(U(BCryptFreeBuffer));
    static const ULONG tables[] = { CRYPT_LOCAL, CRYPT_DOMAIN };
    for (int t = 0; t < 2; t++) {
        CRYPT_CONTEXTS *c = NULL; ULONG cb = 0;
        NTSTATUS st = U(BCryptEnumContexts)(tables[t], &cb, &c);
        t_note("EnumContexts(table %lu) -> 0x%08lx", (unsigned long)tables[t], (unsigned long)st);
        if (st < 0) { CHECK(c == NULL); continue; }
        CHECK(c != NULL && cb > 0);
        if (!c) continue;
        for (ULONG i = 0; i < c->cContexts; i++) { CHECK(c->rgpszContexts[i] && c->rgpszContexts[i][0]); t_note("  context %ls", c->rgpszContexts[i]); }
        if (tables[t] == CRYPT_LOCAL) {
            int def = 0; for (ULONG i = 0; i < c->cContexts; i++) if (!lstrcmpiW(c->rgpszContexts[i], L"Default")) def = 1;
            CHECK(def);
        }
        U(BCryptFreeBuffer)(c);
    }
}
TEST(gap0_querycontextconfiguration_default) {
    REQUIRE(U(BCryptQueryContextConfiguration)); REQUIRE(U(BCryptFreeBuffer));
    CRYPT_CONTEXT_CONFIG *cfg = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, L"Default", &cb, &cfg);
    t_note("QueryContextConfiguration(Default) -> 0x%08lx", (unsigned long)st);
    G0_OKST(st);
    if (st >= 0 && cfg) { t_note("dwFlags=0x%lx dwReserved=0x%lx cb=%lu", (unsigned long)cfg->dwFlags, (unsigned long)cfg->dwReserved, (unsigned long)cb); CHECK(cb >= sizeof *cfg); U(BCryptFreeBuffer)(cfg); }
}
TEST(gap0_querycontextconfiguration_invalid_arguments) {
    REQUIRE(U(BCryptQueryContextConfiguration));
    CRYPT_CONTEXT_CONFIG *cfg = NULL; ULONG cb = 0;
    for (size_t i = 0; i < sizeof g0_bad_tables / sizeof *g0_bad_tables; i++) ST(U(BCryptQueryContextConfiguration)(g0_bad_tables[i], L"Default", &cb, &cfg), G0_INVALID_PARAMETER);
    ST(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, L"Default", NULL, &cfg), G0_INVALID_PARAMETER);
    CHECK(cfg == NULL);
}
TEST(gap0_querycontextconfiguration_missing_context_note) {
    REQUIRE(U(BCryptQueryContextConfiguration));
    CRYPT_CONTEXT_CONFIG *cfg = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, L"Gap0_NoSuchContext_7c1d", &cb, &cfg);
    t_note("QueryContextConfiguration(missing) -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0); CHECK(cfg == NULL);
}
TEST(gap0_enumcontextfunctions_default_cipher) {
    REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    CRYPT_CONTEXT_FUNCTIONS *f = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptEnumContextFunctions)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, &cb, &f);
    t_note("EnumContextFunctions(Default, cipher) -> 0x%08lx", (unsigned long)st);
    G0_OKST(st);
    if (st >= 0 && f) {
        t_note("%lu functions", (unsigned long)f->cFunctions);
        for (ULONG i = 0; i < f->cFunctions; i++) { CHECK(f->rgpszFunctions[i] && f->rgpszFunctions[i][0]); t_note("  %ls", f->rgpszFunctions[i]); }
        U(BCryptFreeBuffer)(f);
    }
}
TEST(gap0_enumcontextfunctions_each_interface) {
    REQUIRE(U(BCryptEnumContextFunctions)); REQUIRE(U(BCryptFreeBuffer));
    for (ULONG itf = 1; itf <= 8; itf++) {
        CRYPT_CONTEXT_FUNCTIONS *f = NULL; ULONG cb = 0;
        NTSTATUS st = U(BCryptEnumContextFunctions)(CRYPT_LOCAL, L"Default", itf, &cb, &f);
        t_note("interface %lu -> 0x%08lx (%lu functions)", (unsigned long)itf, (unsigned long)st, (unsigned long)(st >= 0 && f ? f->cFunctions : 0));
        if (st >= 0 && f) U(BCryptFreeBuffer)(f);
    }
}
TEST(gap0_enumcontextfunctions_invalid_arguments) {
    REQUIRE(U(BCryptEnumContextFunctions));
    CRYPT_CONTEXT_FUNCTIONS *f = NULL; ULONG cb = 0;
    for (size_t i = 0; i < sizeof g0_bad_tables / sizeof *g0_bad_tables; i++) ST(U(BCryptEnumContextFunctions)(g0_bad_tables[i], L"Default", BCRYPT_CIPHER_INTERFACE, &cb, &f), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumContextFunctions)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, NULL, &f), G0_INVALID_PARAMETER);
    CHECK(f == NULL);
}
TEST(gap0_querycontextfunctionconfiguration_invalid_arguments) {
    REQUIRE(U(BCryptQueryContextFunctionConfiguration));
    CRYPT_CONTEXT_FUNCTION_CONFIG *c = NULL; ULONG cb = 0;
    for (size_t i = 0; i < sizeof g0_bad_tables / sizeof *g0_bad_tables; i++)
        ST(U(BCryptQueryContextFunctionConfiguration)(g0_bad_tables[i], L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", &cb, &c), G0_INVALID_PARAMETER);
    ST(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", NULL, &c), G0_INVALID_PARAMETER);
    CHECK(c == NULL);
}
TEST(gap0_querycontextfunctionconfiguration_aes_note) {
    REQUIRE(U(BCryptQueryContextFunctionConfiguration)); REQUIRE(U(BCryptFreeBuffer));
    CRYPT_CONTEXT_FUNCTION_CONFIG *c = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", &cb, &c);
    t_note("QueryContextFunctionConfiguration(Default,cipher,AES) -> 0x%08lx", (unsigned long)st);
    if (st >= 0 && c) { t_note("dwFlags=0x%lx dwReserved=0x%lx", (unsigned long)c->dwFlags, (unsigned long)c->dwReserved); U(BCryptFreeBuffer)(c); }
}
TEST(gap0_enumcontextfunctionproviders_invalid_arguments) {
    REQUIRE(U(BCryptEnumContextFunctionProviders));
    CRYPT_CONTEXT_FUNCTION_PROVIDERS *p = NULL; ULONG cb = 0;
    for (size_t i = 0; i < sizeof g0_bad_tables / sizeof *g0_bad_tables; i++)
        ST(U(BCryptEnumContextFunctionProviders)(g0_bad_tables[i], L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", &cb, &p), G0_INVALID_PARAMETER);
    ST(U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", NULL, &p), G0_INVALID_PARAMETER);
    CHECK(p == NULL);
}
TEST(gap0_enumcontextfunctionproviders_aes_note) {
    REQUIRE(U(BCryptEnumContextFunctionProviders)); REQUIRE(U(BCryptFreeBuffer));
    CRYPT_CONTEXT_FUNCTION_PROVIDERS *p = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptEnumContextFunctionProviders)(CRYPT_LOCAL, L"Default", BCRYPT_CIPHER_INTERFACE, L"AES", &cb, &p);
    t_note("EnumContextFunctionProviders(Default,cipher,AES) -> 0x%08lx", (unsigned long)st);
    if (st >= 0 && p) { for (ULONG i = 0; i < p->cProviders; i++) t_note("  %ls", p->rgpszProviders[i]); U(BCryptFreeBuffer)(p); }
}
