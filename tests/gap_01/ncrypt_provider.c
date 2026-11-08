/* ncrypt.dll provider-level exports: storage provider enumeration, algorithm enumeration and support
 * queries, handle classification and release, stubbed storage entry points, property queries.
 * Only the software key storage provider is ever opened (hardware / smart-card providers are not touched). */
#define GAP1_NCRYPT_FILE 1
#include "gap1.h"

/* ---- GetKeyStorageInterface and its aliases ------------------------------------------------- */
TEST(gap1_gksi_not_implemented) {
    GetKeyStorageInterface_pfn f = (GetKeyStorageInterface_pfn)t_proc_in("ncrypt.dll", "GetKeyStorageInterface");
    REQUIRE(f);
    void *tbl = (void *)(ULONG_PTR)0x55AA;
    /* the export is a stub in ncrypt.dll: every call yields HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND) */
    G_EQ(f(MS_KEY_STORAGE_PROVIDER, &tbl, 0), G_HR_PROC_NOT_FOUND);
    CHECK(tbl == (void *)(ULONG_PTR)0x55AA);
    G_EQ(f(NULL, &tbl, 0), G_HR_PROC_NOT_FOUND);
    G_EQ(f(L"", NULL, 0), G_HR_PROC_NOT_FOUND);
    G_EQ(f(MS_KEY_STORAGE_PROVIDER, &tbl, 0xFFFFFFFF), G_HR_PROC_NOT_FOUND);
    G_EQ(f(L"gap1 no such provider", &tbl, 1), G_HR_PROC_NOT_FOUND);
    CHECK(tbl == (void *)(ULONG_PTR)0x55AA);
}

TEST(gap1_gksi_aliases_same_stub) {
    REQUIRE(t_proc_in("ncrypt.dll", "GetKeyStorageInterface"));
    FARPROC k = t_proc_in("ncrypt.dll", "GetKeyStorageInterface");
    FARPROC i = t_proc_in("ncrypt.dll", "GetIsolationServerInterface");
    FARPROC s = t_proc_in("ncrypt.dll", "GetSChannelInterface");
    if (!k || !i || !s) { t_skip("alias exports missing"); return; }
    void *tbl = NULL;
    G_EQ(((GetKeyStorageInterface_pfn)i)(MS_KEY_STORAGE_PROVIDER, &tbl, 0), G_HR_PROC_NOT_FOUND);
    G_EQ(((GetKeyStorageInterface_pfn)s)(MS_KEY_STORAGE_PROVIDER, &tbl, 0), G_HR_PROC_NOT_FOUND);
    CHECK(tbl == NULL);
    t_note("GetKeyStorageInterface/GetIsolationServerInterface/GetSChannelInterface share an address: %s", (k == i && i == s) ? "yes" : "no");
}

TEST(gap1_gksi_resolves_in_ncrypt_only) {
    HMODULE n = t_module("ncrypt.dll");
    if (!n) { t_skip("ncrypt.dll missing"); return; }
    CHECK(GetProcAddress(n, "GetKeyStorageInterface") != NULL);
    HMODULE b = t_module("bcrypt.dll");
    if (b) { SET_ERR(0); CHECK(GetProcAddress(b, "GetKeyStorageInterface") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); }
}

/* ---- NCryptEnumStorageProviders ------------------------------------------------------------- */
TEST(gap1_esp_null_args) {
    REQUIRE(U(NCryptEnumStorageProviders));
    DWORD n = 0x77; NCryptProviderName *l = (NCryptProviderName *)(ULONG_PTR)0x1;
    G_EQ(U(NCryptEnumStorageProviders)(NULL, &l, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptEnumStorageProviders)(&n, NULL, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptEnumStorageProviders)(NULL, NULL, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(n, 0x77);
    CHECK(l == (NCryptProviderName *)(ULONG_PTR)0x1);
}

TEST(gap1_esp_bad_flags) {
    REQUIRE(U(NCryptEnumStorageProviders));
    /* only NCRYPT_SILENT_FLAG (0x40) is accepted */
    static const DWORD fl[] = { 1, 2, 4, 8, 0x10, 0x20, 0x80, 0x100, 0x200, 0x80000000, 0xFFFFFFBF, 0xFFFFFFFF, 0x41 };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        DWORD n = 0x77; NCryptProviderName *l = (NCryptProviderName *)(ULONG_PTR)0x1;
        DWORD st = U(NCryptEnumStorageProviders)(&n, &l, fl[i]);
        CHECKF(st == G_NTE_BAD_FLAGS, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        EXPECT_EQ(n, 0x77);                                    /* outputs are not touched when flags are rejected */
        CHECK(l == (NCryptProviderName *)(ULONG_PTR)0x1);
    }
}

TEST(gap1_esp_null_check_precedes_flags) {
    REQUIRE(U(NCryptEnumStorageProviders));
    NCryptProviderName *l = NULL;
    G_EQ(U(NCryptEnumStorageProviders)(NULL, &l, 0xFFFFFFFF), G_NTE_INVALID_PARAM);
}

static void esp_common(DWORD flags) {
    DWORD n = 0; NCryptProviderName *l = NULL;
    SECURITY_STATUS st = U(NCryptEnumStorageProviders)(&n, &l, flags);
    EXPECT_EQ((DWORD)st, 0);
    if (st != 0) return;
    CHECK(n >= 1 && n < 64);
    CHECK(l != NULL);
    int sw = 0;
    for (DWORD i = 0; l && i < n; i++) {
        CHECK(l[i].pszName != NULL && l[i].pszName[0] != 0);
        EXPECT_EQ(l[i].pszComment, NULL);                  /* the comment column is never filled in */
        if (l[i].pszName) {
            if (!lstrcmpW(l[i].pszName, MS_KEY_STORAGE_PROVIDER)) sw = 1;
            for (DWORD j = 0; j < i; j++) CHECK(lstrcmpW(l[j].pszName, l[i].pszName) != 0);
            if (flags == 0) t_note("storage provider[%lu]: %ls", (unsigned long)i, l[i].pszName);
        }
    }
    CHECK(sw);
    EXPECT_EQ((DWORD)U(NCryptFreeBuffer)(l), 0);
}
TEST(gap1_esp_default) { REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptFreeBuffer)); esp_common(0); }
TEST(gap1_esp_silent_flag) { REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptFreeBuffer)); esp_common(NCRYPT_SILENT_FLAG); }

TEST(gap1_esp_two_calls_same_list) {
    REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptFreeBuffer));
    DWORD n1 = 0, n2 = 0; NCryptProviderName *a = NULL, *b = NULL;
    if (U(NCryptEnumStorageProviders)(&n1, &a, 0) != 0) { t_skip("enum failed"); return; }
    if (U(NCryptEnumStorageProviders)(&n2, &b, 0) != 0) { U(NCryptFreeBuffer)(a); t_skip("enum failed"); return; }
    EXPECT_EQ(n1, n2);
    CHECK(a != b);
    for (DWORD i = 0; i < n1 && i < n2; i++) CHECK(!lstrcmpW(a[i].pszName, b[i].pszName));
    U(NCryptFreeBuffer)(a); U(NCryptFreeBuffer)(b);
}

TEST(gap1_esp_matches_resolve_providers) {
    REQUIRE(U(NCryptEnumStorageProviders)); REQUIRE(U(NCryptFreeBuffer)); REQUIRE(B(BCryptResolveProviders)); REQUIRE(B(BCryptFreeBuffer));
    DWORD n = 0; NCryptProviderName *l = NULL;
    if (U(NCryptEnumStorageProviders)(&n, &l, 0) != 0) { t_skip("enum failed"); return; }
    ULONG cb = 0; PCRYPT_PROVIDER_REFS r = NULL;
    NTSTATUS st = B(BCryptResolveProviders)(NULL, 0x10001, L"KEY_STORAGE", NULL, CRYPT_UM, 2, &cb, &r);
    EXPECT_EQ((DWORD)st, 0);
    if (st == 0 && r) {
        EXPECT_EQ(r->cProviders, n);
        for (DWORD i = 0; i < n && i < r->cProviders; i++) CHECK(!lstrcmpW(l[i].pszName, r->rgpProviders[i]->pszProvider));
        B(BCryptFreeBuffer)(r);
    }
    U(NCryptFreeBuffer)(l);
}

/* ---- NCryptFreeBuffer / NCryptFreeObject / NCryptIsKeyHandle ----------------------------------- */
TEST(gap1_freebuffer_null) {
    REQUIRE(U(NCryptFreeBuffer));
    G_EQ(U(NCryptFreeBuffer)(NULL), 0);
    G_EQ(U(NCryptFreeBuffer)(NULL), 0);
}

TEST(gap1_freeobject_null) {
    REQUIRE(U(NCryptFreeObject));
    G_EQ(U(NCryptFreeObject)(0), G_NTE_INVALID_HANDLE);
}

TEST(gap1_freeobject_provider) {
    REQUIRE(U(NCryptFreeObject));
    NEED_KSP(p);
    G_EQ(U(NCryptFreeObject)(p), 0);
}

TEST(gap1_freeobject_key_and_secret) {
    REQUIRE(U(NCryptFreeObject)); REQUIRE(U(NCryptSecretAgreement));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1), b = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1);
    if (!a || !b) { g_free(a); g_free(b); g_free(p); t_skip("ECDH_P256 key unavailable"); return; }
    NCRYPT_SECRET_HANDLE s = 0;
    G_EQ(U(NCryptSecretAgreement)(a, b, &s, 0), 0);
    CHECK(s != 0);
    G_EQ(U(NCryptFreeObject)(s), 0);
    G_EQ(U(NCryptFreeObject)(a), 0);
    G_EQ(U(NCryptFreeObject)(b), 0);
    G_EQ(U(NCryptFreeObject)(p), 0);
}

TEST(gap1_freeobject_provider_outlives_by_refcount) {
    REQUIRE(U(NCryptFreeObject));
    NEED_KSP(p);
    /* a key created from the provider keeps working after the provider handle itself is released */
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("ECDSA key unavailable"); return; }
    G_EQ(U(NCryptFreeObject)(p), 0);
    DWORD len = 0, cb = 0;
    G_EQ(U(NCryptGetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof len, &cb, 0), 0);
    EXPECT_EQ(len, 256); EXPECT_EQ(cb, 4);
    G_EQ(U(NCryptFreeObject)(k), 0);
}

TEST(gap1_iskeyhandle_null_and_provider) {
    REQUIRE(U(NCryptIsKeyHandle));
    EXPECT_EQ(U(NCryptIsKeyHandle)(0), FALSE);
    NEED_KSP(p);
    EXPECT_EQ(U(NCryptIsKeyHandle)(p), FALSE);               /* provider handles are not key handles */
    g_free(p);
}

TEST(gap1_iskeyhandle_key_and_secret) {
    REQUIRE(U(NCryptIsKeyHandle));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE a = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1), b = g_ekey(p, NCRYPT_ECDH_P256_ALGORITHM, 0, 0, 1);
    if (!a || !b) { g_free(a); g_free(b); g_free(p); t_skip("key unavailable"); return; }
    EXPECT_EQ(U(NCryptIsKeyHandle)(a), TRUE);
    EXPECT_EQ(U(NCryptIsKeyHandle)(b), TRUE);
    if (U(NCryptSecretAgreement)) {
        NCRYPT_SECRET_HANDLE s = 0;
        if (U(NCryptSecretAgreement)(a, b, &s, 0) == 0) { EXPECT_EQ(U(NCryptIsKeyHandle)(s), FALSE); g_free(s); }
    }
    g_free(a); g_free(b); g_free(p);
}

TEST(gap1_iskeyhandle_unfinalized_key) {
    REQUIRE(U(NCryptIsKeyHandle));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_RSA_ALGORITHM, 1024, 0, 0);
    if (!k) { g_free(p); t_skip("RSA key unavailable"); return; }
    EXPECT_EQ(U(NCryptIsKeyHandle)(k), TRUE);                  /* the handle class does not depend on finalization */
    g_free(k); g_free(p);
}

/* ---- provider-handle validation in the dispatchers ---------------------------------------------- */
TEST(gap1_provider_arg_invalid_handle_null) {
    REQUIRE(U(NCryptIsAlgSupported)); REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptNotifyChangeKey)); REQUIRE(U(NCryptOpenKey)); REQUIRE(U(NCryptCreatePersistedKey));
    DWORD n = 0; NCryptAlgorithmName *l = NULL; NCryptKeyName *kn = NULL; PVOID st = NULL; HANDLE ev = NULL; NCRYPT_KEY_HANDLE k = 0;
    G_EQ(U(NCryptIsAlgSupported)(0, NCRYPT_RSA_ALGORITHM, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptEnumAlgorithms)(0, 0, &n, &l, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptEnumKeys)(0, NULL, &kn, &st, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptNotifyChangeKey)(0, &ev, 1), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptOpenKey)(0, &k, L"gap1_key", 0, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptCreatePersistedKey)(0, &k, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), G_NTE_INVALID_HANDLE);
    CHECK(k == 0);
}

TEST(gap1_provider_arg_key_handle_is_not_provider) {
    REQUIRE(U(NCryptIsAlgSupported)); REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptOpenKey)); REQUIRE(U(NCryptCreatePersistedKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = g_ekey(p, NCRYPT_ECDSA_P256_ALGORITHM, 0, 0, 1);
    if (!k) { g_free(p); t_skip("key unavailable"); return; }
    DWORD n = 0; NCryptAlgorithmName *l = NULL; NCRYPT_KEY_HANDLE k2 = 0;
    G_EQ(U(NCryptIsAlgSupported)(k, NCRYPT_RSA_ALGORITHM, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptEnumAlgorithms)(k, 0, &n, &l, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptOpenKey)(k, &k2, L"gap1_key", 0, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptCreatePersistedKey)(k, &k2, NCRYPT_RSA_ALGORITHM, NULL, 0, 0), G_NTE_INVALID_HANDLE);
    g_free(k); g_free(p);
}

/* ---- NCryptIsAlgSupported ------------------------------------------------------------------- */
TEST(gap1_isalg_supported_table) {
    REQUIRE(U(NCryptIsAlgSupported));
    NEED_KSP(p);
    static const LPCWSTR ok[] = { NCRYPT_RSA_ALGORITHM, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_ECDSA_P384_ALGORITHM, NCRYPT_ECDSA_P521_ALGORITHM,
                                  NCRYPT_ECDH_P256_ALGORITHM, NCRYPT_ECDH_P384_ALGORITHM, NCRYPT_ECDH_P521_ALGORITHM, NCRYPT_DH_ALGORITHM };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        DWORD st = U(NCryptIsAlgSupported)(p, ok[i], 0);
        CHECKF(st == 0, "%ls st=0x%08lx", ok[i], (unsigned long)st);
    }
    DWORD st = U(NCryptIsAlgSupported)(p, NCRYPT_DSA_ALGORITHM, 0);
    t_note("IsAlgSupported(DSA) -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

TEST(gap1_isalg_unsupported_table) {
    REQUIRE(U(NCryptIsAlgSupported));
    NEED_KSP(p);
    /* symmetric, hash and unknown identifiers are not key-storage algorithms */
    static const LPCWSTR bad[] = { L"SHA256", L"MD5", L"RC4", L"gap1NoSuchAlgorithm", L"ECDSA_P257", L"RSA2" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        DWORD st = U(NCryptIsAlgSupported)(p, bad[i], 0);
        CHECKF(st != 0, "%ls unexpectedly supported", bad[i]);
        if (i == 3) t_note("IsAlgSupported(unknown) -> 0x%08lx", (unsigned long)st);
    }
    /* Windows 10 22H2: the software KSP reports the symmetric ciphers AES and 3DES as supported (status 0). */
    t_note("IsAlgSupported(AES) -> 0x%08lx, (3DES) -> 0x%08lx", (unsigned long)U(NCryptIsAlgSupported)(p, L"AES", 0), (unsigned long)U(NCryptIsAlgSupported)(p, L"3DES", 0));
    g_free(p);
}

TEST(gap1_isalg_case_and_whitespace) {
    REQUIRE(U(NCryptIsAlgSupported));
    NEED_KSP(p);
    DWORD a = U(NCryptIsAlgSupported)(p, L"rsa", 0), b = U(NCryptIsAlgSupported)(p, L" RSA", 0), c = U(NCryptIsAlgSupported)(p, L"RSA ", 0);
    t_note("IsAlgSupported lowercase 'rsa' -> 0x%08lx, ' RSA' -> 0x%08lx, 'RSA ' -> 0x%08lx", (unsigned long)a, (unsigned long)b, (unsigned long)c);
    CHECK(b != 0 && c != 0);
    g_free(p);
}

TEST(gap1_isalg_silent_flag) {
    REQUIRE(U(NCryptIsAlgSupported));
    NEED_KSP(p);
    G_EQ(U(NCryptIsAlgSupported)(p, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG), 0);
    g_free(p);
}

/* ---- NCryptEnumAlgorithms ------------------------------------------------------------------- */
TEST(gap1_enumalg_null_out) {
    REQUIRE(U(NCryptEnumAlgorithms));
    NEED_KSP(p);
    DWORD n = 0x77; NCryptAlgorithmName *l = (NCryptAlgorithmName *)(ULONG_PTR)1;
    G_EQ(U(NCryptEnumAlgorithms)(p, 0, NULL, &l, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptEnumAlgorithms)(p, 0, &n, NULL, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(n, 0x77);
    g_free(p);
}

static int enum_has(NCRYPT_PROV_HANDLE p, DWORD ops, LPCWSTR name, DWORD *ops_out) {
    DWORD n = 0; NCryptAlgorithmName *l = NULL; int found = 0;
    if (U(NCryptEnumAlgorithms)(p, ops, &n, &l, 0) != 0) return -1;
    for (DWORD i = 0; i < n; i++) if (l[i].pszName && !lstrcmpW(l[i].pszName, name)) { found = 1; if (ops_out) *ops_out = l[i].dwAlgOperations; }
    U(NCryptFreeBuffer)(l);
    return found;
}

TEST(gap1_enumalg_all_operations) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    DWORD n = 0; NCryptAlgorithmName *l = NULL;
    DWORD est = U(NCryptEnumAlgorithms)(p, 0, &n, &l, 0);
    t_note("EnumAlgorithms(ops=0) -> 0x%08lx count=%lu", (unsigned long)est, (unsigned long)n);
    if (est != 0) { g_free(p); return; }
    for (DWORD i = 0; l && i < n; i++) { CHECK(l[i].pszName && l[i].pszName[0]); if (i < 16) t_note("alg[%lu] %ls class=%lu ops=0x%lx", (unsigned long)i, l[i].pszName, (unsigned long)l[i].dwClass, (unsigned long)l[i].dwAlgOperations); }
    if (l) G_EQ(U(NCryptFreeBuffer)(l), 0);
    g_free(p);
}

TEST(gap1_enumalg_secret_agreement) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    DWORD ops = 0;
    EXPECT_EQ(enum_has(p, NCRYPT_SECRET_AGREEMENT_OPERATION, L"ECDH_P256", &ops), 1);
    CHECK(ops & NCRYPT_SECRET_AGREEMENT_OPERATION);
    EXPECT_EQ(enum_has(p, NCRYPT_SECRET_AGREEMENT_OPERATION, L"ECDH_P384", NULL), 1);
    EXPECT_EQ(enum_has(p, NCRYPT_SECRET_AGREEMENT_OPERATION, L"ECDH_P521", NULL), 1);
    EXPECT_EQ(enum_has(p, NCRYPT_SECRET_AGREEMENT_OPERATION, L"RSA", NULL), 0);
    EXPECT_EQ(enum_has(p, NCRYPT_SECRET_AGREEMENT_OPERATION, L"ECDSA_P256", NULL), 0);
    g_free(p);
}

TEST(gap1_enumalg_signature) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    DWORD ops = 0;
    EXPECT_EQ(enum_has(p, NCRYPT_SIGNATURE_OPERATION, L"ECDSA_P256", &ops), 1);
    CHECK(ops & NCRYPT_SIGNATURE_OPERATION);
    EXPECT_EQ(enum_has(p, NCRYPT_SIGNATURE_OPERATION, L"ECDSA_P384", NULL), 1);
    EXPECT_EQ(enum_has(p, NCRYPT_SIGNATURE_OPERATION, L"ECDSA_P521", NULL), 1);
    EXPECT_EQ(enum_has(p, NCRYPT_SIGNATURE_OPERATION, L"RSA", &ops), 1);
    EXPECT_EQ(enum_has(p, NCRYPT_SIGNATURE_OPERATION, L"ECDH_P256", NULL), 0);
    g_free(p);
}

TEST(gap1_enumalg_asymmetric_encryption) {
    REQUIRE(U(NCryptEnumAlgorithms)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    DWORD ops = 0;
    EXPECT_EQ(enum_has(p, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, L"RSA", &ops), 1);
    CHECK(ops & NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION);
    EXPECT_EQ(enum_has(p, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, L"ECDSA_P256", NULL), 0);
    g_free(p);
}

TEST(gap1_enumalg_unsupported_operations) {
    REQUIRE(U(NCryptEnumAlgorithms));
    NEED_KSP(p);
    /* the key storage provider has no cipher, hash or rng algorithms */
    static const DWORD ops[] = { NCRYPT_CIPHER_OPERATION, NCRYPT_HASH_OPERATION, NCRYPT_RNG_OPERATION };
    for (size_t i = 0; i < 3; i++) {
        DWORD n = 0x77; NCryptAlgorithmName *l = NULL;
        DWORD st = U(NCryptEnumAlgorithms)(p, ops[i], &n, &l, 0);
        t_note("EnumAlgorithms(op 0x%lx) -> 0x%08lx count=%lu", (unsigned long)ops[i], (unsigned long)st, (unsigned long)n);
        if (st == 0) { CHECK(n == 0 || l != NULL); if (l) U(NCryptFreeBuffer)(l); }
    }
    g_free(p);
}

/* ---- NCryptGetProperty on the provider handle ------------------------------------------------- */
TEST(gap1_getprop_invalid_handle) {
    REQUIRE(U(NCryptGetProperty));
    DWORD cb = 0x77; BYTE b[8];
    G_EQ(U(NCryptGetProperty)(0, NCRYPT_NAME_PROPERTY, b, sizeof b, &cb, 0), G_NTE_INVALID_HANDLE);
    G_EQ(U(NCryptGetProperty)(0, NULL, NULL, 0, NULL, 0), G_NTE_INVALID_HANDLE);   /* handle is checked first */
    EXPECT_EQ(cb, 0x77);
}

TEST(gap1_getprop_null_property_or_result) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    DWORD cb = 0x77; BYTE b[8];
    G_EQ(U(NCryptGetProperty)(p, NULL, b, sizeof b, &cb, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, b, sizeof b, NULL, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(cb, 0x77);
    g_free(p);
}

TEST(gap1_getprop_name_length_limit) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    WCHAR n64[65], n65[66]; DWORD cb = 0x77; BYTE b[16];
    g_wfill(n64, 64, L'X'); g_wfill(n65, 65, L'X');
    G_EQ(U(NCryptGetProperty)(p, n65, b, sizeof b, &cb, 0), G_NTE_INVALID_PARAM);          /* > 64 characters */
    EXPECT_EQ(cb, 0x77);
    DWORD st = U(NCryptGetProperty)(p, n64, b, sizeof b, &cb, 0);                          /* == 64 passes the length check */
    CHECKF(st != 0 && st != G_NTE_INVALID_HANDLE, "st=0x%08lx", (unsigned long)st);
    t_note("GetProperty(64-char unknown name) -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

TEST(gap1_getprop_provider_name_protocol) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    const DWORD need = (DWORD)((lstrlenW(MS_KEY_STORAGE_PROVIDER) + 1) * sizeof(WCHAR));
    DWORD cb = 0; WCHAR buf[128];
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), 0);               /* size query */
    EXPECT_EQ(cb, need);
    cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, (PBYTE)buf, 0, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, (PBYTE)buf, need - 1, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, need);
    cb = 0; memset(buf, 0, sizeof buf);
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, (PBYTE)buf, need, &cb, 0), 0);
    EXPECT_EQ(cb, need);
    EXPECT_WSTR(buf, MS_KEY_STORAGE_PROVIDER);
    cb = 0; memset(buf, 0, sizeof buf);
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, (PBYTE)buf, sizeof buf, &cb, 0), 0);   /* larger buffer: cb is the used size */
    EXPECT_EQ(cb, need);
    EXPECT_WSTR(buf, MS_KEY_STORAGE_PROVIDER);
    g_free(p);
}

TEST(gap1_getprop_provider_impl_type) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    DWORD v = 0, cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0), 0);
    EXPECT_EQ(cb, 4);
    CHECK(v & NCRYPT_IMPL_SOFTWARE_FLAG);
    CHECK(!(v & NCRYPT_IMPL_HARDWARE_FLAG));
    cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE)&v, 3, &cb, 0), G_NTE_BUFFER_TOO_SMALL);
    EXPECT_EQ(cb, 4);
    g_free(p);
}

TEST(gap1_getprop_provider_version_and_name_len) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    DWORD v = 0, cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_VERSION_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0), 0);
    EXPECT_EQ(cb, 4);
    CHECK(v != 0);
    t_note("software KSP version property = 0x%08lx", (unsigned long)v);
    cb = 0; v = 0;
    DWORD st = U(NCryptGetProperty)(p, NCRYPT_MAX_NAME_LENGTH_PROPERTY, (PBYTE)&v, sizeof v, &cb, 0);
    t_note("software KSP max name length -> st 0x%08lx value %lu", (unsigned long)st, (unsigned long)v);
    if (st == 0) { EXPECT_EQ(cb, 4); CHECK(v >= 64); }
    g_free(p);
}

TEST(gap1_getprop_provider_unknown_property) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    DWORD cb = 0x77; BYTE b[16];
    DWORD st = U(NCryptGetProperty)(p, L"gap1 no such property", b, sizeof b, &cb, 0);
    CHECKF(st != 0, "unknown property accepted");
    t_note("GetProperty(provider, unknown) -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

TEST(gap1_getprop_provider_handle_property_on_provider) {
    REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    DWORD cb = 0; BYTE b[16];
    DWORD st = U(NCryptGetProperty)(p, NCRYPT_PROVIDER_HANDLE_PROPERTY, b, sizeof b, &cb, 0);
    CHECKF(st != 0, "'Provider Handle' is a key property");
    t_note("GetProperty(provider, 'Provider Handle') -> 0x%08lx", (unsigned long)st);
    g_free(p);
}

/* ---- NCryptEnumKeys (read only) -------------------------------------------------------------- */
TEST(gap1_enumkeys_null_args) {
    REQUIRE(U(NCryptEnumKeys));
    NEED_KSP(p);
    NCryptKeyName *kn = NULL; PVOID st = NULL;
    G_EQ(U(NCryptEnumKeys)(p, NULL, NULL, &st, 0), G_NTE_INVALID_PARAM);
    G_EQ(U(NCryptEnumKeys)(p, NULL, &kn, NULL, 0), G_NTE_INVALID_PARAM);
    CHECK(kn == NULL && st == NULL);
    g_free(p);
}

TEST(gap1_enumkeys_walk_user_store) {
    REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    NCryptKeyName *kn = NULL; PVOID state = NULL; int count = 0; DWORD st;
    while ((st = U(NCryptEnumKeys)(p, NULL, &kn, &state, 0)) == 0 && count < 1000) {
        CHECK(kn != NULL);
        if (kn) { CHECK(kn->pszName != NULL && kn->pszName[0] != 0); CHECK(kn->pszAlgid != NULL); U(NCryptFreeBuffer)(kn); }
        kn = NULL; count++;
    }
    CHECKF(st == G_NTE_NO_MORE_ITEMS, "terminator st=0x%08lx after %d keys", (unsigned long)st, count);
    t_note("user key store holds %d key(s) visible to the software KSP", count);
    if (state) U(NCryptFreeBuffer)(state);
    g_free(p);
}

TEST(gap1_enumkeys_restart_after_free) {
    REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    NCryptKeyName *k1 = NULL, *k2 = NULL; PVOID s1 = NULL, s2 = NULL;
    DWORD a = U(NCryptEnumKeys)(p, NULL, &k1, &s1, 0);
    DWORD b = U(NCryptEnumKeys)(p, NULL, &k2, &s2, 0);
    EXPECT_EQ(a == 0, b == 0);                              /* two fresh scans agree on whether any key exists */
    if (a == 0 && b == 0 && k1 && k2) CHECK(!lstrcmpW(k1->pszName, k2->pszName));
    if (a == 0 && k1) U(NCryptFreeBuffer)(k1);
    if (b == 0 && k2) U(NCryptFreeBuffer)(k2);
    if (s1) U(NCryptFreeBuffer)(s1);
    if (s2) U(NCryptFreeBuffer)(s2);
    g_free(p);
}

/* ---- NCryptNotifyChangeKey -------------------------------------------------------------------- */
TEST(gap1_notify_change_key_register_unregister) {
    REQUIRE(U(NCryptNotifyChangeKey));
    NEED_KSP(p);
    HANDLE ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(ev != NULL);
    if (!ev) { g_free(p); return; }
    DWORD r = U(NCryptNotifyChangeKey)(p, &ev, 1 /* NCRYPT_REGISTER_NOTIFICATION_FLAG */);
    t_note("NotifyChangeKey(register) -> 0x%08lx", (unsigned long)r);
    if (r == 0) {
        EXPECT_EQ(WaitForSingleObject(ev, 0), WAIT_TIMEOUT);
        DWORD u = U(NCryptNotifyChangeKey)(p, &ev, 2 /* NCRYPT_UNREGISTER_NOTIFICATION_FLAG */);
        t_note("NotifyChangeKey(unregister) -> 0x%08lx", (unsigned long)u);
    }
    CloseHandle(ev);
    g_free(p);
}
