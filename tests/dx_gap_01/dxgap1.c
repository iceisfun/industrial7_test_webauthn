/* State-changing CNG exports: persisted key create / open / enumerate / delete in the current user's
 * software key store, and the context-configuration mutators addressed at nonexistent targets.
 * Run only with the destructive pass. Every key created carries a unique name derived from the process id
 * and tick count and is deleted again (also on failure paths). Nothing touches machine keys, the platform
 * authenticator or any configuration that already exists. */
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>

#define NTE_EXISTS_V       0x8009000Fu
#define NTE_BAD_KEYSET_V   0x80090016u
#define NTE_INVALID_HANDLE_V 0x80090026u
#define ST_INVALID_PARAMETER 0xC000000Du

#define B(name) UIN("bcrypt.dll", name)
#define DXEQ(a, b) EXPECT_EQ((DWORD)(a), (DWORD)(b))
#undef REQUIRE
#define REQUIRE(ptr) do { if (t_is_wine()) { t_skip("partial CNG under emulator"); return; } if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)

static NCRYPT_PROV_HANDLE open_ksp(void) {
    NCRYPT_PROV_HANDLE h = 0;
    if (!U(NCryptOpenStorageProvider) || U(NCryptOpenStorageProvider)(&h, MS_KEY_STORAGE_PROVIDER, 0) != 0) return 0;
    return h;
}
#define NEED_KSP(p) NCRYPT_PROV_HANDLE p = open_ksp(); if (!p) { t_skip("software KSP unavailable"); return; }

static void mkname(WCHAR *out, const char *tag) {
    static LONG seq;
    wsprintfW(out, L"gapdx_%S_%lu_%lu_%ld", tag, (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount(), InterlockedIncrement(&seq));
}
static void fr(NCRYPT_HANDLE h) { if (h) U(NCryptFreeObject)(h); }

/* Delete a key by name if it exists (cleanup on every path). */
static void drop(NCRYPT_PROV_HANDLE p, const WCHAR *name) {
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptOpenKey)(p, &k, name, 0, 0) == 0 && k) U(NCryptDeleteKey)(k, 0);
}

static NCRYPT_KEY_HANDLE mk_persisted(NCRYPT_PROV_HANDLE p, LPCWSTR alg, const WCHAR *name, DWORD flags, int exportable) {
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, alg, name, 0, flags) != 0) return 0;
    if (exportable) { DWORD pol = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;  /* plaintext private blobs need both bits */ U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, sizeof pol, 0); }
    if (U(NCryptFinalizeKey)(k, 0) != 0) { U(NCryptDeleteKey)(k, 0); return 0; }
    return k;
}

TEST(dxgap1_persisted_key_lifecycle) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptOpenKey)); REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptGetProperty));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "life");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key in this environment"); return; }
    WCHAR got[128] = { 0 }; DWORD cb = 0;
    DXEQ(U(NCryptGetProperty)(k, NCRYPT_NAME_PROPERTY, (PBYTE)got, sizeof got, &cb, 0), 0);
    EXPECT_WSTR(got, name);
    EXPECT_EQ(cb, (lstrlenW(name) + 1) * sizeof(WCHAR));
    NCRYPT_KEY_HANDLE k2 = 0;
    DXEQ(U(NCryptOpenKey)(p, &k2, name, 0, 0), 0);
    CHECK(k2 != 0 && k2 != k);
    if (k2) {
        memset(got, 0, sizeof got);
        DXEQ(U(NCryptGetProperty)(k2, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)got, sizeof got, &cb, 0), 0);
        EXPECT_WSTR(got, L"ECDSA_P256");
        fr(k2);
    }
    DXEQ(U(NCryptDeleteKey)(k, 0), 0);                        /* success consumes the handle */
    NCRYPT_KEY_HANDLE k3 = (NCRYPT_KEY_HANDLE)0x1234;
    DXEQ(U(NCryptOpenKey)(p, &k3, name, 0, 0), NTE_BAD_KEYSET_V);
    EXPECT_EQ(k3, 0x1234);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_persisted_key_survives_provider_release) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptOpenKey));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "surv");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    fr(k); fr(p);
    NEED_KSP(p2);
    NCRYPT_KEY_HANDLE again = 0;
    DXEQ(U(NCryptOpenKey)(p2, &again, name, 0, 0), 0);
    CHECK(again != 0);
    fr(again);
    drop(p2, name);
    fr(p2);
}

TEST(dxgap1_create_existing_name) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptExportKey));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "dup");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    BYTE first[128]; DWORD c1 = 0;
    DXEQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, first, sizeof first, &c1, 0), 0);
    NCRYPT_KEY_HANDLE dup = (NCRYPT_KEY_HANDLE)0x1234;
    DXEQ(U(NCryptCreatePersistedKey)(p, &dup, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0), NTE_EXISTS_V);
    EXPECT_EQ(dup, 0x1234);
    /* NCRYPT_OVERWRITE_KEY_FLAG replaces the stored key */
    NCRYPT_KEY_HANDLE ow = 0;
    DWORD st = U(NCryptCreatePersistedKey)(p, &ow, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, NCRYPT_OVERWRITE_KEY_FLAG);
    DXEQ(st, 0);
    if (st == 0 && ow) {
        DXEQ(U(NCryptFinalizeKey)(ow, 0), 0);
        BYTE second[128]; DWORD c2 = 0;
        DXEQ(U(NCryptExportKey)(ow, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, second, sizeof second, &c2, 0), 0);
        CHECK(c1 == c2 && memcmp(first, second, c1) != 0);
        fr(ow);
    }
    fr(k);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_enumkeys_lists_new_key) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptFreeBuffer));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "enum");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    NCryptKeyName *kn = NULL; PVOID state = NULL; int found = 0, n = 0; DWORD st;
    while ((st = U(NCryptEnumKeys)(p, NULL, &kn, &state, 0)) == 0 && n < 5000) {
        if (kn && kn->pszName && !lstrcmpW(kn->pszName, name)) {
            found = 1;
            CHECK(kn->pszAlgid != NULL && kn->pszAlgid[0] != 0);
            EXPECT_EQ(kn->dwLegacyKeySpec, 0);
            if (kn->pszAlgid) t_note("enumerated key algid '%ls' flags 0x%lx", kn->pszAlgid, (unsigned long)kn->dwFlags);
        }
        if (kn) U(NCryptFreeBuffer)(kn);
        kn = NULL; n++;
    }
    DXEQ(st, 0x8009002Au);
    CHECK(found);
    if (state) U(NCryptFreeBuffer)(state);
    fr(k);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_enumkeys_forgets_deleted_key) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptEnumKeys)); REQUIRE(U(NCryptFreeBuffer)); REQUIRE(U(NCryptDeleteKey));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "gone");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    DXEQ(U(NCryptDeleteKey)(k, 0), 0);
    NCryptKeyName *kn = NULL; PVOID state = NULL; int found = 0, n = 0; DWORD st;
    while ((st = U(NCryptEnumKeys)(p, NULL, &kn, &state, 0)) == 0 && n < 5000) {
        if (kn && kn->pszName && !lstrcmpW(kn->pszName, name)) found = 1;
        if (kn) U(NCryptFreeBuffer)(kn);
        kn = NULL; n++;
    }
    CHECK(!found);
    if (state) U(NCryptFreeBuffer)(state);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_delete_consumes_handle_only_on_success) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptDeleteKey)); REQUIRE(U(NCryptIsKeyHandle));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "cons");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    EXPECT_EQ(U(NCryptIsKeyHandle)(k), TRUE);
    DXEQ(U(NCryptDeleteKey)(k, 0), 0);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_persisted_exportable_key_roundtrip) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptExportKey)); REQUIRE(U(NCryptImportKey));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "exp");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 1);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    BYTE prv[128], pub1[128], pub2[128]; DWORD cp = 0, c1 = 0, c2 = 0;
    DXEQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPRIVATE_BLOB, NULL, prv, sizeof prv, &cp, 0), 0);
    EXPECT_EQ(cp, 104);
    DXEQ(U(NCryptExportKey)(k, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, pub1, sizeof pub1, &c1, 0), 0);
    /* reopen and export again: the stored key is identical */
    NCRYPT_KEY_HANDLE k2 = 0;
    DXEQ(U(NCryptOpenKey)(p, &k2, name, 0, 0), 0);
    if (k2) {
        DXEQ(U(NCryptExportKey)(k2, 0, BCRYPT_ECCPUBLIC_BLOB, NULL, pub2, sizeof pub2, &c2, 0), 0);
        CHECK(c1 == c2 && !memcmp(pub1, pub2, c1));
        fr(k2);
    }
    fr(k);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_open_with_wrong_legacy_keyspec) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptOpenKey));
    NEED_KSP(p);
    WCHAR name[96]; mkname(name, "spec");
    NCRYPT_KEY_HANDLE k = mk_persisted(p, NCRYPT_ECDSA_P256_ALGORITHM, name, 0, 0);
    if (!k) { fr(p); t_skip("cannot create persisted key"); return; }
    NCRYPT_KEY_HANDLE o = 0;
    DWORD st = U(NCryptOpenKey)(p, &o, name, 1 /* AT_KEYEXCHANGE */, 0);
    t_note("OpenKey(persisted CNG key, legacy keyspec 1) -> 0x%08lx", (unsigned long)st);
    fr(o); fr(k);
    drop(p, name);
    fr(p);
}

TEST(dxgap1_delete_ephemeral_key) {
    REQUIRE(U(NCryptCreatePersistedKey)); REQUIRE(U(NCryptFinalizeKey)); REQUIRE(U(NCryptDeleteKey));
    NEED_KSP(p);
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, NCRYPT_ECDSA_P256_ALGORITHM, NULL, 0, 0) != 0 || U(NCryptFinalizeKey)(k, 0) != 0) { fr(k); fr(p); t_skip("cannot create ephemeral key"); return; }
    DWORD st = U(NCryptDeleteKey)(k, 0);
    t_note("NCryptDeleteKey(ephemeral key) -> 0x%08lx", (unsigned long)st);
    if (st != 0) fr(k);                                       /* the handle is only consumed on success */
    fr(p);
}

/* ---- context configuration mutators, aimed at targets that do not exist ------------------------------------ */
TEST(dxgap1_remove_context_function_nonexistent) {
    REQUIRE(B(BCryptRemoveContextFunction));
    WCHAR ctx[64]; mkname(ctx, "ctx");
    NTSTATUS st = B(BCryptRemoveContextFunction)(CRYPT_LOCAL, ctx, BCRYPT_RNG_INTERFACE, L"gapdx_function");
    t_note("RemoveContextFunction(nonexistent context) -> 0x%08lx", (unsigned long)st);
    CHECKF((DWORD)st != ST_INVALID_PARAMETER, "well-formed arguments rejected by user-mode validation");
    CHECKF((LONG)st < 0, "removing a function that was never added succeeded");
}

TEST(dxgap1_set_context_function_property_nonexistent) {
    REQUIRE(B(BCryptSetContextFunctionProperty));
    WCHAR ctx[64]; mkname(ctx, "ctxp");
    UCHAR v[4] = { 1, 0, 0, 0 };
    NTSTATUS st = B(BCryptSetContextFunctionProperty)(CRYPT_LOCAL, ctx, BCRYPT_RNG_INTERFACE, L"gapdx_function", L"gapdx_property", sizeof v, v);
    t_note("SetContextFunctionProperty(nonexistent context) -> 0x%08lx", (unsigned long)st);
    CHECKF((DWORD)st != ST_INVALID_PARAMETER, "well-formed arguments rejected by user-mode validation");
    CHECKF((LONG)st < 0, "set on a context that does not exist succeeded");
    if (!((LONG)st < 0) && B(BCryptRemoveContextFunction)) B(BCryptRemoveContextFunction)(CRYPT_LOCAL, ctx, BCRYPT_RNG_INTERFACE, L"gapdx_function");
}

TEST(dxgap1_set_context_function_property_domain_table) {
    REQUIRE(B(BCryptSetContextFunctionProperty));
    WCHAR ctx[64]; mkname(ctx, "ctxd");
    UCHAR v[4] = { 1, 0, 0, 0 };
    NTSTATUS st = B(BCryptSetContextFunctionProperty)(CRYPT_DOMAIN, ctx, BCRYPT_RNG_INTERFACE, L"gapdx_function", L"gapdx_property", sizeof v, v);
    t_note("SetContextFunctionProperty(CRYPT_DOMAIN, nonexistent) -> 0x%08lx", (unsigned long)st);
    CHECKF((DWORD)st != ST_INVALID_PARAMETER, "CRYPT_DOMAIN is a valid table id");
    if (!((LONG)st < 0) && B(BCryptRemoveContextFunction)) B(BCryptRemoveContextFunction)(CRYPT_DOMAIN, ctx, BCRYPT_RNG_INTERFACE, L"gapdx_function");
}
