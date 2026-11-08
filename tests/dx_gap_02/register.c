/* State-changing success paths: NCryptRegisterProtectionDescriptorName (per-user registry) and
 * NCryptTranslateHandle (creates and removes a legacy CAPI key container).
 * Runs only with the destructive pass. Names are unique per process and removed before returning. */
#include "t.h"
#include <ncrypt.h>
#include <wincrypt.h>

#define NTE_BAD_FLAGS_ ((LONG)0x80090009L)
UDECL(LONG, NCryptRegisterProtectionDescriptorName, (LPCWSTR, LPCWSTR, DWORD));
UDECL(LONG, NCryptQueryProtectionDescriptorName, (LPCWSTR, WCHAR *, SIZE_T *, DWORD));
#define EQ(a, b) EXPECT_EQ((DWORD)(a), (DWORD)(b))

static const WCHAR *KEYPATH = L"Software\\Microsoft\\Cryptography\\NProtect\\NamedDescriptors";

static void uname(WCHAR *out, size_t cap, const char *tag) {
    swprintf(out, cap, L"gap2dx_%S_%lu", tag, (unsigned long)GetCurrentProcessId());
}
/* 0 = missing, 1 = present (value copied), -1 = other error */
static int regread(const WCHAR *name, WCHAR *val, DWORD cap) {
    DWORD cb = cap * sizeof(WCHAR), type = 0;
    LONG r = RegGetValueW(HKEY_CURRENT_USER, KEYPATH, name, RRF_RT_REG_SZ, &type, val, &cb);
    if (r == ERROR_SUCCESS) return 1;
    if (r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND) return 0;
    return -1;
}
static void regclean(const WCHAR *name) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, KEYPATH, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) { RegDeleteValueW(k, name); RegCloseKey(k); }
}

TEST(dx_gap2_register_name_roundtrip) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; }
    WCHAR n[64], v[128];
    uname(n, 64, "rt");
    regclean(n);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"LOCAL=user", 0), 0);
    EQ(regread(n, v, 128), 1);
    EXPECT_WSTR(v, L"LOCAL=user");            /* stored as REG_SZ in HKCU */
    /* overwrite */
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"LOCAL=machine", 0), 0);
    EQ(regread(n, v, 128), 1);
    EXPECT_WSTR(v, L"LOCAL=machine");
    if (UN(NCryptQueryProtectionDescriptorName)) {
        WCHAR q[128] = {0}; SIZE_T cq = 128;
        LONG r = UN(NCryptQueryProtectionDescriptorName)(n, q, &cq, 0);
        t_note("NCryptQueryProtectionDescriptorName -> 0x%08lx \"%ls\" (%zu)", (unsigned long)r, r == 0 ? q : L"", (size_t)cq);
        if (r == 0) EXPECT_WSTR(q, L"LOCAL=machine");
    }
    /* NULL descriptor deletes the registration */
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, NULL, 0), 0);
    EQ(regread(n, v, 128), 0);
    /* deleting again reports the registry error mapped into an HRESULT */
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, NULL, 0), 0x80070002);
    regclean(n);
}
TEST(dx_gap2_register_name_empty_descriptor_deletes) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; }
    WCHAR n[64], v[128];
    uname(n, 64, "empty");
    regclean(n);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"LOCAL=user", 0), 0);
    EQ(regread(n, v, 128), 1);
    /* an empty descriptor string behaves like NULL */
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"", 0), 0);
    EQ(regread(n, v, 128), 0);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"", 0), 0x80070002);
    regclean(n);
}
TEST(dx_gap2_register_name_unregister_unknown) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; }
    WCHAR n[64];
    uname(n, 64, "unknown");
    regclean(n);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, NULL, 0), 0x80070002);
}
TEST(dx_gap2_register_name_case_and_long_value) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; }
    WCHAR n[64], v[600], big[400];
    uname(n, 64, "long");
    regclean(n);
    for (int i = 0; i < 399; i++) big[i] = (i % 17 == 16) ? L' ' : L'a' + (i % 5);
    big[399] = 0;
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, big, 0), 0);   /* no validation of the descriptor syntax is done at registration time */
    EQ(regread(n, v, 600), 1);
    EXPECT_WSTR(v, big);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, NULL, 0), 0);
    /* value names are case-insensitive in the registry: delete with different case */
    EQ(UN(NCryptRegisterProtectionDescriptorName)(n, L"LOCAL=user", 0), 0);
    WCHAR up[64]; lstrcpyW(up, n); CharUpperW(up);
    EQ(UN(NCryptRegisterProtectionDescriptorName)(up, NULL, 0), 0);
    EQ(regread(n, v, 128), 0);
    regclean(n);
}

/* ---- NCryptTranslateHandle with a legacy CAPI container ---- */
TEST(dx_gap2_translate_handle_legacy_container) {
    REQUIRE(U(NCryptTranslateHandle));
    if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; }
    WCHAR cont[64]; swprintf(cont, 64, L"gap2dx_cont_%lu", (unsigned long)GetCurrentProcessId());
    HCRYPTPROV hp = 0; HCRYPTKEY hk = 0;
    CryptAcquireContextW(&hp, cont, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);   /* ensure clean */
    hp = 0;
    if (!CryptAcquireContextW(&hp, cont, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_NEWKEYSET)) { t_skip("cannot create legacy container (%lu)", GetLastError()); return; }
    if (!CryptGenKey(hp, AT_SIGNATURE, (1024u << 16), &hk)) { t_skip("cannot generate legacy key (%lu)", GetLastError()); goto cleanup; }
    {
        NCRYPT_PROV_HANDLE np = 0; NCRYPT_KEY_HANDLE nk = 0;
        LONG r = U(NCryptTranslateHandle)(&np, &nk, hp, hk, AT_SIGNATURE, 0);
        t_note("NCryptTranslateHandle(legacy RSA signature key) -> 0x%08lx", (unsigned long)r);
        if (r == 0) {
            CHECK(nk != 0);
            /* the translated key can sign: PKCS#1 over a SHA-1 sized digest */
            BYTE h[20] = {1,2,3}; BYTE sig[128]; DWORD cb = 0;
            BCRYPT_PKCS1_PADDING_INFO pi = { NCRYPT_SHA1_ALGORITHM };
            r = U(NCryptSignHash)(nk, &pi, h, 20, sig, sizeof sig, &cb, NCRYPT_PAD_PKCS1_FLAG);
            t_note("sign with translated key -> 0x%08lx cb=%lu", (unsigned long)r, (unsigned long)cb);
            if (r == 0) EXPECT_EQ(cb, 128);
            if (nk) U(NCryptFreeObject)(nk);
            if (np) U(NCryptFreeObject)(np);
        }
        /* NULL phProvider is allowed (only the key is wanted) */
        nk = 0;
        r = U(NCryptTranslateHandle)(NULL, &nk, hp, hk, AT_SIGNATURE, 0);
        t_note("NCryptTranslateHandle(phProvider=NULL) -> 0x%08lx", (unsigned long)r);
        if (r == 0 && nk) U(NCryptFreeObject)(nk);
    }
cleanup:
    if (hk) CryptDestroyKey(hk);
    if (hp) CryptReleaseContext(hp, 0);
    hp = 0;
    CryptAcquireContextW(&hp, cont, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_DELETEKEYSET);
}
