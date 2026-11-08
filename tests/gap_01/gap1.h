/* Shared declarations and helpers for the gap_01 area (CNG: bcrypt.dll / ncrypt.dll public exports).
 * Everything is resolved through the harness (U / UIN / UN); nothing here links the DLLs. */
#ifndef GAP1_H
#define GAP1_H
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>

/* ---- status values (named locally so the checks read the same on every toolchain) ---- */
#define G_NTE_BAD_FLAGS        0x80090009u
#define G_NTE_BAD_KEYSET       0x80090016u
#define G_NTE_INVALID_HANDLE   0x80090026u
#define G_NTE_INVALID_PARAM    0x80090027u
#define G_NTE_BUFFER_TOO_SMALL 0x80090028u
#define G_NTE_NOT_SUPPORTED    0x80090029u
#define G_NTE_NO_MORE_ITEMS    0x8009002Au
#define G_NTE_EXISTS           0x8009000Fu
#define G_ST_INVALID_PARAMETER 0xC000000Du
#define G_ST_INVALID_HANDLE    0xC0000008u
#define G_ST_NOT_SUPPORTED     0xC00000BBu
#define G_HR_FILE_NOT_FOUND    0x80070002u
#define G_HR_PROC_NOT_FOUND    0x8007007Fu

#define B(name) UIN("bcrypt.dll", name)
#define G_EQ(a, b)   EXPECT_EQ((DWORD)(a), (DWORD)(b))
#define G_NT_FAIL(s) ((LONG)(s) < 0)

/* Functions absent from the mingw headers. */
UDECL(SECURITY_STATUS, GetKeyStorageInterface, (LPCWSTR, void **, DWORD));
UDECL(SECURITY_STATUS, NCryptCreateProtectionDescriptor, (LPCWSTR, DWORD, void **));
UDECL(SECURITY_STATUS, NCryptCloseProtectionDescriptor, (void *));
UDECL(SECURITY_STATUS, NCryptGetProtectionDescriptorInfo, (void *, const void *, DWORD, void **));
UDECL(SECURITY_STATUS, NCryptQueryProtectionDescriptorName, (LPCWSTR, WCHAR *, SIZE_T *, DWORD));
UDECL(SECURITY_STATUS, NCryptProtectSecret, (void *, DWORD, const BYTE *, ULONG, const void *, HWND, BYTE **, ULONG *));

/* ---- ECC blob magics (public header values) ---- */
#define G_ECDSA_PUB_P256 0x31534345u
#define G_ECDSA_PRV_P256 0x32534345u
#define G_ECDH_PUB_P256  0x314B4345u
#define G_ECDH_PRV_P256  0x324B4345u

/* Provider handle for the software key storage provider, or 0 (caller skips). */
static NCRYPT_PROV_HANDLE g_open_ksp(void) {
    NCRYPT_PROV_HANDLE h = 0;
    __typeof__(&NCryptOpenStorageProvider) f = U(NCryptOpenStorageProvider);
    if (!f) return 0;
    if (f(&h, MS_KEY_STORAGE_PROVIDER, 0) != 0) return 0;
    return h;
}
static void g_free(NCRYPT_HANDLE h) { if (h) { __typeof__(&NCryptFreeObject) f = U(NCryptFreeObject); if (f) f(h); } }

/* Ephemeral (unnamed, never persisted) key. len == 0 keeps the provider default. Returns 0 on failure. */
static NCRYPT_KEY_HANDLE g_ekey(NCRYPT_PROV_HANDLE prov, LPCWSTR alg, DWORD len, int exportable, int finalize) {
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(prov, &k, alg, NULL, 0, 0) != 0) return 0;
    if (len) U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&len, sizeof len, 0);
    if (exportable) { /* plaintext (non-PKCS8) private blobs need the plaintext-export policy bit as well as the export bit */
        DWORD pol = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG; U(NCryptSetProperty)(k, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&pol, sizeof pol, 0); }
    if (finalize && U(NCryptFinalizeKey)(k, 0) != 0) { g_free(k); return 0; }
    return k;
}

/* Wide string of n copies of 'c'. */
static void g_wfill(WCHAR *out, int n, WCHAR c) { for (int i = 0; i < n; i++) out[i] = c; out[n] = 0; }

#define NEED_KSP(p) NCRYPT_PROV_HANDLE p = g_open_ksp(); if (!p) { t_skip("software KSP unavailable"); return; }

/* Wine ships a partial ncrypt whose missing entry points abort the process; every test skips there (the emulated CNG differs from, and in places aborts where, the real DLLs). */
#undef REQUIRE
#define REQUIRE(ptr) do { if (t_is_wine()) { t_skip("partial ncrypt under emulator"); return; } if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)

#endif
