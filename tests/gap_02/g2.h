/* Shared declarations for the gap_02 area: ncrypt.dll public exports (key operations, DPAPI-NG streams,
 * SSL protocol provider interface).
 *
 * Status codes used below (NTE_* are SECURITY_STATUS / HRESULT values):
 *   NTE_BAD_DATA 0x80090005   NTE_BAD_SIGNATURE 0x80090006  NTE_BAD_FLAGS 0x80090009
 *   NTE_INVALID_HANDLE 0x80090026  NTE_INVALID_PARAMETER 0x80090027  NTE_BUFFER_TOO_SMALL 0x80090028
 *   NTE_NOT_SUPPORTED 0x80090029   NTE_NO_MORE_ITEMS 0x8009002A
 *
 * Several tests build "fake" handles on the stack. The Windows 10 reference decompilation shows that
 * ncrypt.dll identifies its objects purely by a header (DWORD size; DWORD magic; ...) and rejects a
 * handle before any provider call when the header does not match:
 *   NCrypt provider 0x44440001, key 0x44440002, secret 0x44440003   (first DWORD is the magic)
 *   SSL provider  {size >= 0x178, 0x44444441, [2], [3]==0}
 *   SSL key       {size >= 0x20,  0x44444442}
 *   SSL hash      {size >= 0x20,  0x44444443}
 * Fake handles are only ever passed on paths that the decompilation shows fail before dispatching
 * into the provider's function table.
 */
#ifndef G2_H
#define G2_H
#include "t.h"
#include <ncrypt.h>
#include <bcrypt.h>
#include <wincrypt.h>

#define G2_NTE_BAD_DATA        ((SECURITY_STATUS)0x80090005L)
#define G2_NTE_BAD_SIGNATURE   ((SECURITY_STATUS)0x80090006L)
#define G2_NTE_BAD_FLAGS       ((SECURITY_STATUS)0x80090009L)
#define G2_NTE_INVALID_HANDLE  ((SECURITY_STATUS)0x80090026L)
#define G2_NTE_INVALID_PARAM   ((SECURITY_STATUS)0x80090027L)
#define G2_NTE_BUFFER_TOO_SMALL ((SECURITY_STATUS)0x80090028L)
#define G2_NTE_NOT_SUPPORTED   ((SECURITY_STATUS)0x80090029L)
#define G2_NTE_NO_MORE_ITEMS   ((SECURITY_STATUS)0x8009002AL)
#define G2_STATUS_INVALID_HANDLE ((SECURITY_STATUS)0xC0000008L)

#define G2_EQ(a, b) EXPECT_EQ((DWORD)(a), (DWORD)(b))

/* ---- exports missing from the mingw headers ---- */
typedef ULONG_PTR G2_HANDLE;
UDECL(LONG, NCryptCreateProtectionDescriptor, (LPCWSTR, DWORD, void **));
UDECL(LONG, NCryptCloseProtectionDescriptor, (void *));
UDECL(LONG, NCryptRegisterProtectionDescriptorName, (LPCWSTR, LPCWSTR, DWORD));
UDECL(LONG, NCryptQueryProtectionDescriptorName, (LPCWSTR, WCHAR *, SIZE_T *, DWORD));
UDECL(LONG, NCryptProtectSecret, (void *, DWORD, const BYTE *, ULONG, const void *, HWND, BYTE **, ULONG *));
UDECL(LONG, NCryptUnprotectSecret, (void **, DWORD, const BYTE *, ULONG, const void *, HWND, BYTE **, ULONG *));
typedef LONG (WINAPI *G2_STREAM_CB)(void *ctx, const BYTE *data, SIZE_T cb, BOOL final);
typedef struct { G2_STREAM_CB cb; void *ctx; } G2_STREAM_INFO;
UDECL(LONG, NCryptStreamOpenToProtect, (void *, DWORD, HWND, G2_STREAM_INFO *, void **));
UDECL(LONG, NCryptStreamOpenToUnprotect, (G2_STREAM_INFO *, DWORD, HWND, void **));
UDECL(LONG, NCryptStreamOpenToUnprotectEx, (G2_STREAM_INFO *, DWORD, HWND, void **));
UDECL(LONG, NCryptStreamUpdate, (void *, const BYTE *, SIZE_T, BOOL));
UDECL(LONG, NCryptStreamClose, (void *));

UDECL(LONG, SslOpenProvider, (G2_HANDLE *, LPCWSTR, DWORD));
UDECL(LONG, SslIncrementProviderReferenceCount, (G2_HANDLE));
UDECL(LONG, SslDecrementProviderReferenceCount, (G2_HANDLE));
UDECL(LONG, SslFreeObject, (G2_HANDLE));
UDECL(LONG, SslFreeBuffer, (void *));
UDECL(LONG, SslChangeNotify, (void));
UDECL(LONG, SslEnumProtocolProviders, (DWORD *, void **, DWORD));
UDECL(LONG, SslEnumCipherSuites, (G2_HANDLE, G2_HANDLE, void **, void **, DWORD));
UDECL(LONG, SslGetCipherSuitePRFHashAlgorithm, (G2_HANDLE, DWORD, DWORD, DWORD, WCHAR *, DWORD));
UDECL(LONG, SslGetProviderProperty, (G2_HANDLE, LPCWSTR, PBYTE *, DWORD *, void **, DWORD));
UDECL(LONG, SslGetKeyProperty, (G2_HANDLE, LPCWSTR, PBYTE *, DWORD *, DWORD));
UDECL(LONG, SslCreateHandshakeHash, (G2_HANDLE, G2_HANDLE *, DWORD, DWORD, DWORD));
UDECL(LONG, SslHashHandshake, (G2_HANDLE, G2_HANDLE, PBYTE, DWORD, DWORD));
UDECL(LONG, SslComputeFinishedHash, (G2_HANDLE, G2_HANDLE, G2_HANDLE, PBYTE, DWORD, DWORD));
UDECL(LONG, SslCreateClientAuthHash, (G2_HANDLE, G2_HANDLE *, DWORD, DWORD, LPCWSTR, DWORD));
UDECL(LONG, SslComputeClientAuthHash, (G2_HANDLE, G2_HANDLE, G2_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD *, DWORD));
UDECL(LONG, SslComputeEapKeyBlock, (G2_HANDLE, G2_HANDLE, PBYTE, DWORD, PBYTE, DWORD, PBYTE, DWORD, PBYTE, DWORD, DWORD *, DWORD));
UDECL(LONG, SslCreateEphemeralKey, (G2_HANDLE, G2_HANDLE *, DWORD, DWORD, DWORD, DWORD, PBYTE, DWORD, DWORD));
UDECL(LONG, SslExportKey, (G2_HANDLE, G2_HANDLE, LPCWSTR, PBYTE, DWORD, DWORD *, DWORD));
UDECL(LONG, SslExportKeyingMaterial, (G2_HANDLE, G2_HANDLE, LPCWSTR, DWORD, PBYTE, DWORD, BOOL, PBYTE, DWORD, DWORD *, DWORD));
UDECL(LONG, SslGenerateMasterKey, (G2_HANDLE, G2_HANDLE, G2_HANDLE, G2_HANDLE *, DWORD, DWORD, DWORD, void *, PBYTE, DWORD, DWORD));
UDECL(LONG, SslGenerateSessionKeys, (G2_HANDLE, G2_HANDLE, G2_HANDLE *, G2_HANDLE *, void *, DWORD));
UDECL(LONG, SslEncryptPacket, (G2_HANDLE, G2_HANDLE, PBYTE, DWORD, PBYTE, DWORD, DWORD *, ULONGLONG, DWORD, DWORD));
UDECL(LONG, SslDecryptPacket, (G2_HANDLE, G2_HANDLE, PBYTE, DWORD, PBYTE, DWORD, DWORD *, ULONGLONG, DWORD));

/* ---- fake SSL handles (see header comment) ---- */
#define G2_SSLP 0x44444441u
#define G2_SSLK 0x44444442u
#define G2_SSLH 0x44444443u
typedef struct { DWORD w[0x180 / 4]; } __attribute__((aligned(16))) g2_fobj;
/* version: interface version stored in the low word of dword 8 (offset 0x20) of an SSL provider */
static void g2_fake(g2_fobj *o, DWORD size, DWORD magic, WORD version) {
    memset(o, 0, sizeof *o);
    o->w[0] = size; o->w[1] = magic; o->w[4] = 1; o->w[8] = version;
}
#define G2_HND(o) ((G2_HANDLE)(ULONG_PTR)(o))
#define G2_FAKE_PROV(o, ver) g2_fake(&(o), 0x178, G2_SSLP, (ver))
#define G2_FAKE_KEY(o)       g2_fake(&(o), 0x20, G2_SSLK, 0)
#define G2_FAKE_HASH(o)      g2_fake(&(o), 0x20, G2_SSLH, 0)

/* ---- real ephemeral keys ---- */
static NCRYPT_PROV_HANDLE g2_ksp(void) {
    NCRYPT_PROV_HANDLE p = 0;
    if (!U(NCryptOpenStorageProvider)) return 0;
    if (U(NCryptOpenStorageProvider)(&p, MS_KEY_STORAGE_PROVIDER, 0) != 0) return 0;
    return p;
}
/* Creates and finalizes an in-memory (unnamed, not persisted) key. bits==0 keeps the default. */
static NCRYPT_KEY_HANDLE g2_key(NCRYPT_PROV_HANDLE p, LPCWSTR alg, DWORD bits) {
    NCRYPT_KEY_HANDLE k = 0;
    if (U(NCryptCreatePersistedKey)(p, &k, alg, NULL, 0, 0) != 0) return 0;
    if (bits && U(NCryptSetProperty)(k, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, 4, 0) != 0) { U(NCryptFreeObject)(k); return 0; }
    if (U(NCryptFinalizeKey)(k, 0) != 0) { U(NCryptFreeObject)(k); return 0; }
    return k;
}
#endif
