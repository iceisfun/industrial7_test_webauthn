/* Shared declarations for the SSL protocol provider exports (ncrypt.dll).
 * The mingw headers do not declare these, so every prototype is declared here
 * (SECURITY_STATUS == LONG, handles are opaque pointers). */
#ifndef GAP3_H
#define GAP3_H
#include "t.h"

typedef LONG SECSTAT;
typedef void *PROVH;   /* NCRYPT_PROV_HANDLE (SSL provider object, magic 0x44444441) */
typedef void *KEYH;    /* NCRYPT_KEY_HANDLE  (SSL key object,      magic 0x44444442) */

UDECL(SECSTAT, SslOpenProvider, (PROVH *, LPCWSTR, DWORD));
UDECL(SECSTAT, SslImportKey, (PROVH, KEYH *, LPCWSTR, PBYTE, DWORD, DWORD));
UDECL(SECSTAT, SslImportMasterKey, (PROVH, KEYH, KEYH *, DWORD, DWORD, void *, PBYTE, DWORD, DWORD));
UDECL(SECSTAT, SslIncrementProviderReferenceCount, (PROVH));
UDECL(SECSTAT, SslDecrementProviderReferenceCount, (PROVH));
UDECL(SECSTAT, SslFreeObject, (void *));
UDECL(SECSTAT, SslLookupCipherLengths, (PROVH, DWORD, DWORD, DWORD, void *, DWORD, DWORD));
UDECL(SECSTAT, SslLookupCipherSuiteInfo, (PROVH, DWORD, DWORD, DWORD, void *, DWORD));
UDECL(SECSTAT, SslOpenPrivateKey, (PROVH, KEYH *, const void *, DWORD));
UDECL(SECSTAT, SslSignHash, (PROVH, KEYH, PBYTE, DWORD, PBYTE, DWORD, DWORD *, DWORD));
UDECL(SECSTAT, SslVerifySignature, (PROVH, KEYH, PBYTE, DWORD, PBYTE, DWORD, DWORD));

#define NTE_BAD_FLAGS_  0x80090009L
#define NTE_INVALID_HANDLE_ ((LONG)0x80090026)
#define NTE_INVALID_PARAMETER_ ((LONG)0x80090027)
#define NTE_NO_MEMORY_ ((LONG)0x8009000E)
#define STATUS_INVALID_HANDLE_ ((LONG)0xC0000008)
#define SSLPROV_MAGIC 0x44444441u
#define SSLKEY_MAGIC  0x44444442u
#define SSLPROV_SIZE  0x178u
#define SSLKEY_SIZE   0x20u

/* A provider-shaped header in plain memory: size at +0, magic at +4, closed flag at +0xC, refcount at +0x10. */
typedef struct { ULONG w[0x60]; } FAKE_PROV;   /* 0x180 bytes, zeroed by caller */
typedef struct { ULONG w[0x10]; } FAKE_KEY;    /* 0x40 bytes */
static void fake_prov(FAKE_PROV *p, ULONG size, ULONG magic, ULONG closed) {
    memset(p, 0, sizeof *p); p->w[0] = size; p->w[1] = magic; p->w[3] = closed; p->w[4] = 7;
}
static void fake_key(FAKE_KEY *k, ULONG size, ULONG magic) {
    memset(k, 0, sizeof *k); k->w[0] = size; k->w[1] = magic;
}

/* Header variants that every provider-validating export must reject (size < 0x178, wrong magic, closed flag set). */
typedef struct { const char *what; ULONG size, magic, closed; } PROV_VARIANT;
static const PROV_VARIANT bad_prov[] = {
    { "size 0",            0,           SSLPROV_MAGIC, 0 },
    { "size 0x177",        0x177,       SSLPROV_MAGIC, 0 },
    { "size 0x20",         0x20,        SSLPROV_MAGIC, 0 },
    { "magic 0",           SSLPROV_SIZE, 0,            0 },
    { "key magic",         SSLPROV_SIZE, SSLKEY_MAGIC, 0 },
    { "magic 0x44444443",  SSLPROV_SIZE, 0x44444443,   0 },
    { "magic 0x44444440",  SSLPROV_SIZE, 0x44444440,   0 },
    { "magic swapped",     SSLPROV_SIZE, 0x41444444,   0 },
    { "closed 1",          SSLPROV_SIZE, SSLPROV_MAGIC, 1 },
    { "closed 0x80000000", SSLPROV_SIZE, SSLPROV_MAGIC, 0x80000000u },
    { "closed ffffffff",   SSLPROV_SIZE, SSLPROV_MAGIC, 0xFFFFFFFFu },
};
#define N_BAD_PROV (sizeof bad_prov / sizeof bad_prov[0])

/* Key header variants that must be rejected (size < 0x20, wrong magic). */
typedef struct { const char *what; ULONG size, magic; } KEY_VARIANT;
static const KEY_VARIANT bad_key[] = {
    { "size 0",            0,            SSLKEY_MAGIC },
    { "size 0x1f",         0x1f,         SSLKEY_MAGIC },
    { "magic 0",           SSLKEY_SIZE,  0 },
    { "provider magic",    SSLKEY_SIZE,  SSLPROV_MAGIC },
    { "magic 0x44444443",  SSLKEY_SIZE,  0x44444443 },
    { "magic 0x44444441+1 off", SSLKEY_SIZE, 0x44444444 },
    { "magic swapped",     SSLKEY_SIZE,  0x42444444 },
};
#define N_BAD_KEY (sizeof bad_key / sizeof bad_key[0])

/* Flag values to probe (all are reserved/unused by the wrappers' own checks except where stated). */
static const DWORD odd_flags[] = { 0, 1, 2, 4, 0x10, 0x100, 0x8000, 0x10000, 0x80000000u, 0xFFFFFFFFu };
#define N_ODD_FLAGS (sizeof odd_flags / sizeof odd_flags[0])
#define NEED(f) do { REQUIRE(f); if (t_is_wine()) { t_skip("Ssl* exports are unimplemented stubs under wine"); return; } } while (0)
#endif
