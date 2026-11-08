/* gap_04: depth for thinly covered exports (CNG primitives used by the WebAuthn stack, NCrypt provider open,
 * and the small webauthn.dll helpers).
 *
 * All CNG calls go through GetProcAddress pinned to bcrypt.dll / ncrypt.dll. Expected values come from the
 * Windows 10 reference decompilation:
 *   - handles carry a magic word (alg 0x55555551, key 0x55555552, hash 0x55555553); any other object is
 *     rejected with STATUS_INVALID_HANDLE (0xC0000008)
 *   - algorithm class stored in the provider header: 1 symmetric, 2 hash, 3 RSA-like (padded signatures),
 *     4 secret agreement (DH/ECDH), 5 signature (ECDSA/DSA); operations on the wrong class return
 *     STATUS_NOT_SUPPORTED (0xC00000BB)
 *   - STATUS_INVALID_PARAMETER 0xC000000D, STATUS_BUFFER_TOO_SMALL 0xC0000023, STATUS_NOT_FOUND 0xC0000225,
 *     STATUS_INVALID_SIGNATURE 0xC000A000
 */
#ifndef GAP4_H
#define GAP4_H
#include "t.h"
#include <bcrypt.h>
#include <ncrypt.h>
#include <stdlib.h>

#define G4_INVALID_HANDLE   ((NTSTATUS)0xC0000008)
#define G4_INVALID_PARAM    ((NTSTATUS)0xC000000D)
#define G4_NOT_SUPPORTED    ((NTSTATUS)0xC00000BB)
#define G4_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define G4_NOT_FOUND        ((NTSTATUS)0xC0000225)
#define G4_BAD_SIGNATURE    ((NTSTATUS)0xC000A000)

#define BC(name) UIN("bcrypt.dll", name)

/* EXPECT_EQ evaluates its arguments more than once; calls with side effects must go through EQC, which
 * evaluates the call exactly once and compares as 32-bit status values. */
#define EQC(call, want) do { int v_ = (int)(call); int w_ = (int)(want); \
    t_check(v_ == w_, __FILE__, __LINE__, #call " == " #want, "got 0x%lx want 0x%lx", (unsigned long)(unsigned)v_, (unsigned long)(unsigned)w_); } while (0)

static inline int g4_hex(const BYTE *b, size_t n, const char *hex)
{
    static const char d[] = "0123456789abcdef";
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++)
        if (hex[2 * i] != d[b[i] >> 4] || hex[2 * i + 1] != d[b[i] & 15]) return 0;
    return 1;
}

/* open an algorithm; returns NULL (and notes) if the open itself failed */
static inline BCRYPT_ALG_HANDLE g4_open(const wchar_t *alg, ULONG flags)
{
    BCRYPT_ALG_HANDLE h = NULL;
    NTSTATUS s = BC(BCryptOpenAlgorithmProvider)(&h, alg, NULL, flags);
    if (s != 0) { t_note("open of %ls (flags 0x%lx) failed: 0x%lx", alg, (unsigned long)flags, (unsigned long)s); return NULL; }
    return h;
}
static inline void g4_close(BCRYPT_ALG_HANDLE h) { if (h) BC(BCryptCloseAlgorithmProvider)(h, 0); }

/* generate + finalize a key pair; returns NULL on failure */
static inline BCRYPT_KEY_HANDLE g4_keypair(BCRYPT_ALG_HANDLE a, ULONG bits)
{
    BCRYPT_KEY_HANDLE k = NULL;
    if (BC(BCryptGenerateKeyPair)(a, &k, bits, 0) != 0) return NULL;
    if (BC(BCryptFinalizeKeyPair)(k, 0) != 0) { BC(BCryptDestroyKey)(k); return NULL; }
    return k;
}
#endif
