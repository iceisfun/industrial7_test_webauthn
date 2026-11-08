/* Shared declarations for the gap_00 area: CNG (bcrypt.dll) entry points reached through GetProcAddress only.
 * All function pointers come from U(Name); nothing is linked. */
#ifndef GAP0_H
#define GAP0_H
#include "t.h"
#include <bcrypt.h>

/* NTSTATUS values compared as unsigned 32-bit. */
#define G0_SUCCESS            0x00000000u
#define G0_INVALID_HANDLE     0xC0000008u
#define G0_INVALID_PARAMETER  0xC000000Du
#define G0_ACCESS_DENIED      0xC0000022u
#define G0_BUFFER_TOO_SMALL   0xC0000023u
#define G0_NOT_SUPPORTED      0xC00000BBu
#define G0_INVALID_BUF_SIZE   0xC0000206u
#define G0_AUTH_TAG_MISMATCH  0xC000A002u
#define G0_NOT_FOUND          0xC0000225u

/* Check an NTSTATUS-returning expression against an expected unsigned value. */
#define ST(expr, want) do { ULONG s_ = (ULONG)(expr); \
    t_check(s_ == (ULONG)(want), __FILE__, __LINE__, #expr " == " #want, "got 0x%08lx want 0x%08lx", (unsigned long)s_, (unsigned long)(ULONG)(want)); } while (0)
#define G0_OKST(expr) ST(expr, G0_SUCCESS)

/* Windows 10 pseudo algorithm handles (low nibble 1). */
#define G0_PH_MD5     ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x21)
#define G0_PH_SHA1    ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x31)
#define G0_PH_SHA256  ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x41)
#define G0_PH_SHA384  ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x51)
#define G0_PH_SHA512  ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x61)
#define G0_PH_RNG     ((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x81)

#define G0_ALG_HMAC   0x00000008u

/* hex string -> bytes, returns length */
static size_t g0_hex(const char *h, unsigned char *out) {
    size_t n = 0;
    while (h[0] && h[1]) {
        unsigned v = 0;
        for (int i = 0; i < 2; i++) { char c = h[i]; v = v * 16 + (c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0'); }
        out[n++] = (unsigned char)v; h += 2;
    }
    return n;
}
/* compare buffer with hex string (whole length must match) */
static int g0_eqhex(const unsigned char *b, size_t cb, const char *hex) {
    unsigned char e[512]; size_t n = g0_hex(hex, e);
    return n == cb && !memcmp(b, e, n);
}
static void g0_dump(const char *what, const unsigned char *b, size_t cb) {
    char s[1100]; size_t i; for (i = 0; i < cb && i < 512; i++) sprintf(s + i * 2, "%02x", b[i]); s[i * 2] = 0; t_note("%s = %s", what, s);
}
#define G0_CHECK_HEX(buf, cb, hex) do { int ok_ = g0_eqhex((buf), (cb), (hex)); t_check(ok_, __FILE__, __LINE__, "bytes == " hex, NULL); if (!ok_) g0_dump(#buf, (buf), (cb)); } while (0)

static NTSTATUS g0_open(BCRYPT_ALG_HANDLE *h, const wchar_t *id, ULONG flags) {
    *h = NULL; return U(BCryptOpenAlgorithmProvider)(h, id, NULL, flags);
}
static void g0_close(BCRYPT_ALG_HANDLE h) { if (h) U(BCryptCloseAlgorithmProvider)(h, 0); }

/* One-shot hash/HMAC through CreateHash/HashData/FinishHash/DestroyHash. */
static NTSTATUS g0_hash(BCRYPT_ALG_HANDLE alg, const void *key, ULONG cbkey, const void *data, ULONG cb, unsigned char *out, ULONG cbout) {
    BCRYPT_HASH_HANDLE h = NULL; NTSTATUS st;
    st = U(BCryptCreateHash)(alg, &h, NULL, 0, (PUCHAR)key, cbkey, 0); if (st < 0) return st;
    if (cb) st = U(BCryptHashData)(h, (PUCHAR)data, cb, 0);
    if (st >= 0) st = U(BCryptFinishHash)(h, out, cbout, 0);
    U(BCryptDestroyHash)(h); return st;
}
static ULONG g0_prop_u32(BCRYPT_HANDLE h, const wchar_t *name) {
    ULONG v = 0, cb = 0; NTSTATUS st = U(BCryptGetProperty)(h, name, (PUCHAR)&v, 4, &cb, 0); return st >= 0 ? v : 0xFFFFFFFFu;
}
#endif
