/* Shared helpers for the ctap_authdata_cose area.
 *
 * Functions under test (all exported by name from webauthn.dll, none declared in the SDK headers):
 *   HRESULT WebAuthNCtapParseAuthenticatorData(DWORD cb, const BYTE *pb, BYTE *pbFlags, DWORD *pdwSignCount);
 *   HRESULT WebAuthNGetCredentialIdFromAuthenticatorData(DWORD cb, const BYTE *pb, DWORD *pcbCredId, DWORD *pdwOffset);
 *   HRESULT WebAuthNGetCoseAlgorithmIdentifier(PCWSTR pwszName, LONG *plAlg);
 *
 * Authenticator data layout (WebAuthn): rpIdHash[32] | flags | signCount (big endian u32) |
 * [AT: aaguid[16] | credIdLen (BE u16) | credId | COSE_Key (CBOR map)] | [ED: extensions CBOR map].
 */
#ifndef ACD_H
#define ACD_H
#include "t.h"
#include <stdlib.h>

UDECL(HRESULT, WebAuthNCtapParseAuthenticatorData, (DWORD cb, const BYTE *pb, BYTE *pbFlags, DWORD *pdwSignCount));
UDECL(HRESULT, WebAuthNGetCredentialIdFromAuthenticatorData, (DWORD cb, const BYTE *pb, DWORD *pcbCredId, DWORD *pdwOffset));
UDECL(HRESULT, WebAuthNGetCoseAlgorithmIdentifier, (PCWSTR pwszName, LONG *plAlg));

#define ACD_E_INVALID_DATA   0x8007000DUL   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA) */
#define ACD_NTE_INVALID_PARAM 0x80090027UL  /* NTE_INVALID_PARAMETER */
#define ACD_NTE_NOT_SUPPORTED 0x80090029UL  /* NTE_NOT_SUPPORTED */

#define ACD_UP 0x01
#define ACD_UV 0x04
#define ACD_AT 0x40
#define ACD_ED 0x80

#define ACD_HDR 37          /* rpIdHash + flags + signCount */
#define ACD_ATT_FIXED 18    /* aaguid + credIdLen */
#define ACD_CRED_OFF 55     /* offset of the credential id in a well formed AT buffer */

#define HRV(x) ((DWORD)(x))

#define SENT_FL 0xEE
#define SENT_SC 0xDEADBEEFUL
#define SENT_CB 0xDEADBEEFUL
#define SENT_OFF 0x7EADBEEFUL

/* ---- growable byte vector ---------------------------------------------- */
typedef struct { BYTE *p; size_t n, cap; } vec;
static void v_init(vec *v) { v->p = NULL; v->n = v->cap = 0; }
static void v_free(vec *v) { free(v->p); v_init(v); }
static void v_put(vec *v, const void *src, size_t n) {
    if (v->n + n > v->cap) { size_t c = v->cap ? v->cap : 256; while (c < v->n + n) c *= 2; v->p = (BYTE *)realloc(v->p, c); v->cap = c; }
    if (n) memcpy(v->p + v->n, src, n);
    v->n += n;
}
static void v_u8(vec *v, unsigned b) { BYTE x = (BYTE)b; v_put(v, &x, 1); }
static void v_be16(vec *v, unsigned x) { v_u8(v, x >> 8); v_u8(v, x); }
static void v_be32(vec *v, DWORD x) { v_u8(v, x >> 24); v_u8(v, x >> 16); v_u8(v, x >> 8); v_u8(v, x); }
static void v_copy(vec *d, const vec *s) { v_init(d); v_put(d, s->p, s->n); }
static void v_hex(vec *v, const char *hex) {
    while (*hex) { if (*hex == ' ') { hex++; continue; } char b[3] = { hex[0], hex[1], 0 }; v_u8(v, (unsigned)strtoul(b, NULL, 16)); hex += 2; }
}

/* ---- CBOR encoding (minimal heads) -------------------------------------- */
static void cb_head(vec *v, unsigned major, unsigned long long val) {
    unsigned m = major << 5;
    if (val < 24) v_u8(v, m | (unsigned)val);
    else if (val < 0x100) { v_u8(v, m | 24); v_u8(v, (unsigned)val); }
    else if (val < 0x10000) { v_u8(v, m | 25); v_be16(v, (unsigned)val); }
    else { v_u8(v, m | 26); v_be32(v, (DWORD)val); }
}
static void cb_int(vec *v, long long x) { if (x >= 0) cb_head(v, 0, (unsigned long long)x); else cb_head(v, 1, (unsigned long long)(-1 - x)); }
static void cb_bstr(vec *v, const BYTE *p, size_t n) { cb_head(v, 2, n); v_put(v, p, n); }
static void cb_tstr(vec *v, const char *s) { size_t n = strlen(s); cb_head(v, 3, n); v_put(v, s, n); }
static void fill_pat(BYTE *p, size_t n, unsigned seed) { for (size_t i = 0; i < n; i++) p[i] = (BYTE)((seed + i * 7u) ^ 0x5A); }

/* ---- COSE keys ---------------------------------------------------------- */
static const BYTE P256_GX[32] = {
    0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
    0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96 };
static const BYTE P256_GY[32] = {
    0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
    0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5 };

/* {1:2, 3:alg, -1:crv, -2:x, -3:y} */
static void cose_ec(vec *v, long long alg, int crv, size_t clen, int use_g) {
    BYTE x[66], y[66];
    if (use_g && clen == 32) { memcpy(x, P256_GX, 32); memcpy(y, P256_GY, 32); }
    else { fill_pat(x, clen, 0x11); fill_pat(y, clen, 0x77); x[0] |= 0x01; }
    cb_head(v, 5, 5);
    cb_int(v, 1);  cb_int(v, 2);
    cb_int(v, 3);  cb_int(v, alg);
    cb_int(v, -1); cb_int(v, crv);
    cb_int(v, -2); cb_bstr(v, x, clen);
    cb_int(v, -3); cb_bstr(v, y, clen);
}
/* {1:3, 3:alg, -1:n, -2:e} */
static void cose_rsa(vec *v, long long alg, size_t nlen) {
    BYTE n[512]; fill_pat(n, nlen, 0x33); n[0] |= 0x80; n[nlen - 1] |= 1;
    static const BYTE e[3] = { 1, 0, 1 };
    cb_head(v, 5, 4);
    cb_int(v, 1);  cb_int(v, 3);
    cb_int(v, 3);  cb_int(v, alg);
    cb_int(v, -1); cb_bstr(v, n, nlen);
    cb_int(v, -2); cb_bstr(v, e, 3);
}
/* {1:1, 3:-8, -1:6, -2:x} */
static void cose_okp(vec *v) {
    BYTE x[32]; fill_pat(x, 32, 0x21);
    cb_head(v, 5, 4);
    cb_int(v, 1);  cb_int(v, 1);
    cb_int(v, 3);  cb_int(v, -8);
    cb_int(v, -1); cb_int(v, 6);
    cb_int(v, -2); cb_bstr(v, x, 32);
}

typedef struct { const char *name; long long alg; const wchar_t *wname; void (*mk)(vec *); } keycase;
static void mk_es256(vec *v) { cose_ec(v, -7, 1, 32, 1); }
static void mk_es384(vec *v) { cose_ec(v, -35, 2, 48, 0); }
static void mk_es512(vec *v) { cose_ec(v, -36, 3, 66, 0); }
static void mk_rs256(vec *v) { cose_rsa(v, -257, 256); }
static void mk_rs384(vec *v) { cose_rsa(v, -258, 256); }
static void mk_rs512(vec *v) { cose_rsa(v, -259, 256); }
static void mk_ps256(vec *v) { cose_rsa(v, -37, 256); }
static void mk_ps384(vec *v) { cose_rsa(v, -38, 384); }
static void mk_ps512(vec *v) { cose_rsa(v, -39, 512); }
static void mk_rs1(vec *v)   { cose_rsa(v, -65535, 256); }
static void mk_ecdh(vec *v)  { cose_ec(v, -25, 1, 32, 1); }
static void mk_eddsa(vec *v) { cose_okp(v); }
static const keycase KEYS[] = {
    { "ES256", -7,     L"ES256",   mk_es256 },
    { "ES384", -35,    L"ES384",   mk_es384 },
    { "ES512", -36,    L"ES512",   mk_es512 },
    { "RS256", -257,   L"RS256",   mk_rs256 },
    { "RS384", -258,   L"RS384",   mk_rs384 },
    { "RS512", -259,   L"RS512",   mk_rs512 },
    { "PS256", -37,    L"PS256",   mk_ps256 },
    { "PS384", -38,    L"PS384",   mk_ps384 },
    { "PS512", -39,    L"PS512",   mk_ps512 },
    { "RS1",   -65535, L"RS1",     mk_rs1 },
    { "ECDH256", -25,  L"ECDH256", mk_ecdh },
    { "EdDSA", -8,     NULL,       mk_eddsa },
};
#define NKEYS ((int)(sizeof(KEYS) / sizeof(KEYS[0])))
enum { K_ES256, K_ES384, K_ES512, K_RS256, K_RS384, K_RS512, K_PS256, K_PS384, K_PS512, K_RS1, K_ECDH, K_EDDSA };

/* ---- authenticator data builders ---------------------------------------- */
static void ad_header(vec *v, BYTE flags, DWORD sc) {
    BYTE h[32]; for (int i = 0; i < 32; i++) h[i] = (BYTE)(i * 3 + 1);
    v_put(v, h, 32); v_u8(v, flags); v_be32(v, sc);
}
static void cred_fill(BYTE *p, size_t n, unsigned seed) { for (size_t i = 0; i < n; i++) p[i] = (BYTE)(seed + i * 13u + (i >> 8)); }
/* aaguid | BE16 lenField | ncred credential bytes (lenField may lie) */
static void ad_att(vec *v, unsigned lenField, size_t ncred, unsigned seed) {
    BYTE g[16]; for (int i = 0; i < 16; i++) g[i] = (BYTE)(0xA0 + i);
    v_put(v, g, 16); v_be16(v, lenField);
    BYTE *c = (BYTE *)malloc(ncred ? ncred : 1); cred_fill(c, ncred, seed); v_put(v, c, ncred); free(c);
}
static void ext_valid(vec *v) { cb_head(v, 5, 1); cb_tstr(v, "credProtect"); cb_int(v, 2); }
/* Full buffer: header, optional attested data with the given key, optional valid extensions. */
static void ad_full(vec *v, BYTE flags, DWORD sc, int key, unsigned credlen, int ext) {
    v_init(v); ad_header(v, flags, sc);
    if (key >= 0) { ad_att(v, credlen, credlen, 0x40); KEYS[key].mk(v); }
    if (ext) ext_valid(v);
}
/* header + attested data + arbitrary raw COSE bytes */
static void ad_raw(vec *v, BYTE flags, unsigned credlen, const char *cosehex, int ext) {
    v_init(v); ad_header(v, flags, 0x01020304); ad_att(v, credlen, credlen, 0x40);
    v_hex(v, cosehex); if (ext) ext_valid(v);
}

/* ---- guard-page placement: the buffer ends exactly at a PAGE_NOACCESS page ---- */
typedef struct { BYTE *base; } gbuf;
static const BYTE *g_place(gbuf *g, const void *src, size_t n) {
    size_t pages = (n + 4095) / 4096 + 1; if (n == 0) pages = 2;
    g->base = (BYTE *)VirtualAlloc(NULL, pages * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g->base) return NULL;
    DWORD old; VirtualProtect(g->base + (pages - 1) * 4096, 4096, PAGE_NOACCESS, &old);
    BYTE *p = g->base + (pages - 1) * 4096 - n;
    memset(g->base, 0xCC, (size_t)(p - g->base));
    if (n) memcpy(p, src, n);
    return p;
}
static void g_free(gbuf *g) { if (g->base) VirtualFree(g->base, 0, MEM_RELEASE); g->base = NULL; }

typedef struct { HRESULT hr; BYTE fl; DWORD sc; } pres;
/* Call Parse on a guarded copy of (p,n). Outputs are pre-set to sentinels. */
static pres acd_parse(const void *p, size_t n) {
    pres r; r.fl = SENT_FL; r.sc = SENT_SC; r.hr = (HRESULT)0xCAFEF00D;
    gbuf g; const BYTE *q = g_place(&g, p, n);
    if (!q) return r;
    r.hr = UN(WebAuthNCtapParseAuthenticatorData)((DWORD)n, q, &r.fl, &r.sc);
    g_free(&g);
    return r;
}
typedef struct { HRESULT hr; DWORD cb, off; } cres;
static cres acd_credid(const void *p, size_t n) {
    cres r; r.cb = SENT_CB; r.off = SENT_OFF; r.hr = (HRESULT)0xCAFEF00D;
    gbuf g; const BYTE *q = g_place(&g, p, n);
    if (!q) return r;
    r.hr = UN(WebAuthNGetCredentialIdFromAuthenticatorData)((DWORD)n, q, &r.cb, &r.off);
    g_free(&g);
    return r;
}
/* Expect Parse failure with E_INVALID_DATA and zeroed outputs. */
static void expect_parse_fail(const void *p, size_t n, const char *what) {
    pres r = acd_parse(p, n);
    t_check(HRV(r.hr) == ACD_E_INVALID_DATA, __FILE__, __LINE__, what, "parse hr=0x%08lx n=%zu", HRV(r.hr), n);
    t_check(r.fl == 0 && r.sc == 0, __FILE__, __LINE__, what, "outputs not zeroed fl=%02x sc=%08lx n=%zu", r.fl, r.sc, n);
}
static void expect_parse_ok(const void *p, size_t n, BYTE fl, DWORD sc, const char *what) {
    pres r = acd_parse(p, n);
    t_check(HRV(r.hr) == 0, __FILE__, __LINE__, what, "parse hr=0x%08lx n=%zu", HRV(r.hr), n);
    t_check(r.fl == fl && r.sc == sc, __FILE__, __LINE__, what, "outputs fl=%02x sc=%08lx want %02x %08lx", r.fl, r.sc, fl, sc);
}
static void expect_cred_fail(const void *p, size_t n, const char *what) {
    cres r = acd_credid(p, n);
    t_check(HRV(r.hr) == ACD_E_INVALID_DATA, __FILE__, __LINE__, what, "credid hr=0x%08lx n=%zu", HRV(r.hr), n);
    t_check(r.cb == 0 && r.off == 0, __FILE__, __LINE__, what, "outputs not zeroed cb=%lu off=%lu n=%zu", r.cb, r.off, n);
}
#define NEED_ALL() do { REQUIRE(UN(WebAuthNCtapParseAuthenticatorData)); REQUIRE(UN(WebAuthNGetCredentialIdFromAuthenticatorData)); } while (0)
#endif
