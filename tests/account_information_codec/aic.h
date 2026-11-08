/* Shared declarations and helpers for the account-information codec tests.
 *
 * Public surface (webauthn.dll):
 *   HRESULT WebAuthNEncodeAccountInformation(const WEBAUTHN_ACCOUNT_INFORMATION *pAcct,
 *                                            DWORD *pcbEncoded, PBYTE *ppbEncoded);
 *   HRESULT WebAuthNDecodeAccountInformation(DWORD cbEncoded, const BYTE *pbEncoded,
 *                                            WEBAUTHN_ACCOUNT_INFORMATION **ppAcct);
 *   void    WebAuthNFreeEncodedAccountInformation(PVOID);
 *   void    WebAuthNFreeDecodedAccountInformation(PVOID);
 *
 * Wire format (definite-length CBOR map, 3 entries, canonical order produced by the encoder):
 *   { 1: 1, 2: { "id": tstr, "icon": tstr, "name": tstr },
 *           3: { "id": bstr, "icon": tstr, "name": tstr, "displayName": tstr } }
 * Empty/NULL members are omitted from the sub-maps.
 *
 * Error mapping (HRESULT) observed in the decompilation of the codec error translator:
 *   invalid data / limits / bad UTF            0x8007000D
 *   unexpected end of input                    0x8007044C
 *   wrong CBOR type                            0x8007070C
 *   indefinite-length top-level map            0x80070018
 */
#ifndef AIC_H
#define AIC_H
#include "t.h"
#include <stdlib.h>

typedef struct { DWORD dwVersion; PCWSTR pwszId; PCWSTR pwszName; PCWSTR pwszIcon; } AIC_RP;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszName; PCWSTR pwszIcon; PCWSTR pwszDisplayName; } AIC_USER;
typedef struct { DWORD dwVersion; AIC_RP *pRp; AIC_USER *pUser; } AIC_ACCT;

_Static_assert(sizeof(AIC_RP) == 0x20, "rp size");
_Static_assert(sizeof(AIC_USER) == 0x28, "user size");
_Static_assert(sizeof(AIC_ACCT) == 0x18, "acct size");
_Static_assert(offsetof(AIC_RP, pwszId) == 8 && offsetof(AIC_RP, pwszName) == 0x10 && offsetof(AIC_RP, pwszIcon) == 0x18, "rp layout");
_Static_assert(offsetof(AIC_USER, cbId) == 4 && offsetof(AIC_USER, pbId) == 8 && offsetof(AIC_USER, pwszName) == 0x10 &&
               offsetof(AIC_USER, pwszIcon) == 0x18 && offsetof(AIC_USER, pwszDisplayName) == 0x20, "user layout");
_Static_assert(offsetof(AIC_ACCT, pRp) == 8 && offsetof(AIC_ACCT, pUser) == 0x10, "acct layout");

UDECL(HRESULT, WebAuthNEncodeAccountInformation, (const AIC_ACCT *, DWORD *, PBYTE *));
UDECL(HRESULT, WebAuthNDecodeAccountInformation, (DWORD, const BYTE *, AIC_ACCT **));
UDECL(void,    WebAuthNFreeEncodedAccountInformation, (PVOID));
UDECL(void,    WebAuthNFreeDecodedAccountInformation, (PVOID));

#define AIC_REQ() do { \
    REQUIRE(UN(WebAuthNEncodeAccountInformation)); REQUIRE(UN(WebAuthNDecodeAccountInformation)); \
    REQUIRE(UN(WebAuthNFreeEncodedAccountInformation)); REQUIRE(UN(WebAuthNFreeDecodedAccountInformation)); } while (0)

#define HR_INVALID_DATA  ((HRESULT)0x8007000DL)   /* ERROR_INVALID_DATA */
#define HR_NO_MEDIA      ((HRESULT)0x8007044CL)   /* unexpected end of CBOR input */
#define HR_BAD_TYPE      ((HRESULT)0x8007070CL)   /* ERROR_INVALID_DATATYPE */
#define HR_BAD_LENGTH    ((HRESULT)0x80070018L)   /* ERROR_BAD_LENGTH: indefinite top-level map */
#define HR_NOMEM         ((HRESULT)0x8007000EL)

#define HR_EQ(got, want) t_check((HRESULT)(got) == (HRESULT)(want), __FILE__, __LINE__, #got " == " #want, \
                                 "got 0x%08lx want 0x%08lx", (unsigned long)(got), (unsigned long)(want))

#define RPV(v, i, n, c) { v, i, n, c }
#define USV(v, cb, pb, n, i, d) { v, cb, pb, n, i, d }

#define SENT_PTR ((void *)(ULONG_PTR)0xA5A5A5A5A5A5A5A5ull)
#define SENT_CB  0x5A5A5A5Au

/* ---------------------------------------------------------------- call wrappers ---- */
static HRESULT aic_enc(const AIC_ACCT *a, DWORD *cb, PBYTE *pb) { return UN(WebAuthNEncodeAccountInformation)(a, cb, pb); }
static void aic_free_enc(PVOID p) { UN(WebAuthNFreeEncodedAccountInformation)(p); }
static void aic_free_dec(PVOID p) { UN(WebAuthNFreeDecodedAccountInformation)(p); }

/* ---------------------------------------------------------------- guard-page buffers ---- */
typedef struct { BYTE *base; SIZE_T total; BYTE *p; } GB;
static int gb_make(GB *g, const void *d, size_t n, int tail) {
    const SIZE_T pg = 4096; SIZE_T dp = (n + pg - 1) / pg; DWORD old;
    if (!dp) dp = 1;
    g->total = (dp + 2) * pg;
    g->base = (BYTE *)VirtualAlloc(NULL, g->total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g->base) return 0;
    VirtualProtect(g->base, pg, PAGE_NOACCESS, &old);
    VirtualProtect(g->base + (dp + 1) * pg, pg, PAGE_NOACCESS, &old);
    memset(g->base + pg, 0xCC, dp * pg);
    g->p = tail ? g->base + pg + dp * pg - n : g->base + pg;
    if (n) memcpy(g->p, d, n);
    return 1;
}
static void gb_free(GB *g) { if (g->base) VirtualFree(g->base, 0, MEM_RELEASE); g->base = NULL; }

/* Decode from a guard-page-protected copy of the input (tail=1: input ends at the last byte before a
 * PAGE_NOACCESS page; tail=0: input starts right after one). The copy is released before returning, so a
 * result that still referenced the input would fault later. */
static HRESULT aic_dec_g(const void *d, size_t n, int tail, AIC_ACCT **out) {
    GB g; HRESULT hr;
    if (!gb_make(&g, d, n, tail)) { t_note("VirtualAlloc failed"); return E_FAIL; }
    hr = UN(WebAuthNDecodeAccountInformation)((DWORD)n, g.p, out);
    gb_free(&g);
    return hr;
}

/* ---------------------------------------------------------------- CBOR builder ---- */
typedef struct { BYTE *d; size_t n, cap; } B;
static void b_init(B *b, size_t cap) { b->d = (BYTE *)malloc(cap); b->n = 0; b->cap = cap; }
static void b_done(B *b) { free(b->d); b->d = NULL; }
static void b_put(B *b, const void *p, size_t n) { if (b->n + n <= b->cap) { memcpy(b->d + b->n, p, n); b->n += n; } }
static void b_byte(B *b, unsigned c) { BYTE x = (BYTE)c; b_put(b, &x, 1); }
static void b_head(B *b, int major, unsigned long long v) {
    BYTE h[9]; int m = major << 5, i;
    if (v < 24) { b_byte(b, m | (int)v); return; }
    if (v < 0x100) { h[0] = (BYTE)(m | 24); h[1] = (BYTE)v; b_put(b, h, 2); return; }
    if (v < 0x10000) { h[0] = (BYTE)(m | 25); h[1] = (BYTE)(v >> 8); h[2] = (BYTE)v; b_put(b, h, 3); return; }
    if (v < 0x100000000ull) { h[0] = (BYTE)(m | 26); for (i = 0; i < 4; i++) h[1 + i] = (BYTE)(v >> (24 - 8 * i)); b_put(b, h, 5); return; }
    h[0] = (BYTE)(m | 27); for (i = 0; i < 8; i++) h[1 + i] = (BYTE)(v >> (56 - 8 * i)); b_put(b, h, 9);
}
static void b_uint(B *b, unsigned long long v) { b_head(b, 0, v); }
static void b_text(B *b, const char *s) { size_t n = strlen(s); b_head(b, 3, n); b_put(b, s, n); }
static void b_textn(B *b, const void *s, size_t n) { b_head(b, 3, n); b_put(b, s, n); }
static void b_bytes(B *b, const void *p, size_t n) { b_head(b, 2, n); b_put(b, p, n); }
static void b_rep(B *b, int c, size_t n) { while (n--) b_byte(b, c); }
static void b_textrep(B *b, int c, size_t n) { b_head(b, 3, n); b_rep(b, c, n); }

/* Spec of a decoded/encoded account for hand-built blobs (UTF-8 strings, NULL = key omitted). */
typedef struct {
    int ver;                       /* <0: omit key 1 */
    int has_rp, has_user;
    const char *rid, *rname, *ricon;
    const void *uid; size_t ucb; const char *uname, *uicon, *udisp;
    int user_first;                /* emit key 3 before key 2 */
} SPEC;
static void b_rp(B *b, const SPEC *s) {
    unsigned n = (s->rid != NULL) + (s->rname != NULL) + (s->ricon != NULL);
    b_head(b, 5, n);
    if (s->rid) { b_text(b, "id"); b_text(b, s->rid); }
    if (s->ricon) { b_text(b, "icon"); b_text(b, s->ricon); }
    if (s->rname) { b_text(b, "name"); b_text(b, s->rname); }
}
static void b_user(B *b, const SPEC *s) {
    unsigned n = (s->uid != NULL) + (s->uname != NULL) + (s->uicon != NULL) + (s->udisp != NULL);
    b_head(b, 5, n);
    if (s->uid) { b_text(b, "id"); b_bytes(b, s->uid, s->ucb); }
    if (s->uicon) { b_text(b, "icon"); b_text(b, s->uicon); }
    if (s->uname) { b_text(b, "name"); b_text(b, s->uname); }
    if (s->udisp) { b_text(b, "displayName"); b_text(b, s->udisp); }
}
static void b_acct(B *b, const SPEC *s) {
    unsigned n = (s->ver >= 0) + (s->has_rp != 0) + (s->has_user != 0);
    b_head(b, 5, n);
    if (s->ver >= 0) { b_uint(b, 1); b_uint(b, (unsigned)s->ver); }
    if (s->user_first) {
        if (s->has_user) { b_uint(b, 3); b_user(b, s); }
        if (s->has_rp) { b_uint(b, 2); b_rp(b, s); }
    } else {
        if (s->has_rp) { b_uint(b, 2); b_rp(b, s); }
        if (s->has_user) { b_uint(b, 3); b_user(b, s); }
    }
}

/* ---------------------------------------------------------------- string helpers ---- */
static const WCHAR *aic_w(const char *u8) {
    static WCHAR ring[8][20000]; static int k;
    WCHAR *w = ring[k++ & 7];
    int n = MultiByteToWideChar(CP_UTF8, 0, u8, -1, w, 20000);
    if (n <= 0) w[0] = 0;
    return w;
}
/* got must be NULL when want is NULL, else equal to want (UTF-8). */
static int aic_streq(PCWSTR got, const char *want) {
    if (!want) return got == NULL;
    if (!got) return 0;
    return lstrcmpW(got, aic_w(want)) == 0;
}
static void hexdump(const char *tag, const BYTE *p, size_t n) {
    char line[600]; size_t i, o = 0;
    for (i = 0; i < n && o < sizeof line - 4; i++) o += snprintf(line + o, sizeof line - o, "%02X ", p[i]);
    line[o] = 0; t_note("%s (%u bytes): %s", tag, (unsigned)n, line);
}

/* Verify a decoded block: every pointer lies inside the single LocalAlloc'd block, strings are terminated. */
static int aic_in_block(const void *blk, size_t sz, const void *p, size_t bytes) {
    const BYTE *b = (const BYTE *)blk, *q = (const BYTE *)p;
    return q >= b && q + bytes <= b + sz;
}
static void aic_check_block(AIC_ACCT *a) {
    SIZE_T sz = LocalSize(a);
    CHECK(sz >= sizeof(AIC_ACCT) && sz != (SIZE_T)-1);
    if (!a->pRp || !a->pUser) return;
    CHECK(aic_in_block(a, sz, a->pRp, sizeof(AIC_RP)));
    CHECK(aic_in_block(a, sz, a->pUser, sizeof(AIC_USER)));
    if (a->pRp->pwszId) CHECK(aic_in_block(a, sz, a->pRp->pwszId, (lstrlenW(a->pRp->pwszId) + 1) * 2));
    if (a->pRp->pwszName) CHECK(aic_in_block(a, sz, a->pRp->pwszName, (lstrlenW(a->pRp->pwszName) + 1) * 2));
    if (a->pRp->pwszIcon) CHECK(aic_in_block(a, sz, a->pRp->pwszIcon, (lstrlenW(a->pRp->pwszIcon) + 1) * 2));
    if (a->pUser->pbId) CHECK(aic_in_block(a, sz, a->pUser->pbId, a->pUser->cbId));
    if (a->pUser->pwszName) CHECK(aic_in_block(a, sz, a->pUser->pwszName, (lstrlenW(a->pUser->pwszName) + 1) * 2));
    if (a->pUser->pwszIcon) CHECK(aic_in_block(a, sz, a->pUser->pwszIcon, (lstrlenW(a->pUser->pwszIcon) + 1) * 2));
    if (a->pUser->pwszDisplayName) CHECK(aic_in_block(a, sz, a->pUser->pwszDisplayName, (lstrlenW(a->pUser->pwszDisplayName) + 1) * 2));
}

/* Decode `d` (both guard placements) and require exactly `want` (0 = success is NOT checked here). On failure
 * the output pointer must be left untouched. Returns the successful result of the tail=1 run (caller frees) or NULL. */
static AIC_ACCT *aic_expect_dec(const void *d, size_t n, HRESULT want, const char *tag) {
    AIC_ACCT *keep = NULL; int tail;
    for (tail = 1; tail >= 0; tail--) {
        AIC_ACCT *out = (AIC_ACCT *)SENT_PTR;
        HRESULT hr = aic_dec_g(d, n, tail, &out);
        t_check(hr == want, __FILE__, __LINE__, tag, "tail=%d got 0x%08lx want 0x%08lx", tail, (unsigned long)hr, (unsigned long)want);
        if (hr != 0) {
            t_check(out == SENT_PTR, __FILE__, __LINE__, "output untouched on failure", "tag=%s tail=%d", tag, tail);
        } else if (out != SENT_PTR && out != NULL) {
            aic_check_block(out);
            if (tail && !keep) keep = out; else aic_free_dec(out);
        } else CHECK(out != SENT_PTR && out != NULL);
    }
    return keep;
}
#define EXPECT_DEC(bytes, n, hr) aic_expect_dec((bytes), (n), (hr), #hr)

/* Encode and compare against exact expected bytes. */
static void aic_enc_expect(const AIC_ACCT *a, const BYTE *e, size_t en) {
    DWORD cb = SENT_CB; PBYTE pb = (PBYTE)SENT_PTR;
    HRESULT hr = aic_enc(a, &cb, &pb);
    HR_EQ(hr, 0);
    if (hr != 0) return;
    CHECK(pb != NULL && pb != SENT_PTR);
    EXPECT_EQ(cb, en);
    if (pb && cb == en) {
        int same = memcmp(pb, e, en) == 0;
        CHECK(same);
        if (!same) { hexdump("expected", e, en); hexdump("actual", pb, cb); }
        SIZE_T ls = LocalSize(pb);
        CHECK(ls != (SIZE_T)-1 && ls >= cb);
    }
    if (pb) aic_free_enc(pb);
}

/* Compare a decoded account to an input account (fields NULL/empty in the input must come back NULL). */
static int wnorm_eq(PCWSTR in, PCWSTR out) {
    if (!in || !*in) return out == NULL;
    return out != NULL && lstrcmpW(in, out) == 0;
}
static void aic_cmp(const AIC_ACCT *in, const AIC_ACCT *out) {
    CHECK(out != NULL); if (!out) return;
    EXPECT_EQ(out->dwVersion, 1);
    CHECK(out->pRp != NULL && out->pUser != NULL);
    if (!out->pRp || !out->pUser) return;
    EXPECT_EQ(out->pRp->dwVersion, 1);
    EXPECT_EQ(out->pUser->dwVersion, 1);
    CHECK(wnorm_eq(in->pRp->pwszId, out->pRp->pwszId));
    CHECK(wnorm_eq(in->pRp->pwszName, out->pRp->pwszName));
    CHECK(wnorm_eq(in->pRp->pwszIcon, out->pRp->pwszIcon));
    CHECK(wnorm_eq(in->pUser->pwszName, out->pUser->pwszName));
    CHECK(wnorm_eq(in->pUser->pwszIcon, out->pUser->pwszIcon));
    CHECK(wnorm_eq(in->pUser->pwszDisplayName, out->pUser->pwszDisplayName));
    if (in->pUser->cbId == 0) { EXPECT_EQ(out->pUser->cbId, 0); CHECK(out->pUser->pbId == NULL); }
    else {
        EXPECT_EQ(out->pUser->cbId, in->pUser->cbId);
        CHECK(out->pUser->pbId != NULL && out->pUser->cbId == in->pUser->cbId &&
              memcmp(out->pUser->pbId, in->pUser->pbId, in->pUser->cbId) == 0);
    }
}
/* encode -> decode -> compare -> free. Decode only succeeds when the RP id is non-empty. */
static void aic_roundtrip(const AIC_ACCT *in) {
    DWORD cb = 0; PBYTE pb = NULL; AIC_ACCT *out = NULL;
    HRESULT hr = aic_enc(in, &cb, &pb);
    HR_EQ(hr, 0);
    if (hr != 0 || !pb) return;
    int has_id = in->pRp->pwszId && *in->pRp->pwszId;
    out = (AIC_ACCT *)SENT_PTR;
    hr = aic_dec_g(pb, cb, 1, &out);
    if (has_id) {
        HR_EQ(hr, 0);
        if (hr == 0) { aic_check_block(out); aic_cmp(in, out); aic_free_dec(out); }
    } else {
        HR_EQ(hr, HR_INVALID_DATA);
        CHECK(out == SENT_PTR);
    }
    aic_free_enc(pb);
}
#endif
