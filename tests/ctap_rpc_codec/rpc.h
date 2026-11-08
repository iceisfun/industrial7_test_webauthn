/* ctap_rpc_codec: shared declarations and helpers.
 *
 * Covers the internal RPC (de)serialisation exports of webauthn.dll:
 *   I_WebAuthNCtapEncodeMakeCredentialRpcRequest   (ordinal 5)
 *   I_WebAuthNCtapEncodeGetAssertionRpcRequest     (ordinal 4)
 *   I_WebAuthNCtapDecodeMakeCredentialRpcResponse  (ordinal 3)
 *   I_WebAuthNCtapDecodeGetAssertionRpcResponse    (ordinal 2)
 *   WebAuthNCtapRpcGetCborCommand                  (ordinal 33)
 *   WebAuthNCtapRpcGetAssertionUserList            (ordinal 32)
 *   WebAuthNCtapRpcSelectGetAssertion              (ordinal 34)
 *
 * None of these are declared in any SDK header; prototypes were derived from the
 * Windows 10 reference decompilation and are declared here with UDECL.
 *
 * Wire format summary (derived from the reference decompilation):
 *   RPC request  = CBOR map with text keys:
 *       "command" uint, "flags" uint, "timeout" uint, "transactionId" bstr(16),
 *       optional "ticket" bstr, "request" bstr (first byte = CTAP command),
 *       optional "deviceInfoList" ...
 *   Device response envelope = CBOR map(3):
 *       "deviceInfo" map{ "providerType" text?, "providerName" text, ... },
 *       "status" uint, "response" bstr (first byte = CTAP status, then CBOR payload)
 */
#ifndef CRC_H
#define CRC_H
#include "t.h"
#include <psapi.h>

/* ---- return codes ------------------------------------------------------- */
#define HR_INVALID_PARAM     ((LONG)0x80090027)   /* NTE_INVALID_PARAMETER */
#define HR_NOT_FOUND         ((LONG)0x80090011)   /* NTE_NOT_FOUND */
#define HR_NO_MATCH          ((LONG)0x80090347)
#define HR_INVALID_DATA      ((LONG)0x8007000D)   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA) */
#define HR_BAD_LENGTH        ((LONG)0x80070018)   /* HRESULT_FROM_WIN32(ERROR_BAD_LENGTH) */
#define HR_CBOR_EMPTY        ((LONG)0x8007044C)   /* NULL/zero/oversized input to the CBOR layer */

/* ---- prototypes (declared by hand; x64 has a single calling convention) --- */
typedef struct { DWORD dwVersion; LPCWSTR pwszId; LPCWSTR pwszName; LPCWSTR pwszIcon; } CRC_RP;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; LPCWSTR pwszName; LPCWSTR pwszIcon; LPCWSTR pwszDisplayName; } CRC_USER;
typedef struct { DWORD dwVersion; LPCWSTR pwszCredentialType; LONG lAlg; } CRC_COSE_PARAM;
typedef struct { DWORD cCredentialParameters; CRC_COSE_PARAM *pCredentialParameters; } CRC_COSE_PARAMS;
typedef struct { DWORD dwVersion; DWORD cbClientDataJSON; PBYTE pbClientDataJSON; LPCWSTR pwszHashAlgId; } CRC_CLIENTDATA;

#ifndef _MSC_VER
_Static_assert(sizeof(CRC_RP) == 32, "rp");
_Static_assert(sizeof(CRC_USER) == 40, "user");
_Static_assert(sizeof(CRC_COSE_PARAM) == 24, "cose");
_Static_assert(sizeof(CRC_CLIENTDATA) == 24, "cd");
_Static_assert(offsetof(CRC_USER, pbId) == 8, "user.pbId");
_Static_assert(offsetof(CRC_CLIENTDATA, pwszHashAlgId) == 16, "cd.hash");
#endif

UDECL(LONG, I_WebAuthNCtapEncodeMakeCredentialRpcRequest,
      (GUID *txid, ULONG cmd, ULONG flags, ULONG extra, const CRC_RP *rp, const CRC_USER *user,
       const CRC_COSE_PARAMS *params, const CRC_CLIENTDATA *cd, const void *opts, const void *devinfo,
       void *prot, void *rpcreq, ULONG *cbOut, BYTE **pbOut));
UDECL(LONG, I_WebAuthNCtapEncodeGetAssertionRpcRequest,
      (GUID *txid, ULONG cmd, ULONG flags, ULONG extra, LPCWSTR rpid, const CRC_CLIENTDATA *cd,
       const void *opts, const void *devinfo, void *prot, ULONG cbX, const BYTE *pbX, void *rpcreq,
       ULONG *cbOut, BYTE **pbOut));
UDECL(LONG, I_WebAuthNCtapDecodeMakeCredentialRpcResponse,
      (GUID *txid, ULONG cb, BYTE *pb, ULONG conveyance, void **ppDevResp, void **ppAttestation));
UDECL(LONG, I_WebAuthNCtapDecodeGetAssertionRpcResponse,
      (GUID *txid, ULONG cb, BYTE *pb, int allowDefault, ULONG cbSel, const BYTE *pbSel,
       void **ppDevResp, void **ppAssertion));
UDECL(ULONGLONG, WebAuthNCtapRpcGetCborCommand, (ULONG cb, const BYTE *pb, BYTE *pCmd));
UDECL(ULONG, WebAuthNCtapRpcGetAssertionUserList,
      (ULONG cbReq, const BYTE *pbReq, ULONG cbDev, const BYTE *pbDev, WCHAR **ppRpId, void **ppUsers));
UDECL(ULONGLONG, WebAuthNCtapRpcSelectGetAssertion,
      (ULONG cbDev, const BYTE *pbDev, ULONG index, ULONG *pcbOut, BYTE **ppbOut));
UDECL(void, WebAuthNFreeCredentialAttestation, (void *p));
UDECL(void, WebAuthNFreeAssertion, (void *p));
typedef void (WINAPI *CoTaskMemFree_pfn)(void *);
static inline CoTaskMemFree_pfn crc_cotaskfree(void) {
    return (CoTaskMemFree_pfn)t_proc_in("ole32.dll", "CoTaskMemFree");
}

/* ---- growable byte buffer + CBOR builder -------------------------------- */
typedef struct { BYTE b[16384]; size_t n; } cbuf;
static inline void cb_put(cbuf *c, const void *p, size_t n) { if (c->n + n <= sizeof c->b) { memcpy(c->b + c->n, p, n); c->n += n; } }
static inline void cb_byte(cbuf *c, unsigned v) { BYTE x = (BYTE)v; cb_put(c, &x, 1); }
static inline void cb_head(cbuf *c, int major, unsigned long long v) {
    BYTE m = (BYTE)(major << 5);
    if (v < 24) cb_byte(c, m | (unsigned)v);
    else if (v < 0x100) { cb_byte(c, m | 24); cb_byte(c, (unsigned)v); }
    else if (v < 0x10000) { cb_byte(c, m | 25); cb_byte(c, (unsigned)(v >> 8)); cb_byte(c, (unsigned)v); }
    else if (v < 0x100000000ULL) { cb_byte(c, m | 26); for (int i = 3; i >= 0; i--) cb_byte(c, (unsigned)(v >> (8 * i))); }
    else { cb_byte(c, m | 27); for (int i = 7; i >= 0; i--) cb_byte(c, (unsigned)(v >> (8 * i))); }
}
static inline void cb_uint(cbuf *c, unsigned long long v) { cb_head(c, 0, v); }
static inline void cb_nint(cbuf *c, long long v) { cb_head(c, 1, (unsigned long long)(-1 - v)); }
static inline void cb_bstr(cbuf *c, const void *p, size_t n) { cb_head(c, 2, n); cb_put(c, p, n); }
static inline void cb_tstr(cbuf *c, const char *s) { size_t n = strlen(s); cb_head(c, 3, n); cb_put(c, s, n); }
static inline void cb_map(cbuf *c, unsigned n) { cb_head(c, 5, n); }
static inline void cb_arr(cbuf *c, unsigned n) { cb_head(c, 4, n); }

/* ---- minimal CBOR reader ------------------------------------------------ */
typedef struct { int major; unsigned long long val; const BYTE *data; size_t hlen; } citem;
/* Reads one head at p[*pos]; for bstr/tstr data points at the payload and *pos is advanced past it;
 * for other majors *pos is advanced past the head only. Returns 0 on success, -1 on truncation. */
static inline int cr_head(const BYTE *p, size_t n, size_t *pos, citem *it) {
    if (*pos >= n) return -1;
    BYTE b = p[(*pos)++];
    it->major = b >> 5; it->data = NULL; it->hlen = 0;
    unsigned ai = b & 31;
    unsigned long long v = ai;
    if (ai >= 24 && ai <= 27) {
        unsigned k = 1u << (ai - 24);
        if (*pos + k > n) return -1;
        v = 0; for (unsigned i = 0; i < k; i++) v = (v << 8) | p[(*pos)++];
    } else if (ai > 27) return -1;
    it->val = v;
    if (it->major == 2 || it->major == 3) {
        if (v > n - *pos) return -1;
        it->data = p + *pos; it->hlen = (size_t)v; *pos += (size_t)v;
    }
    return 0;
}
/* Skip one complete data item. */
static inline int cr_skip(const BYTE *p, size_t n, size_t *pos) {
    citem it; if (cr_head(p, n, pos, &it)) return -1;
    if (it.major == 4) { for (unsigned long long i = 0; i < it.val; i++) if (cr_skip(p, n, pos)) return -1; }
    else if (it.major == 5) { for (unsigned long long i = 0; i < it.val; i++) if (cr_skip(p, n, pos) || cr_skip(p, n, pos)) return -1; }
    else if (it.major == 6) return cr_skip(p, n, pos);
    return 0;
}
/* Top-level map with text keys: find value by key; returns 1 and the value's [offset,len) of the raw item. */
static inline int cr_text_find(const BYTE *p, size_t n, const char *key, size_t *voff, size_t *vlen) {
    size_t pos = 0; citem m; if (cr_head(p, n, &pos, &m) || m.major != 5) return 0;
    for (unsigned long long i = 0; i < m.val; i++) {
        citem k; if (cr_head(p, n, &pos, &k) || k.major != 3) return 0;
        size_t s = pos; if (cr_skip(p, n, &pos)) return 0;
        if (k.hlen == strlen(key) && !memcmp(k.data, key, k.hlen)) { *voff = s; *vlen = pos - s; return 1; }
    }
    return 0;
}
/* Same for an integer-keyed (unsigned) map. */
static inline int cr_int_find(const BYTE *p, size_t n, unsigned key, size_t *voff, size_t *vlen) {
    size_t pos = 0; citem m; if (cr_head(p, n, &pos, &m) || m.major != 5) return 0;
    for (unsigned long long i = 0; i < m.val; i++) {
        citem k; if (cr_head(p, n, &pos, &k) || k.major != 0) return 0;
        size_t s = pos; if (cr_skip(p, n, &pos)) return 0;
        if (k.val == key) { *voff = s; *vlen = pos - s; return 1; }
    }
    return 0;
}
/* Fetch the payload of a bstr/tstr value of a text-keyed map. */
static inline int cr_text_bytes(const BYTE *p, size_t n, const char *key, const BYTE **out, size_t *olen) {
    size_t o, l; if (!cr_text_find(p, n, key, &o, &l)) return 0;
    size_t pos = o; citem it; if (cr_head(p, n, &pos, &it) || (it.major != 2 && it.major != 3)) return 0;
    *out = it.data; *olen = it.hlen; return 1;
}
static inline int cr_text_uint(const BYTE *p, size_t n, const char *key, unsigned long long *out) {
    size_t o, l; if (!cr_text_find(p, n, key, &o, &l)) return 0;
    size_t pos = o; citem it; if (cr_head(p, n, &pos, &it) || it.major != 0) return 0;
    *out = it.val; return 1;
}
/* Ordered list of the text keys of a top-level map, joined with ','. Returns map size or -1. */
static inline int cr_text_keys(const BYTE *p, size_t n, char *out, size_t cap, size_t *endpos) {
    size_t pos = 0; citem m; out[0] = 0;
    if (cr_head(p, n, &pos, &m) || m.major != 5) return -1;
    for (unsigned long long i = 0; i < m.val; i++) {
        citem k; if (cr_head(p, n, &pos, &k) || k.major != 3) return -1;
        if (strlen(out) + k.hlen + 2 < cap) { if (i) strcat(out, ","); strncat(out, (const char *)k.data, k.hlen); }
        if (cr_skip(p, n, &pos)) return -1;
    }
    if (endpos) *endpos = pos;
    return (int)m.val;
}
static inline int cr_int_keys(const BYTE *p, size_t n, char *out, size_t cap, size_t *endpos) {
    size_t pos = 0; citem m; out[0] = 0;
    if (cr_head(p, n, &pos, &m) || m.major != 5) return -1;
    for (unsigned long long i = 0; i < m.val; i++) {
        citem k; if (cr_head(p, n, &pos, &k) || k.major != 0) return -1;
        char t[24]; wsprintfA(t, i ? ",%u" : "%u", (unsigned)k.val);
        if (strlen(out) + strlen(t) + 1 < cap) strcat(out, t);
        if (cr_skip(p, n, &pos)) return -1;
    }
    if (endpos) *endpos = pos;
    return (int)m.val;
}

/* ---- SHA-256 (own implementation, used to predict the client data hash) ---- */
static inline void crc_sha256(const BYTE *d, size_t n, BYTE out[32]) {
    static const unsigned K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    unsigned h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t total = ((n + 9 + 63) / 64) * 64;
    BYTE *m = (BYTE *)calloc(1, total);
    memcpy(m, d, n); m[n] = 0x80;
    unsigned long long bits = (unsigned long long)n * 8;
    for (int i = 0; i < 8; i++) m[total - 1 - i] = (BYTE)(bits >> (8 * i));
#define ROR(x,k) (((x) >> (k)) | ((x) << (32 - (k))))
    for (size_t off = 0; off < total; off += 64) {
        unsigned w[64];
        for (int i = 0; i < 16; i++) w[i] = (unsigned)m[off+4*i] << 24 | (unsigned)m[off+4*i+1] << 16 | (unsigned)m[off+4*i+2] << 8 | m[off+4*i+3];
        for (int i = 16; i < 64; i++) {
            unsigned s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
            unsigned s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        unsigned a=h[0],b=h[1],c=h[2],dd=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            unsigned S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25), ch = (e & f) ^ (~e & g);
            unsigned t1 = hh + S1 + ch + K[i] + w[i];
            unsigned S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22), mj = (a & b) ^ (a & c) ^ (b & c);
            unsigned t2 = S0 + mj;
            hh = g; g = f; f = e; e = dd + t1; dd = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=dd;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
#undef ROR
    for (int i = 0; i < 8; i++) { out[4*i] = (BYTE)(h[i] >> 24); out[4*i+1] = (BYTE)(h[i] >> 16); out[4*i+2] = (BYTE)(h[i] >> 8); out[4*i+3] = (BYTE)h[i]; }
    free(m);
}

/* ---- fixtures ------------------------------------------------------------ */
static const GUID CRC_TXID = { 0x01020304, 0x0506, 0x0708, { 9, 10, 11, 12, 13, 14, 15, 16 } };
static const BYTE CRC_TXID_BYTES[16] = { 4,3,2,1, 6,5, 8,7, 9,10,11,12,13,14,15,16 };  /* in-memory GUID layout */
static const BYTE CRC_CLIENTDATA_JSON[] = "{\"type\":\"webauthn.create\",\"challenge\":\"AAAA\",\"origin\":\"https://example.com\"}";

/* A fully populated, valid make-credential argument set. */
typedef struct {
    CRC_RP rp; CRC_USER user; CRC_COSE_PARAM cp; CRC_COSE_PARAMS cps; CRC_CLIENTDATA cd;
    BYTE userid[8]; BYTE cdj[sizeof CRC_CLIENTDATA_JSON];
} mc_args;
static inline void mc_args_init(mc_args *a) {
    memset(a, 0, sizeof *a);
    memcpy(a->cdj, CRC_CLIENTDATA_JSON, sizeof a->cdj);
    for (int i = 0; i < 8; i++) a->userid[i] = (BYTE)(0xA0 + i);
    a->rp.dwVersion = 1; a->rp.pwszId = L"example.com"; a->rp.pwszName = L"Example";
    a->user.dwVersion = 1; a->user.cbId = 8; a->user.pbId = a->userid; a->user.pwszName = L"alice"; a->user.pwszDisplayName = L"Alice";
    a->cp.dwVersion = 1; a->cp.pwszCredentialType = L"public-key"; a->cp.lAlg = -7;
    a->cps.cCredentialParameters = 1; a->cps.pCredentialParameters = &a->cp;
    a->cd.dwVersion = 1; a->cd.cbClientDataJSON = sizeof CRC_CLIENTDATA_JSON - 1; a->cd.pbClientDataJSON = a->cdj; a->cd.pwszHashAlgId = L"SHA-256";
}
/* Call the make-credential encoder with output poisoning. */
typedef struct { LONG hr; ULONG cb; BYTE *pb; } enc_res;
static inline enc_res mc_encode(const mc_args *a, ULONG cmd, ULONG flags, ULONG extra, const void *opts, const void *devinfo, const GUID *txid) {
    enc_res r; static BYTE rq[0x200]; GUID g = txid ? *txid : CRC_TXID;
    memset(rq, 0, sizeof rq);
    r.cb = 0xDEADBEEF; r.pb = (BYTE *)(ULONG_PTR)0x1; /* poisoned: the function must reset both before validating */
    r.hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, cmd, flags, extra, &a->rp, &a->user, &a->cps, &a->cd, opts, devinfo, NULL, rq, &r.cb, &r.pb);
    return r;
}
/* get-assertion fixture */
static const BYTE CRC_GA_CLIENTDATA_JSON[] = "{\"type\":\"webauthn.get\",\"challenge\":\"BBBB\",\"origin\":\"https://example.com\"}";
typedef struct { CRC_CLIENTDATA cd; BYTE cdj[sizeof CRC_GA_CLIENTDATA_JSON]; } ga_args;
static inline void ga_args_init(ga_args *a) {
    memset(a, 0, sizeof *a);
    memcpy(a->cdj, CRC_GA_CLIENTDATA_JSON, sizeof a->cdj);
    a->cd.dwVersion = 1; a->cd.cbClientDataJSON = sizeof CRC_GA_CLIENTDATA_JSON - 1; a->cd.pbClientDataJSON = a->cdj; a->cd.pwszHashAlgId = L"SHA-256";
}
static inline enc_res ga_encode(const ga_args *a, LPCWSTR rpid, ULONG cmd, ULONG flags, ULONG extra, const void *opts, const void *devinfo, const GUID *txid) {
    enc_res r; static BYTE rq[0x200]; GUID g = txid ? *txid : CRC_TXID;
    memset(rq, 0, sizeof rq);
    r.cb = 0xDEADBEEF; r.pb = (BYTE *)(ULONG_PTR)0x1;
    r.hr = UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)(&g, cmd, flags, extra, rpid, &a->cd, opts, devinfo, NULL, 0, NULL, rq, &r.cb, &r.pb);
    return r;
}
static inline void enc_free(enc_res *r) { if (r->pb && r->pb != (BYTE *)(ULONG_PTR)1) LocalFree(r->pb); r->pb = NULL; }

/* Device info (_CTAPCBOR_DEVICE_INFO, 0x88 bytes). Field offsets from the reference decompilation. */
typedef struct { BYTE raw[0x88]; } devinfo_t;
static inline void devinfo_init(devinfo_t *d, LPCWSTR providerName) {
    memset(d, 0, sizeof *d);
    *(DWORD *)(d->raw + 0) = 1;
    *(LPCWSTR *)(d->raw + 0x10) = providerName;
}

/* RPC request map builder (what the encoders produce) */
static inline void rpc_request(cbuf *c, unsigned long long cmd, unsigned long long flags, unsigned long long timeout,
                               const BYTE *txid16, size_t txlen, const BYTE *req, size_t reqlen) {
    c->n = 0;
    cb_map(c, 4 + (req ? 1 : 0));
    cb_tstr(c, "command"); cb_uint(c, cmd);
    cb_tstr(c, "flags"); cb_uint(c, flags);
    cb_tstr(c, "timeout"); cb_uint(c, timeout);
    if (txid16) { cb_tstr(c, "transactionId"); cb_bstr(c, txid16, txlen); }
    else cb_tstr(c, "x");   /* placeholder to keep the map size stable */
    if (txid16 == NULL) cb_uint(c, 0);
    if (req) { cb_tstr(c, "request"); cb_bstr(c, req, reqlen); }
}
/* Device response envelope */
static inline void dev_info_map(cbuf *c, const char *providerName, const char *providerType) {
    cb_map(c, (providerName ? 1 : 0) + (providerType ? 1 : 0));
    if (providerType) { cb_tstr(c, "providerType"); cb_tstr(c, providerType); }
    if (providerName) { cb_tstr(c, "providerName"); cb_tstr(c, providerName); }
}
static inline void envelope(cbuf *c, unsigned long long status, const BYTE *resp, size_t resplen) {
    c->n = 0;
    cb_map(c, 3);
    cb_tstr(c, "deviceInfo"); dev_info_map(c, "TestProvider", "hid");
    cb_tstr(c, "status"); cb_uint(c, status);
    cb_tstr(c, "response"); cb_bstr(c, resp, resplen);
}
/* A 37-byte authenticator data (rpIdHash, flags=UP, signCount). */
static inline size_t make_authdata(BYTE out[37], BYTE seed) {
    memset(out, seed, 32); out[32] = 0x01; out[33] = 0; out[34] = 0; out[35] = 0; out[36] = 1; return 37;
}
/* CTAP2 makeCredential response payload: status byte 0 + {1:fmt, 2:authData, 3:attStmt} */
static inline void mc_payload(cbuf *c, const char *fmt, const BYTE *ad, size_t adlen, int withAttStmt) {
    c->n = 0; cb_byte(c, 0);
    cb_map(c, 2 + (withAttStmt ? 1 : 0));
    cb_uint(c, 1); cb_tstr(c, fmt);
    cb_uint(c, 2); cb_bstr(c, ad, adlen);
    if (withAttStmt) { cb_uint(c, 3); cb_map(c, 0); }
}
/* CTAP2 getAssertion response map (no leading status byte) */
static inline void ga_item(cbuf *c, const BYTE *ad, size_t adlen, const BYTE *sig, size_t siglen, const BYTE *uid, size_t uidlen) {
    cb_map(c, 2 + (uid ? 1 : 0));
    cb_uint(c, 2); cb_bstr(c, ad, adlen);
    cb_uint(c, 3); cb_bstr(c, sig, siglen);
    if (uid) { cb_uint(c, 4); cb_map(c, 1); cb_tstr(c, "id"); cb_bstr(c, uid, uidlen); }
}

/* HRESULTs coming out of the CBOR layer's error mapping: always HRESULT_FROM_WIN32 of one of these. */
static inline int is_cbor_layer_error(LONG hr) {
    if (hr >= 0 || ((ULONG)hr >> 16) != 0x8007) return 0;
    switch (hr & 0xFFFF) { case 0x0D: case 0x18: case 0x44C: case 0x70C: return 1; }
    return 0;
}
#define CHECK_CBOR_ERR(hr) CHECKF(is_cbor_layer_error(hr), "hr=0x%08lx", (unsigned long)(hr))

/* Current private bytes of the process (for coarse leak checks). */
static inline SIZE_T crc_private_bytes(void) {
    typedef BOOL (WINAPI *gpmi_t)(HANDLE, PROCESS_MEMORY_COUNTERS *, DWORD);
    gpmi_t f = (gpmi_t)t_proc_in("kernel32.dll", "K32GetProcessMemoryInfo");
    PROCESS_MEMORY_COUNTERS pmc; memset(&pmc, 0, sizeof pmc); pmc.cb = sizeof pmc;
    if (!f || !f(GetCurrentProcess(), &pmc, sizeof pmc)) return 0;
    return pmc.PagefileUsage;
}
#endif
