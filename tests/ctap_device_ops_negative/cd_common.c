#include "cd.h"

/* ---- selected-device record ---- */
void *cd_dev_alloc(void) { return LocalAlloc(LPTR, CD_DEV_SIZE); }
void cd_dev_set(void *dev, DWORD kind, void *p20, void *p28) {
    BYTE *b = (BYTE *)dev;
    *(DWORD *)b = kind; *(void **)(b + 0x20) = p20; *(void **)(b + 0x28) = p28;
}
int cd_dev_complete(const void *dev) {
    const BYTE *b = (const BYTE *)dev;
    return dev && *(const DWORD *)b != 0 && *(void *const *)(b + 0x20) != NULL && *(void *const *)(b + 0x28) != NULL;
}

/* ---- PIN buffers ---- */
void cd_pin_fill(WCHAR *buf, size_t cap, size_t n, WCHAR ch) {
    for (size_t i = 0; i < cap; i++) buf[i] = 0x5A5A;
    for (size_t i = 0; i < n; i++) buf[i] = ch;
    buf[n] = 0;
}
int cd_pin_wiped(const WCHAR *buf, size_t n) { for (size_t i = 0; i <= n; i++) if (buf[i]) return 0; return 1; }
int cd_pin_tail_intact(const WCHAR *buf, size_t from, size_t cap) { for (size_t i = from; i < cap; i++) if (buf[i] != 0x5A5A) return 0; return 1; }

/* ---- BCrypt via GetProcAddress ---- */
static BCRYPT_ALG_HANDLE g_sha, g_ec;
static int g_ready = -1;
int cd_crypto_ready(void) {
    if (g_ready >= 0) return g_ready;
    g_ready = 0;
    if (!U(BCryptOpenAlgorithmProvider) || !U(BCryptGenerateKeyPair) || !U(BCryptSignHash) || !U(BCryptVerifySignature) ||
        !U(BCryptHash) || !U(BCryptExportKey) || !U(BCryptFinalizeKeyPair) || !U(BCryptDestroyKey)) return 0;
    if (U(BCryptOpenAlgorithmProvider)(&g_sha, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return 0;
    if (U(BCryptOpenAlgorithmProvider)(&g_ec, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0) return 0;
    BYTE h[32];
    if (U(BCryptHash)(g_sha, NULL, 0, (PUCHAR)"abc", 3, h, 32) != 0) return 0;
    g_ready = 1;
    return 1;
}
void cd_sha256(const void *p, ULONG cb, BYTE out[32]) { U(BCryptHash)(g_sha, NULL, 0, (PUCHAR)(cb ? p : (const void *)"")  , cb, out, 32); }
void cd_rp_hash(PCWSTR rp, BYTE out[32]) {
    char u[256]; int n = rp ? WideCharToMultiByte(CP_UTF8, 0, rp, -1, u, sizeof u, NULL, NULL) : 1;
    if (n <= 0) n = 1, u[0] = 0;
    cd_sha256(u, (ULONG)(n - 1), out);
}
int cd_key_gen(cd_key *k) {
    memset(k, 0, sizeof *k);
    if (U(BCryptGenerateKeyPair)(g_ec, &k->h, 256, 0) != 0) return 0;
    if (U(BCryptFinalizeKeyPair)(k->h, 0) != 0) return 0;
    BYTE blob[8 + 64]; ULONG got = 0;
    if (U(BCryptExportKey)(k->h, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &got, 0) != 0 || got != sizeof blob) return 0;
    memcpy(k->x, blob + 8, 32); memcpy(k->y, blob + 40, 32);
    return 1;
}
void cd_key_free(cd_key *k) { if (k->h) U(BCryptDestroyKey)(k->h); k->h = NULL; }
int cd_sign_raw(const cd_key *k, const BYTE *msg, ULONG cb, BYTE sig[64]) {
    BYTE h[32]; ULONG got = 0;
    cd_sha256(msg, cb, h);
    return U(BCryptSignHash)(k->h, NULL, h, 32, sig, 64, &got, 0) == 0 && got == 64;
}
int cd_verify_raw(const cd_key *k, const BYTE *msg, ULONG cb, const BYTE sig[64]) {
    BYTE h[32]; cd_sha256(msg, cb, h);
    return U(BCryptVerifySignature)(k->h, NULL, h, 32, (PUCHAR)sig, 64, 0) == 0;
}
static ULONG der_int(BYTE *o, const BYTE *v) {
    int s = 0; while (s < 31 && v[s] == 0) s++;
    int n = 32 - s, pad = (v[s] & 0x80) ? 1 : 0;
    o[0] = 0x02; o[1] = (BYTE)(n + pad);
    if (pad) o[2] = 0;
    memcpy(o + 2 + pad, v + s, n);
    return 2 + pad + n;
}
ULONG cd_der_from_raw(const BYTE raw[64], BYTE *der) {
    BYTE tmp[80]; ULONG n = der_int(tmp, raw); n += der_int(tmp + n, raw + 32);
    der[0] = 0x30; der[1] = (BYTE)n; memcpy(der + 2, tmp, n);
    return n + 2;
}

/* COSE_Key: {1:2, 3:alg, -1:1, -2:x, -3:y}, minimal CBOR encoding */
static ULONG cbor_int(BYTE *o, long v) {
    int neg = v < 0; unsigned long long u = neg ? (unsigned long long)(-1 - v) : (unsigned long long)v; BYTE mt = neg ? 0x20 : 0;
    if (u < 24) { o[0] = mt | (BYTE)u; return 1; }
    if (u < 256) { o[0] = mt | 24; o[1] = (BYTE)u; return 2; }
    o[0] = mt | 25; o[1] = (BYTE)(u >> 8); o[2] = (BYTE)u; return 3;
}
static ULONG cbor_bstr(BYTE *o, const BYTE *p, ULONG n) {
    ULONG h;
    if (n < 24) { o[0] = 0x40 | (BYTE)n; h = 1; } else if (n < 256) { o[0] = 0x58; o[1] = (BYTE)n; h = 2; } else { o[0] = 0x59; o[1] = (BYTE)(n >> 8); o[2] = (BYTE)n; h = 3; }
    memcpy(o + h, p, n); return h + n;
}
ULONG cd_cose_ec(BYTE *out, long alg, const BYTE *x, ULONG cx, const BYTE *y, ULONG cy) {
    ULONG n = 0;
    out[n++] = 0xA5;
    n += cbor_int(out + n, 1);  n += cbor_int(out + n, 2);
    n += cbor_int(out + n, 3);  n += cbor_int(out + n, alg);
    n += cbor_int(out + n, -1); n += cbor_int(out + n, 1);
    n += cbor_int(out + n, -2); n += cbor_bstr(out + n, x, cx);
    n += cbor_int(out + n, -3); n += cbor_bstr(out + n, y, cy);
    return n;
}
ULONG cd_cose_es256(BYTE *out, const BYTE x[32], const BYTE y[32]) { return cd_cose_ec(out, -7, x, 32, y, 32); }

/* ---- verify vectors ---- */
void cd_vec_init(cd_vec *v, const cd_key *k, PCWSTR rp, BYTE flags, ULONG counter, const char *json) {
    memset(v, 0, sizeof *v);
    if (rp) { lstrcpynW(v->rpbuf, rp, 64); v->rp = v->rpbuf; } else v->rp = NULL;
    v->cjLen = (ULONG)strlen(json); memcpy(v->cj, json, v->cjLen);
    cd_sha256(v->cj, v->cjLen, v->chash);
    cd_rp_hash(rp ? rp : L"", v->aa);
    v->aa[32] = flags;
    v->aa[33] = (BYTE)(counter >> 24); v->aa[34] = (BYTE)(counter >> 16); v->aa[35] = (BYTE)(counter >> 8); v->aa[36] = (BYTE)counter;
    v->aaLen = 37;
    /* credential authenticator data: rpIdHash | UP|AT | counter 0 | aaguid | credIdLen | credId | COSE key */
    BYTE *c = v->ca; ULONG n = 0;
    memcpy(c, v->aa, 32); n = 32; c[n++] = 0x41; c[n++] = 0; c[n++] = 0; c[n++] = 0; c[n++] = 0;
    for (int i = 0; i < 16; i++) c[n++] = (BYTE)(0xA0 + i);
    c[n++] = 0; c[n++] = 16;
    for (int i = 0; i < 16; i++) c[n++] = (BYTE)(0xC0 + i);
    v->caKeyOff = n; v->caKeyLen = cd_cose_es256(c + n, k->x, k->y); n += v->caKeyLen;
    v->caLen = n;
    cd_vec_resign(v, k);
}
void cd_vec_resign(cd_vec *v, const cd_key *k) {
    BYTE msg[256 + 32], raw[64]; ULONG n = v->aaLen;
    memcpy(msg, v->aa, n); memcpy(msg + n, v->chash, 32);
    cd_sign_raw(k, msg, n + 32, raw);
    v->sigLen = cd_der_from_raw(raw, v->sig);
}
CDHR cd_verify_call(PCWSTR rp, const CD_CLIENT_DATA *cd, const CD_ASSERTION *as, DWORD cbCa, const BYTE *pbCa) {
    return UN(WebAuthNCtapVerifyGetAssertion)(rp, cd, as, cbCa, pbCa);
}
CDHR cd_vec_call(const cd_vec *v) {
    CD_CLIENT_DATA cdta = { 1, v->cjLen, (PBYTE)v->cj, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as);
    as.dwVersion = 1; as.cbAuthenticatorData = v->aaLen; as.pbAuthenticatorData = (PBYTE)v->aa;
    as.cbSignature = v->sigLen; as.pbSignature = (PBYTE)v->sig;
    return cd_verify_call(v->rp, &cdta, &as, v->caLen, v->ca);
}
