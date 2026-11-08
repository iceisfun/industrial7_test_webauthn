/* ctap_device_ops_negative: shared declarations.
 *
 * Prototypes are derived from the Windows 10 reference decompilation of webauthn.dll; the public SDK header does not
 * declare these exports. Every device-facing call in this area is made only with arguments that the reference shows
 * are rejected before any device, RPC or UI work happens; see the per-file comments for the proof of each path.
 */
#ifndef CD_H
#define CD_H
#include "t.h"
#include <bcrypt.h>

typedef DWORD CDHR;   /* HRESULT-like result compared as an unsigned 32-bit value */
#define SENT 0xCCCCCCCCu

/* ---- result codes seen on the early-failure paths ---- */
#define CD_NTE_INVALID_PARAMETER   0x80090027u   /* NTE_INVALID_PARAMETER */
#define CD_NTE_BAD_HASH            0x80090002u   /* rpIdHash mismatch in VerifyGetAssertion */
#define CD_NTE_BAD_KEY_SIZE        0x80090015u   /* COSE coordinate size mismatch */
#define CD_HR_INVALID_DATA         0x8007000Du   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA) */
#define CD_HR_NOT_SUPPORTED        0x80070032u   /* HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) */
#define CD_HR_INVALID_ARG          0x80070057u   /* E_INVALIDARG */
#define CD_HR_CBOR_SIZE            0x8007044Cu   /* HRESULT_FROM_WIN32(1100): CBOR request size/pointer rejected */
#define CD_STATUS_INVALID_SIGNATURE 0xC000A000u

#define CD_FAILED(r) (((LONG)(r)) < 0)

/* ---- struct layouts (x64) used by the calls ---- */
typedef struct { DWORD dwVersion; PCWSTR pwszId; PCWSTR pwszName; PCWSTR pwszIcon; } CD_RP;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszName; PCWSTR pwszIcon; PCWSTR pwszDisplayName; } CD_USER;
typedef struct { DWORD dwVersion; PCWSTR pwszCredentialType; LONG lAlg; } CD_COSE_PARAM;
typedef struct { DWORD cCredentialParameters; CD_COSE_PARAM *pCredentialParameters; } CD_COSE_PARAMS;
typedef struct { DWORD dwVersion; DWORD cbClientDataJSON; PBYTE pbClientDataJSON; PCWSTR pwszHashAlgId; } CD_CLIENT_DATA;
typedef struct {
    DWORD dwVersion; DWORD cbAuthenticatorData; PBYTE pbAuthenticatorData;
    DWORD cbSignature; PBYTE pbSignature;
    DWORD credVersion; DWORD cbCredId; PBYTE pbCredId; PCWSTR pwszCredType;
    DWORD cbUserId; PBYTE pbUserId;
} CD_ASSERTION;
_Static_assert(sizeof(CD_RP) == 32, "rp");
_Static_assert(sizeof(CD_USER) == 40, "user");
_Static_assert(sizeof(CD_COSE_PARAM) == 24, "cose param");
_Static_assert(sizeof(CD_COSE_PARAMS) == 16, "cose params");
_Static_assert(sizeof(CD_CLIENT_DATA) == 24, "client data");
_Static_assert(offsetof(CD_CLIENT_DATA, pbClientDataJSON) == 8, "pbClientDataJSON");
_Static_assert(offsetof(CD_ASSERTION, cbSignature) == 16, "cbSignature");
_Static_assert(offsetof(CD_ASSERTION, pbSignature) == 24, "pbSignature");

/* ---- prototypes (first argument is the owner window handle; the second is an opaque flags word forwarded to the
 *      device selector; both are untouched on the early-failure paths) ---- */
UDECL(CDHR, WebAuthNCtapSetClientPin, (HWND, ULONG, const GUID *, WCHAR *pin, DWORD *pRetries));
UDECL(CDHR, WebAuthNCtapChangeClientPin, (HWND, ULONG, const GUID *, WCHAR *oldPin, WCHAR *newPin, DWORD *pOut1, DWORD *pOut2));
UDECL(CDHR, WebAuthNCtapChangeClientPinForSelectedDevice, (HWND, ULONG, const GUID *, WCHAR *oldPin, WCHAR *newPin, void **ppSelectedDevice));
UDECL(CDHR, WebAuthNCtapResetDevice, (HWND, ULONG, const GUID *));
UDECL(CDHR, WebAuthNCtapSendCommand, (HWND, DWORD cbCbor, const BYTE *pbCbor, DWORD *pcbOut, BYTE **ppbOut, WCHAR *pin, void **ppSelectedDevice));
UDECL(CDHR, WebAuthNCtapMakeCredential, (HWND, ULONG, const CD_RP *, const CD_USER *, const CD_COSE_PARAMS *, const CD_CLIENT_DATA *,
        const void *options, void **ppAttestation, const GUID *, WCHAR *pinA, WCHAR *pinB, DWORD *pOut1, DWORD *pOut2));
UDECL(CDHR, WebAuthNCtapGetAssertion, (HWND, ULONG, PCWSTR rpId, const CD_CLIENT_DATA *, const void *options, void **ppAssertion,
        const GUID *, WCHAR *pin, DWORD *pcbHmac, BYTE *pbHmac, void **ppSelectedDevice, ULONG, BYTE *));
UDECL(CDHR, WebAuthNCtapVerifyGetAssertion, (PCWSTR rpId, const CD_CLIENT_DATA *, const CD_ASSERTION *, DWORD cbCredAuthData, const BYTE *pbCredAuthData));

/* ---- selected-device record (LocalAlloc'd by the DLL; layout partly known) ----
 * dword@0x00 validity/kind, ptr@0x20, ptr@0x28, ptr@0x30, dword@0x38, ptr@0x40. A record is only "complete"
 * when dword@0 != 0 and both ptr@0x20 and ptr@0x28 are non-NULL; every test below keeps it incomplete. */
#define CD_DEV_SIZE 0x100
void *cd_dev_alloc(void);                      /* zeroed LocalAlloc block, CD_DEV_SIZE bytes */
void  cd_dev_set(void *dev, DWORD kind, void *p20, void *p28);
int   cd_dev_complete(const void *dev);        /* mirrors the "complete" test above */

/* ---- PIN buffers ---- */
/* Fill buf[0..n) with pattern chars, terminator at n, sentinel 0x5A5A afterwards up to cap. */
void cd_pin_fill(WCHAR *buf, size_t cap, size_t n, WCHAR ch);
int  cd_pin_wiped(const WCHAR *buf, size_t n);                 /* buf[0..n] all zero */
int  cd_pin_tail_intact(const WCHAR *buf, size_t from, size_t cap); /* sentinel region untouched */

/* ---- crypto fixtures (built through BCrypt via GetProcAddress) ---- */
typedef struct { BCRYPT_KEY_HANDLE h; BYTE x[32], y[32]; } cd_key;
int  cd_crypto_ready(void);
int  cd_key_gen(cd_key *k);
void cd_key_free(cd_key *k);
void cd_sha256(const void *p, ULONG cb, BYTE out[32]);
void cd_rp_hash(PCWSTR rp, BYTE out[32]);                       /* SHA-256 of the UTF-8 form */
int  cd_sign_raw(const cd_key *k, const BYTE *msg, ULONG cb, BYTE sig[64]);      /* ES256 over msg, P1363 */
int  cd_verify_raw(const cd_key *k, const BYTE *msg, ULONG cb, const BYTE sig[64]);
ULONG cd_der_from_raw(const BYTE raw[64], BYTE *der);           /* DER SEQUENCE { INTEGER r, INTEGER s } */
ULONG cd_cose_es256(BYTE *out, const BYTE x[32], const BYTE y[32]);   /* 77-byte COSE_Key map */
ULONG cd_cose_ec(BYTE *out, long alg, const BYTE *x, ULONG cx, const BYTE *y, ULONG cy);

typedef struct {
    WCHAR rpbuf[64]; const WCHAR *rp;
    BYTE cj[256]; ULONG cjLen;
    BYTE chash[32];
    BYTE aa[160]; ULONG aaLen;          /* assertion authenticator data */
    BYTE sig[192]; ULONG sigLen;         /* DER signature */
    BYTE ca[700]; ULONG caLen;          /* credential (attestation) authenticator data */
    ULONG caKeyOff, caKeyLen;           /* position of the COSE key inside ca */
} cd_vec;
void cd_vec_init(cd_vec *v, const cd_key *k, PCWSTR rp, BYTE flags, ULONG counter, const char *json);
void cd_vec_resign(cd_vec *v, const cd_key *k);                  /* recompute sig over aa || SHA256(cj) */
CDHR cd_vec_call(const cd_vec *v);
CDHR cd_verify_call(PCWSTR rp, const CD_CLIENT_DATA *cd, const CD_ASSERTION *as, DWORD cbCa, const BYTE *pbCa);
#define CD_REQUIRE_VERIFY() REQUIRE(UN(WebAuthNCtapVerifyGetAssertion))
#define CD_NEED_CRYPTO() do { if (!cd_crypto_ready()) { t_skip("bcrypt ES256 not available"); return; } } while (0)
#endif
