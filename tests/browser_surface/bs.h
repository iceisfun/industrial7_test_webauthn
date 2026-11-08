/* browser_surface: the entry points and argument shapes that browser integrations of webauthn.dll use.
 *
 * Nothing here reaches UI or an authenticator. Every call to WebAuthNAuthenticatorMakeCredential /
 * WebAuthNAuthenticatorGetAssertion is made in a child process (timeout) and carries at least one fault
 * that the DLL rejects locally (a COSE parameter with algorithm 0, or an RP id that is not valid UTF-16, or
 * a list entry with a zero-length credential id) so that the call can never be sent to the service.
 *
 * Structure-read probing: a structure under test is placed at the very end of a committed page whose
 * successor page is PAGE_NOACCESS and only its first S bytes exist. A read beyond S raises an access
 * violation, caught by a vectored handler in the child (first chance, so a SEH frame inside the DLL cannot
 * hide it). The smallest S for which the call returns normally is the number of bytes the DLL reads for that
 * structure, at 4-byte granularity, given the fault that ends the call.
 *
 * Structures are declared locally with the layout of the current public header (x64), including the option
 * fields added after the API versions this Windows build implements. */
#ifndef BS_H
#define BS_H
#include "t.h"

#define BS_NTE_INVALID_PARAMETER 0x80090027u   /* entry-point argument check */
#define BS_ENC_FAIL              0x8007000Du   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA): request encoder */

/* ---- structures (x64 layout) ---- */
typedef struct { DWORD dwVersion; PCWSTR pwszId, pwszName, pwszIcon; } BS_RP;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszName, pwszIcon, pwszDisplayName; } BS_USER;
typedef struct { DWORD dwVersion; PCWSTR pwszCredentialType; LONG lAlg; } BS_COSE_PARAM;
typedef struct { DWORD cCredentialParameters; BS_COSE_PARAM *pCredentialParameters; } BS_COSE_PARAMS;
typedef struct { DWORD dwVersion; DWORD cbClientDataJSON; PBYTE pbClientDataJSON; PCWSTR pwszHashAlgId; } BS_CLIENT_DATA;
typedef struct { PCWSTR pwszExtensionIdentifier; DWORD cbExtension; PVOID pvExtension; } BS_EXTENSION;
typedef struct { DWORD cExtensions; BS_EXTENSION *pExtensions; } BS_EXTENSIONS;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszCredentialType; } BS_CRED;
typedef struct { DWORD cCredentials; BS_CRED *pCredentials; } BS_CREDS;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszCredentialType; DWORD dwTransports; } BS_CRED_EX;
typedef struct { DWORD cCredentials; BS_CRED_EX **ppCredentials; } BS_CRED_LIST;
typedef struct { DWORD cbFirst; PBYTE pbFirst; DWORD cbSecond; PBYTE pbSecond; } BS_HMAC_SALT;

/* WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, versions 1..9 */
typedef struct {
    DWORD dwVersion, dwTimeoutMilliseconds;
    BS_CREDS CredentialList; BS_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment, bRequireResidentKey, dwUserVerificationRequirement, dwAttestationConveyancePreference, dwFlags;
    GUID *pCancellationId;                        /* v2 */
    BS_CRED_LIST *pExcludeCredentialList;         /* v3 */
    DWORD dwEnterpriseAttestation, dwLargeBlobSupport, bPreferResidentKey;   /* v4 */
    DWORD bBrowserInPrivateMode;                  /* v5 */
    DWORD bEnablePrf;                             /* v6 */
    PVOID pLinkedDevice; DWORD cbJsonExt; PBYTE pbJsonExt;   /* v7 */
    BS_HMAC_SALT *pPRFGlobalEval; DWORD cCredentialHints; LPCWSTR *ppwszCredentialHints; DWORD bThirdPartyPayment;  /* v8 */
    PCWSTR pwszRemoteWebOrigin; DWORD cbCreationOptionsJSON; PBYTE pbCreationOptionsJSON; DWORD cbAuthenticatorId; PBYTE pbAuthenticatorId; /* v9 */
} BS_MC_OPTIONS;

/* WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, versions 1..9 */
typedef struct {
    DWORD dwVersion, dwTimeoutMilliseconds;
    BS_CREDS CredentialList; BS_EXTENSIONS Extensions;
    DWORD dwAuthenticatorAttachment, dwUserVerificationRequirement, dwFlags;
    PCWSTR pwszU2fAppId; BOOL *pbU2fAppId;        /* v2 */
    GUID *pCancellationId;                        /* v3 */
    BS_CRED_LIST *pAllowCredentialList;           /* v4 */
    DWORD dwCredLargeBlobOperation; DWORD cbCredLargeBlob; PBYTE pbCredLargeBlob;   /* v5 */
    PVOID pHmacSecretSaltValues; DWORD bBrowserInPrivateMode;   /* v6 */
    PVOID pLinkedDevice; DWORD bAutoFill; DWORD cbJsonExt; PBYTE pbJsonExt;   /* v7 */
    DWORD cCredentialHints; LPCWSTR *ppwszCredentialHints;   /* v8 */
    PCWSTR pwszRemoteWebOrigin; DWORD cbRequestOptionsJSON; PBYTE pbRequestOptionsJSON; DWORD cbAuthenticatorId; PBYTE pbAuthenticatorId; /* v9 */
} BS_GA_OPTIONS;

_Static_assert(sizeof(BS_RP) == 0x20, "rp");
_Static_assert(sizeof(BS_USER) == 0x28, "user");
_Static_assert(sizeof(BS_CLIENT_DATA) == 0x18, "cd");
_Static_assert(sizeof(BS_COSE_PARAM) == 0x18, "cose");
_Static_assert(sizeof(BS_CRED_EX) == 0x20, "credex");
_Static_assert(offsetof(BS_MC_OPTIONS, pCancellationId) == 0x40, "mc v2");
_Static_assert(offsetof(BS_MC_OPTIONS, pExcludeCredentialList) == 0x48, "mc v3");
_Static_assert(offsetof(BS_MC_OPTIONS, dwEnterpriseAttestation) == 0x50, "mc v4");
_Static_assert(offsetof(BS_MC_OPTIONS, bBrowserInPrivateMode) == 0x5c, "mc v5");
_Static_assert(offsetof(BS_MC_OPTIONS, bEnablePrf) == 0x60, "mc v6");
_Static_assert(offsetof(BS_MC_OPTIONS, pLinkedDevice) == 0x68, "mc v7");
_Static_assert(offsetof(BS_MC_OPTIONS, pPRFGlobalEval) == 0x80, "mc v8");
_Static_assert(offsetof(BS_MC_OPTIONS, pwszRemoteWebOrigin) == 0xa0, "mc v9");
_Static_assert(offsetof(BS_GA_OPTIONS, pwszU2fAppId) == 0x38, "ga v2");
_Static_assert(offsetof(BS_GA_OPTIONS, pCancellationId) == 0x48, "ga v3");
_Static_assert(offsetof(BS_GA_OPTIONS, pAllowCredentialList) == 0x50, "ga v4");
_Static_assert(offsetof(BS_GA_OPTIONS, dwCredLargeBlobOperation) == 0x58, "ga v5");
_Static_assert(offsetof(BS_GA_OPTIONS, pHmacSecretSaltValues) == 0x68, "ga v6");
_Static_assert(offsetof(BS_GA_OPTIONS, pLinkedDevice) == 0x78, "ga v7");
_Static_assert(offsetof(BS_GA_OPTIONS, cCredentialHints) == 0x90, "ga v8");
_Static_assert(offsetof(BS_GA_OPTIONS, pwszRemoteWebOrigin) == 0xa0, "ga v9");

UDECL(HRESULT, WebAuthNAuthenticatorMakeCredential, (HWND, const BS_RP *, const BS_USER *, const BS_COSE_PARAMS *, const BS_CLIENT_DATA *, const BS_MC_OPTIONS *, PVOID *));
UDECL(HRESULT, WebAuthNAuthenticatorGetAssertion, (HWND, LPCWSTR, const BS_CLIENT_DATA *, const BS_GA_OPTIONS *, PVOID *));
UDECL(DWORD,   WebAuthNGetApiVersionNumber, (void));
UDECL(PCWSTR,  WebAuthNGetErrorName, (HRESULT));
UDECL(HRESULT, WebAuthNGetW3CExceptionDOMError, (HRESULT));
UDECL(HRESULT, WebAuthNGetCancellationId, (GUID *));
UDECL(HRESULT, WebAuthNCancelCurrentOperation, (const GUID *));

#define BS_MOD "webauthn.dll"

/* Documented end (unpadded) of each options version, from the field layout above. Index = version (1..9). */
extern const unsigned bs_mc_end[10];
extern const unsigned bs_ga_end[10];
#define BS_ROUND8(x) (((x) + 7u) & ~7u)

/* ---- guarded probe ----
 * api 'm' (MakeCredential) or 'g' (GetAssertion); kind names the structure placed on the guard page.
 * mode 0: only the local fault (alg 0 / bad RP id); mode 1: the fault is a bad list entry, used where the
 * version-matching list form is shown to be rejected locally.
 * Result: bytes read (4-byte granularity), or a negative BS_X_* value. *hr_full gets the HRESULT of the call
 * with the whole structure readable. */
#define BS_X_FAULT_AT_MAX  (-1)    /* still faults when `maxS` bytes are readable */
#define BS_X_NO_RESULT     (-2)    /* child timed out / could not run */
#define BS_X_NO_EXPORT     (-3)
int bs_extent(char api, const char *kind, DWORD ver, int mode, int maxS, DWORD *hr_full);
/* one call of the child with S readable bytes; returns the child exit code (HRESULT, or BS_FAULT_* | offset) */
DWORD bs_probe(char api, const char *kind, DWORD ver, int mode, int S);
#define BS_IS_FAULT(rc) (((rc) >> 16) == 0xFA17u)
#define BS_FAULT_OFF(rc) ((rc) & 0xFFFFu)

/* extension identifiers probed (index = `ver` of the "ext" kind) */
#define BS_NEXT 12
extern const WCHAR *const bs_ext_ids[BS_NEXT];

/* module facts shared by tests */
HMODULE bs_dll(void);
#endif
