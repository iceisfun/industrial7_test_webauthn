/* make_credential_validation: early-validation failure paths of WebAuthNAuthenticatorMakeCredential.
 *
 * Every call is made in a child process (10 s timeout) and only with arguments that are rejected
 * before any RPC / UI / device work happens:
 *   - the entry-point parameter check (result NTE_INVALID_PARAMETER 0x80090027), or
 *   - the request encoder (result HRESULT_FROM_WIN32(ERROR_INVALID_DATA) 0x8007000D), which runs
 *     before the request is sent to the service.
 * Cases that are "accepted at this layer" are made unmistakably failing by adding a second, encoder-level
 * fault (a COSE parameter with algorithm 0); the observed result then tells which layer saw the argument.
 *
 * Structures are declared locally (x64 layout, webauthn.h API versions 1-4). */
#ifndef MCV_H
#define MCV_H
#include "t.h"

#define MCV_NTE_INVALID_PARAMETER 0x80090027u   /* top-level argument check */
#define MCV_ENC_FAIL              0x8007000Du   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA): request encoder rejected */
#define MCV_X_PP_NOT_RESET        0xBAD00001u   /* child: *ppAttestation was not reset to NULL */
#define MCV_X_NO_EXPORT           0xBAD00002u
#define MCV_X_UNSTABLE            0xBAD00003u   /* child: repeated calls returned different results */
#define MCV_X_SETUP               0xBAD00004u   /* child: environment cannot provide the requested hwnd */

typedef struct { DWORD dwVersion; PCWSTR pwszId, pwszName, pwszIcon; } MCV_RP;                       /* 0x20 */
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszName, pwszIcon, pwszDisplayName; } MCV_USER; /* 0x28 */
typedef struct { DWORD dwVersion; PCWSTR pwszCredentialType; LONG lAlg; } MCV_COSE_PARAM;           /* 0x18 */
typedef struct { DWORD cCredentialParameters; MCV_COSE_PARAM *pCredentialParameters; } MCV_COSE_PARAMS; /* 0x10 */
typedef struct { DWORD dwVersion; DWORD cbClientDataJSON; PBYTE pbClientDataJSON; PCWSTR pwszHashAlgId; } MCV_CLIENT_DATA; /* 0x18 */
typedef struct { PCWSTR pwszExtensionIdentifier; DWORD cbExtension; PVOID pvExtension; } MCV_EXTENSION; /* 0x18 */
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszCredentialType; } MCV_CREDENTIAL;  /* 0x18 */
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; PCWSTR pwszCredentialType; DWORD dwTransports; } MCV_CREDENTIAL_EX; /* 0x20 */
typedef struct { DWORD cCredentials; MCV_CREDENTIAL_EX **ppCredentials; } MCV_CREDENTIAL_LIST;      /* 0x10 */

typedef struct { /* options v1 */
    DWORD dwVersion, dwTimeoutMilliseconds;
    DWORD cCredentials; MCV_CREDENTIAL *pCredentials;
    DWORD cExtensions; MCV_EXTENSION *pExtensions;
    DWORD dwAuthenticatorAttachment, bRequireResidentKey, dwUserVerificationRequirement, dwAttestationConveyancePreference, dwFlags;
} MCV_OPTIONS_V1;
typedef struct { /* options up to v4 (v2: cancellation id, v3: exclude list, v4: enterprise attestation / large blob / prefer RK) */
    DWORD dwVersion, dwTimeoutMilliseconds;
    DWORD cCredentials; MCV_CREDENTIAL *pCredentials;
    DWORD cExtensions; MCV_EXTENSION *pExtensions;
    DWORD dwAuthenticatorAttachment, bRequireResidentKey, dwUserVerificationRequirement, dwAttestationConveyancePreference, dwFlags;
    GUID *pCancellationId;
    MCV_CREDENTIAL_LIST *pExcludeCredentialList;
    DWORD dwEnterpriseAttestation, dwLargeBlobSupport, bPreferResidentKey;
} MCV_OPTIONS;

_Static_assert(sizeof(MCV_RP) == 0x20, "rp");
_Static_assert(sizeof(MCV_USER) == 0x28, "user");
_Static_assert(sizeof(MCV_COSE_PARAM) == 0x18, "cose param");
_Static_assert(sizeof(MCV_COSE_PARAMS) == 0x10, "cose params");
_Static_assert(sizeof(MCV_CLIENT_DATA) == 0x18, "client data");
_Static_assert(sizeof(MCV_EXTENSION) == 0x18, "extension");
_Static_assert(sizeof(MCV_CREDENTIAL) == 0x18, "credential");
_Static_assert(sizeof(MCV_CREDENTIAL_EX) == 0x20, "credential ex");
_Static_assert(offsetof(MCV_OPTIONS, dwAuthenticatorAttachment) == 0x28, "attachment");
_Static_assert(offsetof(MCV_OPTIONS, dwFlags) == 0x38, "flags");
_Static_assert(offsetof(MCV_OPTIONS, pCancellationId) == 0x40, "cancel id");
_Static_assert(offsetof(MCV_OPTIONS, pExcludeCredentialList) == 0x48, "exclude list");
_Static_assert(sizeof(MCV_OPTIONS) == 0x60, "options v4");
_Static_assert(sizeof(MCV_OPTIONS_V1) == 0x40, "options v1");

#define MCV_NCP 4
#define MCV_NEXT 4
#define MCV_NCRED 4
#define MCV_JSON_MAX 70000

/* All argument storage for one call; a builder edits it. Pointers default to the storage. */
typedef struct mcv_args {
    MCV_RP rp; MCV_USER user; MCV_COSE_PARAMS cose; MCV_COSE_PARAM cp[MCV_NCP];
    MCV_CLIENT_DATA cd; MCV_OPTIONS opts; MCV_EXTENSION ext[MCV_NEXT];
    MCV_CREDENTIAL legacy[MCV_NCRED]; MCV_CREDENTIAL_EX ex[MCV_NCRED]; MCV_CREDENTIAL_EX *exp[MCV_NCRED];
    MCV_CREDENTIAL_LIST list; DWORD cprot[2]; DWORD hmac;
    BYTE userid[512]; BYTE credid[64]; BYTE json[MCV_JSON_MAX];
    MCV_RP *prp; MCV_USER *puser; MCV_COSE_PARAMS *pcose; MCV_CLIENT_DATA *pcd; MCV_OPTIONS *popts;
    int hwnd_sel; HWND hwnd;
} mcv_args;

/* hwnd_sel -1 = explicit NULL */
enum { MCV_HW_DESKTOP, MCV_HW_ONE, MCV_HW_MINUS1, MCV_HW_JUNK, MCV_HW_DESTROYED, MCV_HW_MSGONLY, MCV_HW_OTHERPROC, MCV_HW_STATIC };

typedef void (*mcv_builder)(mcv_args *a, long long p);
void mcv_register(const char *name, mcv_builder b);
/* Run builder `name` (parameter p) in a child, `reps` sequential calls. Returns the child's exit code. */
DWORD mcv_run(const char *name, long long p, int reps);
/* Run and compare; returns 1 when the result matched, 0 on mismatch, -1 when the environment could not set it up. */
int mcv_expect(const char *name, long long p, DWORD want, int reps);

/* Builder helpers */
void mcv_use_opts(mcv_args *a, DWORD version);   /* popts = &opts with the given dwVersion, fields zero */
void mcv_bad_alg(mcv_args *a);                   /* cp[0].lAlg = 0: guaranteed encoder-level failure */
void mcv_legacy_list(mcv_args *a, DWORD n);      /* options.cCredentials/pCredentials -> n valid legacy entries */
void mcv_ex_list(mcv_args *a, DWORD n);          /* options.pExcludeCredentialList -> n valid EX entries */
void mcv_one_ext(mcv_args *a, PCWSTR id, DWORD cb, PVOID pv);

/* MCB: builder only.  MCT: builder + a one-shot TEST (name mcv_<n>) expecting `want`. */
#define MCB(n) \
    static void bld_##n(mcv_args *a, long long p); \
    static void __attribute__((constructor)) regb_##n(void) { mcv_register(#n, bld_##n); } \
    static void bld_##n(mcv_args *a, long long p)
#define MCT(n, want, ...) \
    static void bld_##n(mcv_args *a, long long p) { (void)p; __VA_ARGS__ } \
    static void __attribute__((constructor)) regb_##n(void) { mcv_register(#n, bld_##n); } \
    TEST(mcv_##n) { REQUIRE(UN(WebAuthNAuthenticatorMakeCredential)); mcv_expect(#n, 0, (DWORD)(want), 1); }

UDECL(HRESULT, WebAuthNAuthenticatorMakeCredential, (HWND, const MCV_RP *, const MCV_USER *, const MCV_COSE_PARAMS *, const MCV_CLIENT_DATA *, const MCV_OPTIONS *, PVOID *));
#endif
