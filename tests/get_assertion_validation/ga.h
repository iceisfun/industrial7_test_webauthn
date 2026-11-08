#ifndef GA_H
#define GA_H
#include "t.h"

/* Area: WebAuthNAuthenticatorGetAssertion early validation.
 *
 * Every call to the function goes through a child process (10 s timeout) and every case is built so that
 * the call is rejected locally, before any RPC to the authenticator broker, i.e. before any UI or device
 * access. A case only calls the API when the harness can prove (from the rules below, taken from the
 * Windows 10 implementation) that it fails locally; otherwise the child refuses to run it.
 *
 * Rules (HRESULT results):
 *  Outer parameter check -> 0x80090027 (NTE_INVALID_PARAMETER), out pointer already set to NULL:
 *    RP id NULL; client data NULL; client data dwVersion 0; pbClientDataJSON NULL; cbClientDataJSON 0;
 *    pwszHashAlgId NULL; options non-NULL with dwVersion 0.
 *  Request encoding (still local) -> 0x8007000D (HRESULT_FROM_WIN32(ERROR_INVALID_DATA)):
 *    RP id that is not valid UTF-16 (lone surrogate); an allow-list credential entry that has
 *    cbId == 0, a NULL or empty type string, or (extended entries only) dwVersion == 0.
 *  Nothing else is validated before the request is sent, so those inputs are only usable together with
 *  one of the failures above. */

typedef struct { DWORD dwVersion; DWORD cbClientDataJSON; PBYTE pbClientDataJSON; LPCWSTR pwszHashAlgId; } GA_CLIENT_DATA;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; LPCWSTR pwszCredentialType; } GA_CRED;
typedef struct { DWORD dwVersion; DWORD cbId; PBYTE pbId; LPCWSTR pwszCredentialType; DWORD dwTransports; } GA_CRED_EX;
typedef struct { DWORD cCredentials; GA_CRED_EX **ppCredentials; } GA_CRED_LIST;
typedef struct { DWORD cCredentials; GA_CRED *pCredentials; } GA_CREDS;
typedef struct { DWORD cExtensions; void *pExtensions; } GA_EXTS;
/* WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, versions 1..4 (later versions only append fields). */
typedef struct {
    DWORD dwVersion;                       /* 0x00 */
    DWORD dwTimeoutMilliseconds;           /* 0x04 */
    GA_CREDS CredentialList;               /* 0x08 */
    GA_EXTS Extensions;                    /* 0x18 */
    DWORD dwAuthenticatorAttachment;       /* 0x28 */
    DWORD dwUserVerificationRequirement;   /* 0x2c */
    DWORD dwFlags;                         /* 0x30 */
    LPCWSTR pwszU2fAppId;                  /* 0x38  v2 */
    BOOL *pbU2fAppId;                      /* 0x40  v2 */
    GUID *pCancellationId;                 /* 0x48  v3 */
    GA_CRED_LIST *pAllowCredentialList;    /* 0x50  v4 */
} GA_OPTIONS;
_Static_assert(sizeof(GA_CLIENT_DATA) == 0x18, "client data");
_Static_assert(sizeof(GA_CRED) == 0x18, "cred");
_Static_assert(sizeof(GA_CRED_EX) == 0x20, "cred ex");
_Static_assert(offsetof(GA_OPTIONS, CredentialList) == 0x08, "opt cred");
_Static_assert(offsetof(GA_OPTIONS, Extensions) == 0x18, "opt ext");
_Static_assert(offsetof(GA_OPTIONS, dwAuthenticatorAttachment) == 0x28, "opt attach");
_Static_assert(offsetof(GA_OPTIONS, dwFlags) == 0x30, "opt flags");
_Static_assert(offsetof(GA_OPTIONS, pwszU2fAppId) == 0x38, "opt appid");
_Static_assert(offsetof(GA_OPTIONS, pCancellationId) == 0x48, "opt cancel");
_Static_assert(offsetof(GA_OPTIONS, pAllowCredentialList) == 0x50, "opt allow");
_Static_assert(sizeof(GA_OPTIONS) == 0x58, "opt size");

#define E_GA_PARAM 0x80090027u   /* NTE_INVALID_PARAMETER */
#define E_GA_DATA  0x8007000Du   /* HRESULT_FROM_WIN32(ERROR_INVALID_DATA) */
#define GA_OK      0x600D600Du   /* child exit code: everything as expected */

enum { RP_NORMAL = 0, RP_NULL, RP_EMPTY, RP_LONG, RP_UNICODE, RP_URL, RP_LOCALHOST, RP_UPPER, RP_PORT, RP_SPACE,
       RP_EMOJI, RP_DOT, RP_IP,
       RP_LONE_HIGH, RP_LONE_LOW, RP_TRAIL_HIGH, RP_LEAD_LOW, RP_TWO_HIGH, RP_LOW_HIGH, RP_MID_HIGH };
enum { CD_OK = 0, CD_NULL, CD_VER0, CD_VER2, CD_VERMAX, CD_CB0, CD_PB_NULL, CD_HASH_NULL, CD_ZEROED, CD_CB0_PB_NULL,
       CD_CB1, CD_BIG, CD_EMPTY_OBJ };
enum { H_SHA256 = 0, H_EMPTY, H_BOGUS, H_SHA384, H_SHA512, H_SHA1, H_LOWER, H_CNG, H_MD5, H_LONG };
enum { OM_STRUCT = 0, OM_ZERO_VER, OM_NONE };
enum { K_NONE = 0, K_OK, K_VER0, K_CB0, K_TYPE_NULL, K_TYPE_EMPTY, K_TYPE_SCOPED, K_TYPE_BOGUS, K_TYPE_UPPER, K_VERMAX };
enum { B_NA = 0, B_UNCHANGED, B_ZEROED };
enum { HW_NULL = 0, HW_BOGUS, HW_DESKTOP, HW_MINUS1, HW_ODD };

typedef struct {
    const char *name;
    int rp, cd, hash, hw, om;
    DWORD ov;                 /* options dwVersion (0 = default 4); ignored for OM_ZERO_VER / OM_NONE */
    DWORD osz;                /* options allocation size override (0 = by version) */
    DWORD to, at, uv, fl;     /* timeout, attachment, user verification, flags */
    int cancel;               /* pCancellationId -> never-signalled GUID (v3+) */
    int b;                    /* pbU2fAppId -> BOOL sentinel (v2+); expected state afterwards */
    int appid;                /* pwszU2fAppId set (v2+) */
    DWORD tr;                 /* dwTransports of extended allow-list entries */
    unsigned char leg[3];     /* legacy CredentialList entries (K_*) */
    unsigned char ex[3];      /* pAllowCredentialList entries (K_*, v4+) */
    DWORD hr;                 /* expected HRESULT */
} gacase;

void ga_register(const gacase *c);
void ga_run(const gacase *c);

/* One TEST per case. Defaults: valid RP, client data, hash, v4 options, no credentials. */
#define GA(nm, ...) \
    static const gacase gac_##nm = { #nm, __VA_ARGS__ }; \
    static void __attribute__((constructor)) gar_##nm(void) { ga_register(&gac_##nm); } \
    TEST(get_assertion_validation_##nm) { ga_run(&gac_##nm); }
#endif
