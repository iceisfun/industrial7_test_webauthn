/* Declarations and helpers for the WebAuthNCtapManage* area.
 *
 * None of these prototypes are in the SDK headers, so each is declared here (UDECL) and resolved
 * with UN(name). Parameter names are descriptive only; the types follow the x64 register usage
 * of the Windows 10 reference corpus.
 *
 * Management handle layout used by the early-validation paths (x64):
 *   handle + 0x08 : pointer to the internal management context (NULL => invalid handle)
 * Internal context layout, only the fields the early checks read:
 *   ctx + 0x00 : pointer to the selected-device record (NULL => no device session)
 *   ctx + 0x08 : DWORD  request-buffer length   (0 => no session)
 *   ctx + 0x10 : pointer to request buffer      (NULL => no session)
 *   ctx + 0x2c : DWORD  pending fingerprint-enrolment template-id length
 *   ctx + 0x30 : pointer to LocalAlloc'd pending template id (freed + cleared by Enroll/Cancel)
 * Handles built from these shapes never name a real device; every call made with them fails or
 * returns before any device, RPC service or UI work.
 */
#ifndef CM_API_H
#define CM_API_H
#include "t.h"

#define CM_E_NTE_INVALID_PARAMETER ((HRESULT)0x80090027)
#define CM_E_NTE_BAD_DATA          ((HRESULT)0x80090005)

UDECL(void,    WebAuthNCtapManageClose, (void *hManage));
UDECL(HRESULT, WebAuthNCtapManageSelect, (HWND hWnd, DWORD dwFlags, const GUID *pSession, void **phManage));
UDECL(HRESULT, WebAuthNCtapManageSetPin, (HWND hWnd, void *hManage, PWSTR pwszPin, int *pRetries));
UDECL(HRESULT, WebAuthNCtapManageChangePin, (HWND hWnd, void *hManage, PWSTR pwszOldPin, PWSTR pwszNewPin, int *pRetries, DWORD *pUvRetries));
UDECL(HRESULT, WebAuthNCtapManageAuthenticatePin, (HWND hWnd, void *hManage, PWSTR pwszPin, int *pRetries, DWORD *pUvRetries));
UDECL(HRESULT, WebAuthNCtapManageGetDisplayCredentials, (HWND hWnd, void *hManage, void **ppList));
UDECL(void,    WebAuthNCtapManageFreeDisplayCredentials, (void *pList));
UDECL(HRESULT, WebAuthNCtapManageDeleteCredential, (HWND hWnd, void *hManage, int cbCredentialId, const BYTE *pbCredentialId));
UDECL(HRESULT, WebAuthNCtapManageEnrollFingerprint, (HWND hWnd, void *hManage, int fBegin, DWORD dwTimeoutMs, DWORD *pLastStatus, DWORD *pRemaining));
UDECL(HRESULT, WebAuthNCtapManageCancelEnrollFingerprint, (HWND hWnd, void *hManage));
UDECL(HRESULT, WebAuthNCtapManageRemoveFingerprints, (HWND hWnd, void *hManage));
UDECL(HRESULT, WebAuthNCtapManageResetDevice, (HWND hWnd, void *hManage));
UDECL(void,    WebAuthNFreePlatformCredentials, (void *pList));

/* Synthetic handle + context (stack objects, so the DLL must not free them). */
typedef struct { DWORD tag; DWORD pad; void *ctx; DWORD spare[4]; } CM_HANDLE;
typedef struct { _Alignas(16) unsigned char b[0x80]; } CM_CTX;
#define CTX_Q0(c)      (*(void **)((c)->b + 0x00))
#define CTX_LEN(c)     (*(DWORD *)((c)->b + 0x08))
#define CTX_BUF(c)     (*(void **)((c)->b + 0x10))
#define CTX_TLEN(c)    (*(DWORD *)((c)->b + 0x2c))
#define CTX_TPTR(c)    (*(void **)((c)->b + 0x30))

enum { SH_NULL, SH_NO_CTX, SH_ZERO_CTX, SH_NO_BUFLEN, SH_NO_BUFPTR, SH_COUNT };
extern const char *const cm_shape_name[SH_COUNT];

typedef struct { CM_HANDLE h; CM_CTX c; unsigned char dummy[64]; } CM_SHAPE;
/* Returns the handle value to pass (NULL for SH_NULL). */
static inline void *cm_shape(CM_SHAPE *s, int shape)
{
    memset(s, 0, sizeof *s);
    switch (shape) {
    case SH_NULL: return NULL;
    case SH_NO_CTX: return &s->h;
    case SH_ZERO_CTX: s->h.ctx = &s->c; return &s->h;
    case SH_NO_BUFLEN: s->h.ctx = &s->c; CTX_Q0(&s->c) = s->dummy; CTX_LEN(&s->c) = 0; CTX_BUF(&s->c) = s->dummy; return &s->h;
    case SH_NO_BUFPTR: s->h.ctx = &s->c; CTX_Q0(&s->c) = s->dummy; CTX_LEN(&s->c) = 1; CTX_BUF(&s->c) = NULL; return &s->h;
    }
    return NULL;
}

/* PIN buffer helpers: n UTF-16 units, terminator, then a canary that a correct wipe must not touch. */
#define PIN_CANARY 0xBEEF
static inline void pin_fill(WCHAR *buf, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) buf[i] = (WCHAR)(L'1' + (i % 9));
    buf[n] = 0;
    for (i = 1; i <= 4; i++) buf[n + i] = PIN_CANARY;
}
static inline int pin_wiped(const WCHAR *buf, size_t n)
{
    size_t i;
    for (i = 0; i <= n; i++) if (buf[i] != 0) return 0;
    return 1;
}
static inline int pin_untouched(const WCHAR *buf, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (buf[i] != (WCHAR)(L'1' + (i % 9))) return 0;
    return buf[n] == 0;
}
static inline int pin_canary_ok(const WCHAR *buf, size_t n)
{
    size_t i;
    for (i = 1; i <= 4; i++) if (buf[n + i] != PIN_CANARY) return 0;
    return 1;
}
#endif
