/* platform_credentials: shared declarations.
 *
 * Win10 x64 webauthn.dll exports (ordinals in parentheses):
 *   WebAuthNGetPlatformCredentials (54)      HRESULT f(ULONG_PTR arg1, PCWSTR rpId, PVOID *ppList)
 *   WebAuthNFreePlatformCredentials (47)     void    f(PVOID pList)
 *   WebAuthNDeletePlatformCredential (41)    HRESULT f(DWORD cbId, const BYTE *pbId)
 *   WebAuthNFreeUserEntityList (48)          void    f(PVOID p)
 *
 * The query function on this build does NOT take the later PCWEBAUTHN_GET_CREDENTIALS_OPTIONS
 * signature. arg1 must be non-zero (it is only compared with zero in the validation step), rpId may be
 * NULL (meaning: all relying parties), ppList receives a LocalAlloc'd list:
 *     struct { DWORD cItems; PVOID *ppItems; }   (cItems at +0, ppItems at +8, items array follows at +0x10)
 * where every item is its own LocalAlloc block. Only the early parameter-validation path (arg1 == 0 or
 * ppList == NULL) is exercised here: every other path goes on to the platform user-verification prompt,
 * which a conformance corpus must never trigger.
 */
#ifndef PC_H
#define PC_H
#include "t.h"

#ifndef NTE_NOT_FOUND
#define NTE_NOT_FOUND ((HRESULT)0x80090011L)
#endif
#define PC_NTE_INVALID_PARAMETER ((HRESULT)0x80090027L)
#define PC_NTE_NO_MORE_ITEMS     ((HRESULT)0x8009002AL)
#define PC_NTE_NOT_FOUND         ((HRESULT)0x80090011L)

typedef HRESULT (WINAPI *pc_get_fn)(ULONG_PTR arg1, PCWSTR rpId, PVOID *ppList);
typedef void    (WINAPI *pc_free_fn)(PVOID p);
typedef HRESULT (WINAPI *pc_delete_fn)(DWORD cbId, const BYTE *pbId);

static inline pc_get_fn    pc_get(void)    { return (pc_get_fn)t_proc("WebAuthNGetPlatformCredentials"); }
static inline pc_free_fn   pc_freepc(void) { return (pc_free_fn)t_proc("WebAuthNFreePlatformCredentials"); }
static inline pc_free_fn   pc_freeue(void) { return (pc_free_fn)t_proc("WebAuthNFreeUserEntityList"); }
static inline pc_delete_fn pc_del(void)    { return (pc_delete_fn)t_proc("WebAuthNDeletePlatformCredential"); }

/* Build a list in the documented layout from LocalAlloc blocks. Items are pc_item_size bytes each. */
typedef struct { DWORD cItems; DWORD pad; PVOID *ppItems; } pc_list_hdr;
static inline void *pc_make_list(DWORD n, size_t item_size)
{
    /* header (16 bytes) followed by the pointer array, like the real allocation */
    pc_list_hdr *h = (pc_list_hdr *)LocalAlloc(LPTR, 16 + (SIZE_T)n * 8 + 8);
    if (!h) return NULL;
    h->cItems = n;
    h->ppItems = (PVOID *)((BYTE *)h + 16);
    for (DWORD i = 0; i < n; i++) h->ppItems[i] = LocalAlloc(LPTR, item_size ? item_size : 1);
    return h;
}

/* deterministic, structured, never-real credential id bytes */
static inline void pc_fill_id(BYTE *p, size_t n, int mode)
{
    static const char tag[] = "CORPUS-NONEXISTENT-CREDENTIAL-ID/";
    for (size_t i = 0; i < n; i++)
        p[i] = mode == 0 ? 0 : (BYTE)(i < sizeof(tag) - 1 ? tag[i] : (BYTE)((i * 131u + 0x5Au) ^ 0xC3u));
}
#endif
