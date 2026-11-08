#ifndef CID_H
#define CID_H
#include "t.h"
#include <stdlib.h>

/* Signatures declared locally (SDK header may be partial). All are WINAPI. */
UDECL(HRESULT, WebAuthNGetCancellationId, (GUID *));
UDECL(HRESULT, WebAuthNCancelCurrentOperation, (const GUID *));
UDECL(void, WebAuthNFreeCredentialAttestation, (void *));
UDECL(void, WebAuthNFreeAssertion, (void *));
UDECL(void, WebAuthNFreePlatformCredentials, (void *));
UDECL(void, WebAuthNFreeUserEntityList, (void *));
UDECL(void, WebAuthNFreeDecodedAccountInformation, (void *));
UDECL(void, WebAuthNFreeEncodedAccountInformation, (void *));
UDECL(void, WebAuthNCtapFreeSelectedDeviceInformation, (void *));
UDECL(void, WebAuthNCtapManageFreeDisplayCredentials, (void *));

#define CID_MOD "webauthn.dll"
#define GETID() ((WebAuthNGetCancellationId_pfn)t_proc_in(CID_MOD, "WebAuthNGetCancellationId"))
#define CANCEL() ((WebAuthNCancelCurrentOperation_pfn)t_proc_in(CID_MOD, "WebAuthNCancelCurrentOperation"))

static inline int cid_is_nil(const GUID *g) { static const GUID z = {0}; return !memcmp(g, &z, sizeof z); }
static inline int cid_eq(const GUID *a, const GUID *b) { return !memcmp(a, b, sizeof *a); }
/* RFC 4122 version nibble and variant bits as laid out in the in-memory GUID. */
static inline int cid_version(const GUID *g) { return (g->Data3 >> 12) & 0xF; }
static inline int cid_variant_ok(const GUID *g) { return (g->Data4[0] & 0xC0) == 0x80; }
static inline int cid_cmp(const void *a, const void *b) { return memcmp(a, b, sizeof(GUID)); }
static inline int cid_in_image(const char *m, const void *p) {
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)m;
    const IMAGE_NT_HEADERS *n = (const IMAGE_NT_HEADERS *)(m + d->e_lfanew);
    return (const char *)p > m && (const char *)p < m + n->OptionalHeader.SizeOfImage;
}
#endif
