/* Shared declarations for the ctap_helpers_misc area (declared locally: the SDK headers lack these). */
#ifndef CTAP_MISC_H
#define CTAP_MISC_H
#include "t.h"

/* WEBAUTHN_CTAP_TRANSPORT_* bits */
#define CM_TRANSPORT_USB      0x00000001u
#define CM_TRANSPORT_NFC      0x00000002u
#define CM_TRANSPORT_BLE      0x00000004u
#define CM_TRANSPORT_TEST     0x00000008u
#define CM_TRANSPORT_INTERNAL 0x00000010u
#define CM_TRANSPORT_HYBRID   0x00000020u
#define CM_TRANSPORT_KNOWN    0x0000003Fu

/* BOOL WebAuthNCtapIsStopSendCommandError(HRESULT hr) -- 0/1 in rax */
UDECL(BOOL, WebAuthNCtapIsStopSendCommandError, (HRESULT hr));
/* HRESULT WebAuthNCtapGetSupportedTransports(DWORD *pdwTransports, const GUID *pCorrelationId OPTIONAL) */
UDECL(HRESULT, WebAuthNCtapGetSupportedTransports, (DWORD *pdwTransports, const GUID *pCorrelationId));
/* HRESULT WebAuthNCtapGetWnfLocalizedString(DWORD id, int category, int hr, int extra, LPWSTR *ppsz, DWORD *pdwFallback) */
UDECL(HRESULT, WebAuthNCtapGetWnfLocalizedString, (DWORD a, int b, int c, int d, LPWSTR *ppsz, DWORD *pdwFallback));
/* void WebAuthNCtapFreeSelectedDeviceInformation(void *p)  (LocalFree wrapper, NULL tolerated) */
UDECL(void, WebAuthNCtapFreeSelectedDeviceInformation, (void *p));
/* void WebAuthNCtapStartDeviceChangeNotify(void) / Stop...(void): no parameters, no result */
UDECL(void, WebAuthNCtapStartDeviceChangeNotify, (void));
UDECL(void, WebAuthNCtapStopDeviceChangeNotify, (void));
/* ULONG CryptsvcDllCtrl(ULONG op, ULONG a, ULONG b, void *p) */
UDECL(ULONG, CryptsvcDllCtrl, (ULONG op, ULONG a, ULONG b, void *p));
/* HRESULT VirtualChannelGetInstance(REFGUID iid, ULONG *pcount, void **ppv) */
UDECL(LONG, VirtualChannelGetInstance, (const GUID *iid, ULONG *pcount, void **ppv));

#endif
