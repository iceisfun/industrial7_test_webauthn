/* Shared helpers for the api_version_platform area: PE image walking over the loaded module,
 * COM scaffolding resolved at run time, and typedefs for the two API-version/platform exports. */
#ifndef APV_H
#define APV_H
#include "t.h"
#include <objbase.h>
#include <stdint.h>
#include <webauthn.h>   /* declarations only: the DLL is never linked */

/* ole32 is not linked by the harness build: resolve the two COM calls we need at run time. */
static inline HRESULT apv_CoInitializeEx(LPVOID r, DWORD f) {
    typeof(&CoInitializeEx) p = (typeof(&CoInitializeEx))t_proc_in("ole32.dll", "CoInitializeEx");
    return p ? p(r, f) : E_NOTIMPL;
}
static inline void apv_CoUninitialize(void) {
    typeof(&CoUninitialize) p = (typeof(&CoUninitialize))t_proc_in("ole32.dll", "CoUninitialize");
    if (p) p();
}
#define CoInitializeEx apv_CoInitializeEx
#define CoUninitialize apv_CoUninitialize

#define APV_DLL "webauthn.dll"

/* The loaded module, or NULL (Wine without the DLL). */
static inline HMODULE apv_mod(void) { return t_module(APV_DLL); }
#define APV_REQUIRE_MOD(h) HMODULE h = apv_mod(); if (!(h)) { t_skip(APV_DLL " not loadable here"); return; }

/* ---- PE walking over the mapped image ---------------------------------- */
static inline const IMAGE_NT_HEADERS64 *apv_nt(HMODULE m) {
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)m;
    if (!m || d->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    const IMAGE_NT_HEADERS64 *n = (const IMAGE_NT_HEADERS64 *)((const BYTE *)m + d->e_lfanew);
    return n->Signature == IMAGE_NT_SIGNATURE ? n : NULL;
}
static inline const IMAGE_DATA_DIRECTORY *apv_dd(HMODULE m, int idx) {
    const IMAGE_NT_HEADERS64 *n = apv_nt(m);
    if (!n || (DWORD)idx >= n->OptionalHeader.NumberOfRvaAndSizes) return NULL;
    return &n->OptionalHeader.DataDirectory[idx];
}
static inline const void *apv_rva(HMODULE m, DWORD rva) { return (const BYTE *)m + rva; }
static inline const IMAGE_SECTION_HEADER *apv_sections(HMODULE m, int *count) {
    const IMAGE_NT_HEADERS64 *n = apv_nt(m);
    if (!n) return NULL;
    *count = n->FileHeader.NumberOfSections;
    return IMAGE_FIRST_SECTION(n);
}
static inline const IMAGE_SECTION_HEADER *apv_section_of_rva(HMODULE m, DWORD rva) {
    int c; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    for (int i = 0; s && i < c; i++) {
        DWORD sz = s[i].Misc.VirtualSize > s[i].SizeOfRawData ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
        if (rva >= s[i].VirtualAddress && rva < s[i].VirtualAddress + sz) return &s[i];
    }
    return NULL;
}
static inline const IMAGE_SECTION_HEADER *apv_section_named(HMODULE m, const char *name) {
    int c; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    for (int i = 0; s && i < c; i++) if (!strncmp((const char *)s[i].Name, name, 8)) return &s[i];
    return NULL;
}
static inline const IMAGE_EXPORT_DIRECTORY *apv_expdir(HMODULE m) {
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_EXPORT);
    return d && d->VirtualAddress ? (const IMAGE_EXPORT_DIRECTORY *)apv_rva(m, d->VirtualAddress) : NULL;
}

/* Delay-load descriptor (IMAGE_DELAYLOAD_DESCRIPTOR); all fields are RVAs on x64. */
typedef struct {
    DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA,
          BoundImportAddressTableRVA, UnloadInformationTableRVA, TimeDateStamp;
} apv_delay_desc;

/* ---- the two functions of this area ------------------------------------- */
typedef DWORD   (WINAPI *apv_getver_fn)(void);
typedef HRESULT (WINAPI *apv_iuvpaa_fn)(BOOL *);
/* A missing export yields a stub that returns an impossible value, so a stand-in lacking the entry
 * point fails the checks instead of crashing the whole run. */
static DWORD WINAPI apv_stub_getver(void) { return 0xFFFFFFFFu; }
static HRESULT WINAPI apv_stub_iuvpaa(BOOL *p) { (void)p; return E_NOTIMPL; }
static inline apv_getver_fn apv_getver(void) {
    apv_getver_fn f = (apv_getver_fn)GetProcAddress(apv_mod(), "WebAuthNGetApiVersionNumber");
    return f ? f : apv_stub_getver;
}
static inline apv_iuvpaa_fn apv_iuvpaa(void) {
    apv_iuvpaa_fn f = (apv_iuvpaa_fn)GetProcAddress(apv_mod(), "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    return f ? f : apv_stub_iuvpaa;
}

/* True when this process runs inside a Remote Desktop session; the API-version and IUVPAA
 * entry points take a different (remote) path there, so exact values are only asserted locally. */
static inline int apv_is_remote_session(void) { return GetSystemMetrics(SM_REMOTESESSION) != 0; }

/* Wait for a thread with a bound; terminates it on timeout so the run cannot hang. */
static inline int apv_join(HANDLE h, DWORD ms) {
    if (WaitForSingleObject(h, ms) == WAIT_OBJECT_0) { CloseHandle(h); return 1; }
    TerminateThread(h, 0xDEAD); CloseHandle(h); return 0;
}
#endif
