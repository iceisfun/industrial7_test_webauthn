/* Shared helpers for the dx_state_and_threading area.
 *
 * Every state-changing / concurrency scenario runs in a CHILD process with a hard timeout, so a hang
 * or crash in the DLL under test is reported as a failed test instead of taking the run down.
 * Nothing here ever calls an API that can show UI or talk to an authenticator: only the
 * non-UI exports whose early behaviour is visible in the Windows 10 reference decompilation.
 *
 * Reference behaviour used for hard checks (Windows 10 x64, local session):
 *   WebAuthNGetApiVersionNumber()             -> 2 (0..2 in a remote session)
 *   WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(p)
 *        p == NULL -> returns 0 without touching anything
 *        else      -> *p is zeroed first, the return value is always S_OK (0)
 *   WebAuthNGetErrorName / WebAuthNGetW3CExceptionDOMError -> pure table lookups (see dx_tbl)
 *   WebAuthNGetCancellationId(g)              -> UuidCreate mapped to HRESULT (0 or 0x8007xxxx)
 *   WebAuthNCancelCurrentOperation(g)         -> always returns S_OK (NULL included)
 */
#ifndef DX_COMMON_H
#define DX_COMMON_H
#include "t.h"
#include <objbase.h>
#include <webauthn.h>
#include <stdlib.h>

#define DX_HR_UUID_LOCAL_ONLY ((HRESULT)0x80070720L)

/* ---- name / DOM error table (verified against the reference decompilation) ---- */
typedef struct { HRESULT hr; const wchar_t *name; HRESULT dom; } dx_ent;
#define DXE(h, n, d) { (HRESULT)(h), n, (HRESULT)(d) }
static const dx_ent dx_tbl[] = {
    DXE(0x00000000u, L"Success",           0x00000000u),
    DXE(0x8009000Fu, L"InvalidStateError", 0x8070000Bu),
    DXE(0x80090023u, L"ConstraintError",   0x8070001Au),
    DXE(0x80070032u, L"ConstraintError",   0x8070001Au),
    DXE(0x80090029u, L"ConstraintError",   0x8070001Au),
    DXE(0x80090011u, L"NotAllowedError",   0x80700023u),
    DXE(0x800704C7u, L"NotAllowedError",   0x80700023u),
    DXE(0x800705B4u, L"NotAllowedError",   0x80700023u),
    DXE(0x80090035u, L"NotAllowedError",   0x80700023u),
    DXE(0x80090036u, L"NotAllowedError",   0x80700023u),
    DXE(0x80090027u, L"NotSupportedError", 0x80700009u),
};
#define DX_NTBL (sizeof dx_tbl / sizeof dx_tbl[0])
static const wchar_t *dx_exp_name(HRESULT hr, HRESULT *dom) {
    for (size_t i = 0; i < DX_NTBL; i++) if (dx_tbl[i].hr == hr) { if (dom) *dom = dx_tbl[i].dom; return dx_tbl[i].name; }
    if (dom) *dom = (HRESULT)0x80700000u;
    return L"UnknownError";
}

/* ---- API pointers resolved through the harness (never linked) ---- */
typedef struct {
    __typeof__(&WebAuthNGetApiVersionNumber) ver;
    __typeof__(&WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable) iuv;
    __typeof__(&WebAuthNGetErrorName) ename;
    __typeof__(&WebAuthNGetW3CExceptionDOMError) w3c;
    __typeof__(&WebAuthNGetCancellationId) cid;
    __typeof__(&WebAuthNCancelCurrentOperation) cancel;
} dx_api;
static int dx_resolve(dx_api *a) {
    a->ver = U(WebAuthNGetApiVersionNumber);
    a->iuv = U(WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable);
    a->ename = U(WebAuthNGetErrorName);
    a->w3c = U(WebAuthNGetW3CExceptionDOMError);
    a->cid = U(WebAuthNGetCancellationId);
    a->cancel = U(WebAuthNCancelCurrentOperation);
    return a->ver && a->iuv && a->ename && a->w3c && a->cid && a->cancel;
}
UDECL(void, WebAuthNCtapStartDeviceChangeNotify, (void));
UDECL(void, WebAuthNCtapStopDeviceChangeNotify, (void));

/* ---- parent-side: run a child and judge its exit code ---- */
static const char *dx_rc_text(DWORD rc, char *buf, size_t cap) {
    if (rc == 0xDEAD0000) return "spawn failed";
    if (rc == 0xDEAD0001) return "TIMEOUT (hang), child killed";
    if ((rc & 0xF0000000) == 0xC0000000) { snprintf(buf, cap, "crashed 0x%08lx", rc); return buf; }
    snprintf(buf, cap, "exit code %lu (number of failed child checks)", rc); return buf;
}
#define DX_CHILD_OK(name, args, tmo) do { char b_[64]; DWORD rc_ = t_run_child(name, args, tmo); \
    t_check(rc_ == 0, __FILE__, __LINE__, "child " name " " args " exit 0", "%s", dx_rc_text(rc_, b_, sizeof b_)); } while (0)

/* ---- child-side check accounting ---- */
#define DXC(c) do { int ok_ = !!(c); if (!ok_) InterlockedIncrement(&dx_cfail); t_check(ok_, __FILE__, __LINE__, #c, NULL); } while (0)
#define DXCF(c, ...) do { int ok_ = !!(c); if (!ok_) InterlockedIncrement(&dx_cfail); t_check(ok_, __FILE__, __LINE__, #c, __VA_ARGS__); } while (0)
static volatile LONG dx_cfail;
static int dx_rc(void) { LONG f = dx_cfail; return f > 100 ? 100 : (int)f; }

static int dx_is_remote(void) { return GetSystemMetrics(SM_REMOTESESSION) != 0; }
static int dx_guid_zero(const GUID *g) { static const GUID z; return !memcmp(g, &z, sizeof z); }
static int dx_guid_cmp(const void *a, const void *b) { return memcmp(a, b, sizeof(GUID)); }
/* number of duplicate adjacent GUIDs after sorting */
static size_t dx_dups(GUID *v, size_t n) {
    size_t d = 0; qsort(v, n, sizeof(GUID), dx_guid_cmp);
    for (size_t i = 1; i < n; i++) if (!memcmp(&v[i - 1], &v[i], sizeof(GUID))) d++;
    return d;
}

/* One pass over every non-UI export; hard checks only on decompilation-proven values. */
static void dx_call_all(const dx_api *a, const char *label) {
    int remote = dx_is_remote();
    DWORD v = a->ver();
    DXCF(v <= 2, "%s: version %lu", label, v);
    if (!remote) DXCF(v == 2, "%s: version %lu", label, v);
    BOOL b = 0x7777;
    HRESULT hr = a->iuv(&b);
    DXCF(hr == 0, "%s: IUVPAA hr=0x%08lx", label, (unsigned long)hr);
    DXCF(b != 0x7777, "%s: *out was not written", label);
    t_note("%s: version=%lu IUVPAA hr=0x%08lx value=%ld", label, v, (unsigned long)hr, (long)b);
    DXC(a->iuv(NULL) == 0);
    for (size_t i = 0; i < DX_NTBL; i++) {
        const wchar_t *p = a->ename(dx_tbl[i].hr);
        DXC(p && !lstrcmpW(p, dx_tbl[i].name));
        DXC(a->w3c(dx_tbl[i].hr) == dx_tbl[i].dom);
    }
    GUID g; memset(&g, 0, sizeof g);
    HRESULT hc = a->cid(&g);
    DXCF(hc == 0 || hc == DX_HR_UUID_LOCAL_ONLY || (hc & 0xFFFF0000) == 0x80070000, "%s: cid hr=0x%08lx", label, (unsigned long)hc);
    if (hc == 0) DXC(!dx_guid_zero(&g));
    HRESULT hx = a->cancel(&g);
    if (!remote) DXCF(hx == 0, "%s: cancel hr=0x%08lx", label, (unsigned long)hx);
    else t_note("%s: remote-session cancel hr=0x%08lx", label, (unsigned long)hx);
    DXC(a->cancel(NULL) == 0);
    t_note("%s: GetCancellationId hr=0x%08lx cancel hr=0x%08lx", label, (unsigned long)hc, (unsigned long)hx);
}

/* Spawn a child with explicit creation flags and a hard timeout; returns the exit code (see t_run_child). */
static DWORD dx_run_flags(const char *name, const char *args, DWORD flags, DWORD tmo) {
    PROCESS_INFORMATION pi; DWORD code = 0xDEAD0000;
    HANDLE h = t_spawn_child(name, args, flags, NULL, NULL, NULL, FALSE, NULL, &pi);
    if (!h) return 0xDEAD0000;
    if (WaitForSingleObject(h, tmo) != WAIT_OBJECT_0) { TerminateProcess(h, 1); WaitForSingleObject(h, 5000); code = 0xDEAD0001; }
    else GetExitCodeProcess(h, &code);
    CloseHandle(pi.hThread); CloseHandle(h);
    return code;
}

/* Opt-out for the hardware-adjacent device-change tests (the whole dx_ exe is already opt-in). */
static int dx_gate_devnotify(void) {
    if (getenv("T_DX_NO_DEVNOTIFY")) { t_skip("T_DX_NO_DEVNOTIFY set"); return 0; }
    return 1;
}
#endif
