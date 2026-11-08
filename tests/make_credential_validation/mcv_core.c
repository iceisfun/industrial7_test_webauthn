#include "mcv.h"
#include <stdlib.h>

static struct { const char *n; mcv_builder b; } g_b[1024];
static int g_nb;
void mcv_register(const char *name, mcv_builder b) { if (g_nb < 1024) { g_b[g_nb].n = name; g_b[g_nb].b = b; g_nb++; } }
static mcv_builder find(const char *n) { for (int i = 0; i < g_nb; i++) if (!strcmp(g_b[i].n, n)) return g_b[i].b; return NULL; }

static mcv_args g_a;   /* child-side storage (large; keep off the stack) */

static void fill_defaults(mcv_args *a) {
    memset(a, 0, sizeof *a);
    for (unsigned i = 0; i < sizeof a->userid; i++) a->userid[i] = (BYTE)(i * 7 + 1);
    for (unsigned i = 0; i < sizeof a->credid; i++) a->credid[i] = (BYTE)(0xA0 + i);
    const char *pre = "{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://example.com\"}";
    memset(a->json, 'x', sizeof a->json);
    memcpy(a->json, pre, strlen(pre));
    a->rp.dwVersion = 1; a->rp.pwszId = L"example.com"; a->rp.pwszName = L"Example RP";
    a->user.dwVersion = 1; a->user.cbId = 16; a->user.pbId = a->userid;
    a->user.pwszName = L"alice@example.com"; a->user.pwszDisplayName = L"Alice";
    a->cp[0].dwVersion = 1; a->cp[0].pwszCredentialType = L"public-key"; a->cp[0].lAlg = -7;
    a->cp[1].dwVersion = 1; a->cp[1].pwszCredentialType = L"public-key"; a->cp[1].lAlg = -257;
    a->cp[2].dwVersion = 1; a->cp[2].pwszCredentialType = L"public-key"; a->cp[2].lAlg = -8;
    a->cp[3].dwVersion = 1; a->cp[3].pwszCredentialType = L"public-key"; a->cp[3].lAlg = 3;
    a->cose.cCredentialParameters = 1; a->cose.pCredentialParameters = a->cp;
    a->cd.dwVersion = 1; a->cd.cbClientDataJSON = (DWORD)strlen(pre); a->cd.pbClientDataJSON = a->json; a->cd.pwszHashAlgId = L"SHA-256";
    for (int i = 0; i < MCV_NCRED; i++) {
        a->legacy[i].dwVersion = 1; a->legacy[i].cbId = 32; a->legacy[i].pbId = a->credid; a->legacy[i].pwszCredentialType = L"public-key";
        a->ex[i].dwVersion = 1; a->ex[i].cbId = 32; a->ex[i].pbId = a->credid; a->ex[i].pwszCredentialType = L"public-key";
        a->exp[i] = &a->ex[i];
    }
    a->prp = &a->rp; a->puser = &a->user; a->pcose = &a->cose; a->pcd = &a->cd; a->popts = NULL;
    a->hwnd_sel = MCV_HW_DESKTOP;
}

void mcv_use_opts(mcv_args *a, DWORD version) { memset(&a->opts, 0, sizeof a->opts); a->opts.dwVersion = version; a->popts = &a->opts; }
void mcv_bad_alg(mcv_args *a) { a->cp[0].lAlg = 0; }
void mcv_legacy_list(mcv_args *a, DWORD n) { a->opts.cCredentials = n; a->opts.pCredentials = n ? a->legacy : NULL; }
void mcv_ex_list(mcv_args *a, DWORD n) { a->list.cCredentials = n; a->list.ppCredentials = n ? a->exp : NULL; a->opts.pExcludeCredentialList = &a->list; }
void mcv_one_ext(mcv_args *a, PCWSTR id, DWORD cb, PVOID pv) {
    a->ext[0].pwszExtensionIdentifier = id; a->ext[0].cbExtension = cb; a->ext[0].pvExtension = pv;
    a->opts.cExtensions = 1; a->opts.pExtensions = a->ext;
}

/* ---- window helpers (user32 resolved dynamically; never linked) ---- */
typedef HWND (WINAPI *pCreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef BOOL (WINAPI *pDestroyWindow)(HWND);
typedef HWND (WINAPI *pGetDesktopWindow)(void);
typedef HWND (WINAPI *pGetShellWindow)(void);
static int resolve_hwnd(mcv_args *a) {
    if (a->hwnd_sel == -1) { a->hwnd = NULL; return 1; }   /* explicit NULL */
    HMODULE u = LoadLibraryA("user32.dll");
    if (!u) return a->hwnd_sel == MCV_HW_ONE || a->hwnd_sel == MCV_HW_MINUS1 || a->hwnd_sel == MCV_HW_JUNK;
    pCreateWindowExA cw = (pCreateWindowExA)GetProcAddress(u, "CreateWindowExA");
    pDestroyWindow dw = (pDestroyWindow)GetProcAddress(u, "DestroyWindow");
    switch (a->hwnd_sel) {
    case MCV_HW_DESKTOP: { pGetDesktopWindow g = (pGetDesktopWindow)GetProcAddress(u, "GetDesktopWindow"); a->hwnd = g ? g() : (HWND)(ULONG_PTR)0x10010; return a->hwnd != NULL; }
    case MCV_HW_ONE: a->hwnd = (HWND)(ULONG_PTR)1; return 1;
    case MCV_HW_MINUS1: a->hwnd = (HWND)(LONG_PTR)-1; return 1;
    case MCV_HW_JUNK: a->hwnd = (HWND)(ULONG_PTR)0xDEADBEEFull; return 1;
    case MCV_HW_STATIC: case MCV_HW_DESTROYED: {
        if (!cw) return 0;
        HWND w = cw(0, "STATIC", "mcv", WS_POPUP, 0, 0, 1, 1, NULL, NULL, GetModuleHandleA(NULL), NULL);
        if (!w) return 0;
        if (a->hwnd_sel == MCV_HW_DESTROYED) { if (!dw || !dw(w)) return 0; }
        a->hwnd = w; return 1; }
    case MCV_HW_MSGONLY: {
        if (!cw) return 0;
        HWND w = cw(0, "STATIC", "mcv", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandleA(NULL), NULL);
        if (!w) return 0;
        a->hwnd = w; return 1; }
    case MCV_HW_OTHERPROC: {
        pGetShellWindow g = (pGetShellWindow)GetProcAddress(u, "GetShellWindow");
        HWND w = g ? g() : NULL;
        if (!w) return 0;
        DWORD pid = 0; typedef DWORD (WINAPI *pGT)(HWND, LPDWORD); pGT gt = (pGT)GetProcAddress(u, "GetWindowThreadProcessId");
        if (gt) gt(w, &pid);
        if (!pid || pid == GetCurrentProcessId()) return 0;
        a->hwnd = w; return 1; }
    }
    return 0;
}

/* child: argv[1]=builder, argv[2]=parameter, argv[3]=repetitions. Exit code = the HRESULT returned. */
CHILD(mcv_call) {
    if (argc < 4) return 0xC0DE0002;
    mcv_builder b = find(argv[1]);
    if (!b) return 0xC0DE0003;
    long long p = _atoi64(argv[2]); int reps = atoi(argv[3]); if (reps < 1) reps = 1;
    mcv_args *a = &g_a;
    fill_defaults(a);
    b(a, p);
    if (!resolve_hwnd(a)) return (int)MCV_X_SETUP;
    WebAuthNAuthenticatorMakeCredential_pfn fn = UN(WebAuthNAuthenticatorMakeCredential);
    if (!fn) return (int)MCV_X_NO_EXPORT;
    HRESULT first = 0;
    for (int r = 0; r < reps; r++) {
        PVOID att = (PVOID)(ULONG_PTR)0x1;   /* sentinel: never dereferenced, must be overwritten with NULL */
        HRESULT hr = fn(a->hwnd, a->prp, a->puser, a->pcose, a->pcd, a->popts, &att);
        if (att != NULL) return (int)MCV_X_PP_NOT_RESET;
        if (r == 0) first = hr; else if (hr != first) return (int)MCV_X_UNSTABLE;
    }
    return (int)first;
}

DWORD mcv_run(const char *name, long long p, int reps) {
    char args[256]; snprintf(args, sizeof args, "%s %lld %d", name, p, reps);
    return t_run_child("mcv_call", args, 10000);
}

int mcv_expect(const char *name, long long p, DWORD want, int reps) {
    DWORD got = mcv_run(name, p, reps);
    if (got == MCV_X_SETUP) { t_note("%s p=%lld: environment cannot provide the requested window handle", name, p); return -1; }
    int ok = (got == want);
    CHECKF(got != 0xDEAD0001, "%s p=%lld: child timed out (call may have blocked)", name, p);
    CHECKF(got != MCV_X_PP_NOT_RESET, "%s p=%lld: *ppWebAuthNCredentialAttestation was not reset to NULL", name, p);
    CHECKF(got != MCV_X_UNSTABLE, "%s p=%lld: repeated calls returned different results", name, p);
    CHECKF(ok, "%s p=%lld: got 0x%08lx want 0x%08lx", name, p, (unsigned long)got, (unsigned long)want);
    return ok;
}
