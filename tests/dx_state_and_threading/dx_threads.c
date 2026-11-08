/* Concurrency: many threads calling the non-UI exports while another thread loads/unloads the DLL,
 * DLL reload cycles, thread churn (DLL_THREAD_ATTACH/DETACH), and in-process error-table checks.
 * Heavy scenarios run in a child process with a timeout. */
#include "dx_common.h"

#define DX_REQ_ALL() dx_api a_; if (!dx_resolve(&a_)) { t_skip("missing export"); return; }

enum { K_VER, K_IUV, K_ERR, K_W3C, K_CID, K_CANCEL, K_MIX, K_N };
static const char *kname[K_N] = { "version", "iuvpaa", "errname", "w3c", "cancelid", "cancel", "mixed" };
static const int kmin[K_N] = { 2000, 40, 3000, 3000, 300, 100, 100 };

typedef struct {
    int kind, idx;
    LONG fails, calls, seen[3];
    GUID *guids; size_t nguids;
} wctx;
#define GCAP 20000

static dx_api g_api;
static DWORD g_base_ver;
static const wchar_t *g_first_name[DX_NTBL];
static const wchar_t *g_first_unknown;
static HANDLE g_start;
static volatile LONG g_loader_done;
static int g_loader, g_remote;
static ULONGLONG g_deadline;

#define W(c) do { if (!(c)) { if (InterlockedIncrement(&x->fails) <= 5) printf("  FAIL worker %d kind %s line %d: %s\n", x->idx, kname[x->kind], __LINE__, #c); } } while (0)

static void step(wctx *x, int kind, int it) {
    const dx_api *a = &g_api;
    switch (kind) {
    case K_VER: W(a->ver() == g_base_ver); break;
    case K_IUV: {
        BOOL b = 0x7777; HRESULT hr = a->iuv(&b);
        W(hr == 0); W(b != 0x7777);
        InterlockedIncrement(&x->seen[b == 0 ? 0 : b == 1 ? 1 : 2]);
        if (it % 8 == 0) W(a->iuv(NULL) == 0);
        break; }
    case K_ERR: {
        size_t i = (size_t)it % DX_NTBL;
        const wchar_t *p = a->ename(dx_tbl[i].hr);
        W(p && !lstrcmpW(p, dx_tbl[i].name)); W(p == g_first_name[i]);
        p = a->ename((HRESULT)0x80004005u);
        W(p && !lstrcmpW(p, L"UnknownError")); W(p == g_first_unknown);
        break; }
    case K_W3C: {
        size_t i = (size_t)it % DX_NTBL;
        W(a->w3c(dx_tbl[i].hr) == dx_tbl[i].dom);
        W(a->w3c((HRESULT)0x80004005u) == (HRESULT)0x80700000u);
        break; }
    case K_CID: {
        GUID g; memset(&g, 0, sizeof g);
        HRESULT hr = a->cid(&g);
        W(hr == 0 || hr == DX_HR_UUID_LOCAL_ONLY);
        if (hr == 0) { W(!dx_guid_zero(&g)); if (x->nguids < GCAP) x->guids[x->nguids++] = g; }
        break; }
    case K_CANCEL: {
        GUID g; memset(&g, 0, sizeof g);
        HRESULT hr = a->cid(&g);
        W(hr == 0 || hr == DX_HR_UUID_LOCAL_ONLY);
        HRESULT hx = a->cancel(&g);
        if (!g_remote) W(hx == 0);
        if (it % 5 == 0) W(a->cancel(NULL) == 0);
        if (it % 7 == 0) { GUID z; memset(&z, 0, sizeof z); hx = a->cancel(&z); if (!g_remote) W(hx == 0); }
        break; }
    default: break;
    }
    InterlockedIncrement(&x->calls);
}

static DWORD WINAPI worker(LPVOID p) {
    wctx *x = (wctx *)p;
    WaitForSingleObject(g_start, 30000);
    int min = kmin[x->kind == K_MIX ? K_MIX : x->kind];
    int cap = g_loader ? min * 20 : min;
    if (cap > 100000) cap = 100000;
    for (int it = 0; it < cap; it++) {
        if (it >= min && (!g_loader || g_loader_done)) break;
        if (GetTickCount64() > g_deadline) break;
        if (x->kind == K_MIX) step(x, it % 6, it); else step(x, x->kind, it);
    }
    return 0;
}

static DWORD WINAPI loader(LPVOID p) {
    HMODULE base = GetModuleHandleW(L"webauthn.dll");
    WaitForSingleObject(g_start, 30000);
    for (int i = 0; i < 100 && GetTickCount64() < g_deadline; i++) {
        HMODULE h = LoadLibraryW(L"webauthn.dll");
        if (h != base) { InterlockedIncrement(&dx_cfail); printf("  FAIL loader: LoadLibrary returned a different base\n"); }
        FARPROC f = h ? GetProcAddress(h, "WebAuthNGetApiVersionNumber") : NULL;
        if (f != (FARPROC)g_api.ver) { InterlockedIncrement(&dx_cfail); printf("  FAIL loader: export address changed\n"); }
        if (h && !FreeLibrary(h)) { InterlockedIncrement(&dx_cfail); printf("  FAIL loader: FreeLibrary failed\n"); }
        if (!GetModuleHandleW(L"webauthn.dll")) { InterlockedIncrement(&dx_cfail); printf("  FAIL loader: module vanished under active callers\n"); }
        SwitchToThread();
    }
    InterlockedExchange(&g_loader_done, 1);
    return 0;
}

CHILD(dx_stress) {
    int kind = -1, n = argc > 2 ? atoi(argv[2]) : 4; g_loader = argc > 3 ? atoi(argv[3]) : 0;
    for (int i = 0; i < K_N; i++) if (argc > 1 && !strcmp(argv[1], kname[i])) kind = i;
    if (kind < 0 || n < 1 || n > 64) return 98;
    HMODULE priv = LoadLibraryA("webauthn.dll");     /* private reference: the loader thread can never drop the last one */
    DXC(priv != NULL);
    if (!dx_resolve(&g_api)) return 97;
    g_remote = dx_is_remote();
    g_base_ver = g_api.ver();
    DXCF(g_base_ver <= 2, "version %lu", g_base_ver);
    for (size_t i = 0; i < DX_NTBL; i++) g_first_name[i] = g_api.ename(dx_tbl[i].hr);
    g_first_unknown = g_api.ename((HRESULT)0x80004005u);
    g_start = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_deadline = GetTickCount64() + 40000;
    wctx *ctx = (wctx *)calloc(n, sizeof *ctx);
    HANDLE th[70]; int nt = 0;
    for (int i = 0; i < n; i++) {
        ctx[i].kind = kind; ctx[i].idx = i;
        if (kind == K_CID || kind == K_MIX) ctx[i].guids = (GUID *)calloc(GCAP, sizeof(GUID));
        th[nt] = CreateThread(NULL, 0, worker, &ctx[i], 0, NULL);
        DXC(th[nt] != NULL); if (th[nt]) nt++;
    }
    if (g_loader) { th[nt] = CreateThread(NULL, 0, loader, NULL, 0, NULL); DXC(th[nt] != NULL); if (th[nt]) nt++; }
    SetEvent(g_start);
    if (WaitForMultipleObjects(nt, th, TRUE, 60000) != WAIT_OBJECT_0) {
        printf("  FAIL stress threads did not finish in 60 s (hang)\n");
        TerminateProcess(GetCurrentProcess(), 99);
    }
    LONG calls = 0, fails = 0, seen[3] = {0, 0, 0}; size_t ng = 0;
    for (int i = 0; i < n; i++) { calls += ctx[i].calls; fails += ctx[i].fails; for (int k = 0; k < 3; k++) seen[k] += ctx[i].seen[k]; ng += ctx[i].nguids; }
    DXCF(fails == 0, "%ld worker check failures", (long)fails);
    DXCF(calls >= n * (kmin[kind] < 100 ? kmin[kind] : 40), "only %ld calls completed before the deadline", (long)calls);
    if (ng) {
        GUID *all = (GUID *)malloc(ng * sizeof(GUID)); size_t o = 0;
        for (int i = 0; i < n; i++) { memcpy(all + o, ctx[i].guids, ctx[i].nguids * sizeof(GUID)); o += ctx[i].nguids; }
        size_t d = dx_dups(all, ng);
        DXCF(d == 0, "%lu duplicate cancellation ids out of %lu", (unsigned long)d, (unsigned long)ng);
        free(all);
    }
    if (kind == K_IUV) t_note("IUVPAA values seen: 0 x%ld, 1 x%ld, other x%ld", (long)seen[0], (long)seen[1], (long)seen[2]);
    t_note("stress %s threads=%d loader=%d calls=%ld", kname[kind], n, g_loader, (long)calls);
    DXC(GetModuleHandleW(L"webauthn.dll") != NULL);
    FreeLibrary(priv);
    return dx_rc();
}

#define STRESS(kind, n, ld) \
    TEST(dx_thr_##kind##_t##n##_ld##ld) { DX_REQ_ALL(); DX_CHILD_OK("dx_stress", #kind " " #n " " #ld, 120000); }
#define STRESS_KIND(kind) STRESS(kind, 2, 0) STRESS(kind, 8, 0) STRESS(kind, 32, 0) STRESS(kind, 2, 1) STRESS(kind, 8, 1) STRESS(kind, 32, 1)
STRESS_KIND(version)
STRESS_KIND(iuvpaa)
STRESS_KIND(errname)
STRESS_KIND(w3c)
STRESS_KIND(cancelid)
STRESS_KIND(cancel)
STRESS_KIND(mixed)

/* ---- DLL reload cycles: fully unload and reload, calling the exports each time ---- */
static void resolve_h(HMODULE h, dx_api *a) {
    a->ver = (__typeof__(a->ver))GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    a->iuv = (__typeof__(a->iuv))GetProcAddress(h, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    a->ename = (__typeof__(a->ename))GetProcAddress(h, "WebAuthNGetErrorName");
    a->w3c = (__typeof__(a->w3c))GetProcAddress(h, "WebAuthNGetW3CExceptionDOMError");
    a->cid = (__typeof__(a->cid))GetProcAddress(h, "WebAuthNGetCancellationId");
    a->cancel = (__typeof__(a->cancel))GetProcAddress(h, "WebAuthNCancelCurrentOperation");
}
static int have_all(const dx_api *a) { return a->ver && a->iuv && a->ename && a->w3c && a->cid && a->cancel; }
static void quick_pass(const dx_api *a) {
    DWORD v = a->ver(); DXCF(v <= 2, "version %lu", v);
    BOOL b = 0x7777; DXC(a->iuv(&b) == 0); DXC(b != 0x7777);
    for (size_t i = 0; i < DX_NTBL; i++) { const wchar_t *p = a->ename(dx_tbl[i].hr); DXC(p && !lstrcmpW(p, dx_tbl[i].name)); DXC(a->w3c(dx_tbl[i].hr) == dx_tbl[i].dom); }
    DXC(a->cancel(NULL) == 0);
}
CHILD(dx_reload) {
    int cycles = argc > 1 ? atoi(argv[1]) : 10, mode = argc > 2 ? atoi(argv[2]) : 0, stayed = 0;
    for (int i = 0; i < cycles; i++) {
        HMODULE h = LoadLibraryW(L"webauthn.dll");
        if (!h) { DXC(h != NULL); return dx_rc() ? dx_rc() : 96; }
        dx_api a; memset(&a, 0, sizeof a); resolve_h(h, &a);
        if (!have_all(&a)) return 97;
        quick_pass(&a);
        if (mode == 1) { BOOL b; for (int k = 0; k < 5; k++) a.iuv(&b); }
        DXC(FreeLibrary(h));
        if (GetModuleHandleW(L"webauthn.dll")) stayed++;
    }
    if (stayed) t_note("module stayed resident after the last FreeLibrary in %d of %d cycles", stayed, cycles);
    else t_note("module fully unloaded and reloaded %d times", cycles);
    return dx_rc();
}
TEST(dx_reload_cycles_10)  { DX_REQ_ALL(); DX_CHILD_OK("dx_reload", "10 0", 60000); }
TEST(dx_reload_cycles_100) { DX_REQ_ALL(); DX_CHILD_OK("dx_reload", "100 0", 120000); }
TEST(dx_reload_cycles_30_with_iuvpaa) { DX_REQ_ALL(); DX_CHILD_OK("dx_reload", "30 1", 120000); }

/* ---- thread churn: DLL_THREAD_ATTACH/DETACH with API use on short-lived threads ---- */
static dx_api g_churn;
static DWORD WINAPI churn_thread(LPVOID p) { quick_pass(&g_churn); return 0; }
CHILD(dx_churn) {
    int total = argc > 1 ? atoi(argv[1]) : 50, par = argc > 2 ? atoi(argv[2]) : 1;
    HMODULE priv = LoadLibraryA("webauthn.dll");
    resolve_h(priv, &g_churn);
    if (!have_all(&g_churn)) return 97;
    ULONGLONG dl = GetTickCount64() + 60000;
    for (int done = 0; done < total && GetTickCount64() < dl; done += par) {
        HANDLE th[16]; int nt = 0;
        for (int i = 0; i < par && i < 16; i++) { th[nt] = CreateThread(NULL, 0, churn_thread, NULL, 0, NULL); if (th[nt]) nt++; }
        DXC(nt == par || par > 16);
        if (WaitForMultipleObjects(nt, th, TRUE, 30000) != WAIT_OBJECT_0) { printf("  FAIL churn thread hang\n"); TerminateProcess(GetCurrentProcess(), 99); }
        for (int i = 0; i < nt; i++) CloseHandle(th[i]);
    }
    FreeLibrary(priv);
    return dx_rc();
}
TEST(dx_churn_serial_50)     { DX_REQ_ALL(); DX_CHILD_OK("dx_churn", "50 1", 90000); }
TEST(dx_churn_serial_300)    { DX_REQ_ALL(); DX_CHILD_OK("dx_churn", "300 1", 120000); }
TEST(dx_churn_parallel_8x20) { DX_REQ_ALL(); DX_CHILD_OK("dx_churn", "160 8", 120000); }
TEST(dx_churn_parallel_16x10){ DX_REQ_ALL(); DX_CHILD_OK("dx_churn", "160 16", 120000); }

/* ---- in-process: error-name / DOM-error table (pure lookups, no state) ---- */
static void expect_hr(HRESULT hr, const dx_api *a) {
    HRESULT dom; const wchar_t *n = dx_exp_name(hr, &dom);
    const wchar_t *p = a->ename(hr);
    t_check(p != NULL && !lstrcmpW(p, n), __FILE__, __LINE__, "GetErrorName(hr)", "hr=0x%08lx", (unsigned long)hr);
    t_check(a->w3c(hr) == dom, __FILE__, __LINE__, "GetW3CExceptionDOMError(hr)", "hr=0x%08lx got 0x%08lx want 0x%08lx", (unsigned long)hr, (unsigned long)a->w3c(hr), (unsigned long)dom);
}
TEST(dx_errmap_table) {
    DX_REQ_ALL();
    for (size_t i = 0; i < DX_NTBL; i++) expect_hr(dx_tbl[i].hr, &a_);
}
TEST(dx_errmap_sweep_nte_range) {      /* 0x80090000..0x800900FF (NTE_* family) */
    DX_REQ_ALL();
    for (unsigned h = 0x80090000u; h < 0x80090100u; h++) expect_hr((HRESULT)h, &a_);
}
TEST(dx_errmap_sweep_win32_low) {      /* 0x80070000..0x800700FF (HRESULT_FROM_WIN32 low) */
    DX_REQ_ALL();
    for (unsigned h = 0x80070000u; h < 0x80070100u; h++) expect_hr((HRESULT)h, &a_);
}
TEST(dx_errmap_sweep_cancelled_neighbourhood) {   /* around ERROR_CANCELLED / ERROR_TIMEOUT */
    DX_REQ_ALL();
    for (unsigned h = 0x800704B0u; h < 0x800704F0u; h++) expect_hr((HRESULT)h, &a_);
    for (unsigned h = 0x800705A0u; h < 0x800705C0u; h++) expect_hr((HRESULT)h, &a_);
}
TEST(dx_errmap_sweep_zero_neighbourhood) {
    DX_REQ_ALL();
    for (int h = -64; h <= 64; h++) expect_hr((HRESULT)h, &a_);
}
TEST(dx_errmap_sweep_generic_failures) {
    DX_REQ_ALL();
    static const unsigned v[] = { 0x80004001u, 0x80004002u, 0x80004004u, 0x80004005u, 0x8000FFFFu, 0x80070005u, 0x80070057u, 0x8007000Eu,
        0x800700AAu, 0x800710D2u, 0x80100001u, 0x80100002u, 0x8010000Bu, 0x80090001u, 0x80090005u, 0x80090008u, 0x8009002Au, 0x80090030u,
        0x80090034u, 0x80090037u, 0x80090020u, 0x80090022u, 0x80090024u, 0x80090025u, 0x80090026u, 0x80090028u, 0x8009002Bu,
        0x80700000u, 0x8070000Bu, 0x8070001Au, 0x80700023u, 0x80700009u, 0x80000000u, 0x7FFFFFFFu, 0xFFFFFFFFu, 0x00000001u, 0x00000100u, 0x40000000u };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) expect_hr((HRESULT)v[i], &a_);
}
TEST(dx_errmap_boundaries_of_not_allowed_range) {   /* 0x80090034 and 0x80090037 are outside, 0x80090035/36 inside */
    DX_REQ_ALL();
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090034u), L"UnknownError"));
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090035u), L"NotAllowedError"));
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090036u), L"NotAllowedError"));
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090037u), L"UnknownError"));
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090024u), L"UnknownError"));
    CHECK(!lstrcmpW(a_.ename((HRESULT)0x80090022u), L"UnknownError"));
}
TEST(dx_errmap_name_pointer_stable_and_static) {
    DX_REQ_ALL();
    for (size_t i = 0; i < DX_NTBL; i++) {
        const wchar_t *p = a_.ename(dx_tbl[i].hr), *q = a_.ename(dx_tbl[i].hr);
        CHECK(p != NULL); CHECK(p == q);
    }
    CHECK(a_.ename((HRESULT)0x80004005u) == a_.ename((HRESULT)0x12345678));
    CHECK(a_.ename(0) != NULL);
}
TEST(dx_errmap_name_domain_consistency) {
    DX_REQ_ALL();
    for (unsigned h = 0x80090000u; h < 0x80090040u; h++) {
        const wchar_t *p = a_.ename((HRESULT)h); HRESULT d = a_.w3c((HRESULT)h);
        HRESULT want = (HRESULT)0x80700000u;
        if (!lstrcmpW(p, L"NotAllowedError")) want = (HRESULT)0x80700023u;
        else if (!lstrcmpW(p, L"ConstraintError")) want = (HRESULT)0x8070001Au;
        else if (!lstrcmpW(p, L"InvalidStateError")) want = (HRESULT)0x8070000Bu;
        else if (!lstrcmpW(p, L"NotSupportedError")) want = (HRESULT)0x80700009u;
        CHECKF(d == want, "hr=0x%08lx", (unsigned long)h);
    }
}
TEST(dx_errmap_from_many_threads_inprocess) {
    DX_REQ_ALL();
    DX_CHILD_OK("dx_stress", "errname 16 0", 90000);
}
