/* WebAuthNCtapStartDeviceChangeNotify / WebAuthNCtapStopDeviceChangeNotify: each is a thin wrapper that
 * sends a simple RPC command (2 = start, 3 = stop) to the platform service and ignores the result.
 * They take no arguments and cannot show UI. The only hard expectations are: no crash, no hang, and the
 * process stays usable. Every sequence ends with extra Stop calls so no notification is left registered.
 * Opt out with T_DX_NO_DEVNOTIFY=1. */
#include "dx_common.h"

#define DX_REQ_NOTIFY() \
    if (!dx_gate_devnotify()) return; \
    if (!UN(WebAuthNCtapStartDeviceChangeNotify) || !UN(WebAuthNCtapStopDeviceChangeNotify)) { t_skip("missing export"); return; }

static void (WINAPI *g_start)(void), (WINAPI *g_stop)(void);
static ULONGLONG g_dl;
static volatile LONG g_calls, g_idx;

typedef struct { int pattern, iters, id; } nctx;

static DWORD WINAPI nworker(LPVOID p) {
    nctx *c = (nctx *)p; unsigned seed = 12345u + c->id * 7919u;
    for (int i = 0; i < c->iters && GetTickCount64() < g_dl; i++) {
        switch (c->pattern) {
        case 0: g_start(); g_stop(); InterlockedAdd(&g_calls, 2); break;                     /* start/stop pairs */
        case 1: g_start(); InterlockedIncrement(&g_calls); break;                              /* start only */
        case 2: g_stop(); InterlockedIncrement(&g_calls); break;                               /* stop only */
        case 3: if (c->id & 1) g_start(); else g_stop(); InterlockedIncrement(&g_calls); break;  /* odd threads start, even stop */
        case 4: seed = seed * 1103515245u + 12345u; if ((seed >> 16) & 1) g_start(); else g_stop(); InterlockedIncrement(&g_calls); break;
        case 5: g_start(); g_start(); g_stop(); g_stop(); InterlockedAdd(&g_calls, 4); break;  /* doubled */
        case 6: g_stop(); g_start(); InterlockedAdd(&g_calls, 2); break;                       /* stop before start */
        default: break;
        }
    }
    return 0;
}

CHILD(dx_devnotify) {
    int pattern = argc > 1 ? atoi(argv[1]) : 0, nthreads = argc > 2 ? atoi(argv[2]) : 1, iters = argc > 3 ? atoi(argv[3]) : 10;
    g_start = (void (WINAPI *)(void))UN(WebAuthNCtapStartDeviceChangeNotify);
    g_stop = (void (WINAPI *)(void))UN(WebAuthNCtapStopDeviceChangeNotify);
    if (!g_start || !g_stop || nthreads < 1 || nthreads > 32) return 97;
    g_dl = GetTickCount64() + 45000;
    ULONGLONG t0 = GetTickCount64();
    nctx ctx[32]; HANDLE th[32]; int nt = 0;
    for (int i = 0; i < nthreads; i++) {
        ctx[i].pattern = pattern; ctx[i].iters = iters; ctx[i].id = i;
        th[nt] = CreateThread(NULL, 0, nworker, &ctx[i], 0, NULL); DXC(th[nt] != NULL); if (th[nt]) nt++;
    }
    if (WaitForMultipleObjects(nt, th, TRUE, 60000) != WAIT_OBJECT_0) {
        printf("  FAIL device-notify calls hung for 60 s\n");
        TerminateProcess(GetCurrentProcess(), 99);
    }
    for (int i = 0; i < nt; i++) CloseHandle(th[i]);
    g_stop(); g_stop(); g_stop();                        /* leave nothing registered */
    t_note("pattern %d threads %d iters %d: %ld calls", pattern, nthreads, iters, (long)g_calls);
    /* the process must still be able to use the rest of the DLL */
    dx_api a;
    if (dx_resolve(&a)) { BOOL b = 0x7777; DXC(a.iuv(&b) == 0); DXC(b != 0x7777); DXC(a.ver() <= 2); }
    return dx_rc();
}
#define NOTIFY(pattern_name, pat, thr, it) \
    TEST(dx_notify_##pattern_name##_t##thr##_i##it) { DX_REQ_NOTIFY(); DX_CHILD_OK("dx_devnotify", #pat " " #thr " " #it, 120000); }
NOTIFY(pairs, 0, 1, 1)
NOTIFY(pairs, 0, 1, 20)
NOTIFY(pairs, 0, 2, 20)
NOTIFY(pairs, 0, 4, 20)
NOTIFY(pairs, 0, 8, 10)
NOTIFY(start_only, 1, 1, 5)
NOTIFY(start_only, 1, 4, 5)
NOTIFY(stop_only, 2, 1, 5)
NOTIFY(stop_only, 2, 4, 5)
NOTIFY(split_roles, 3, 4, 10)
NOTIFY(split_roles, 3, 8, 10)
NOTIFY(random, 4, 4, 20)
NOTIFY(random, 4, 8, 20)
NOTIFY(doubled, 5, 1, 10)
NOTIFY(doubled, 5, 4, 5)
NOTIFY(stop_first, 6, 1, 10)
NOTIFY(stop_first, 6, 4, 5)

/* Sequential single-thread order variants in one child (explicit, readable orderings). */
CHILD(dx_devnotify_seq) {
    g_start = (void (WINAPI *)(void))UN(WebAuthNCtapStartDeviceChangeNotify);
    g_stop = (void (WINAPI *)(void))UN(WebAuthNCtapStopDeviceChangeNotify);
    if (!g_start || !g_stop) return 97;
    int which = argc > 1 ? atoi(argv[1]) : 0;
    switch (which) {
    case 0: g_stop(); break;                                  /* stop with nothing started */
    case 1: g_start(); g_stop(); break;
    case 2: g_start(); g_start(); g_stop(); break;
    case 3: g_start(); g_stop(); g_stop(); break;
    case 4: for (int i = 0; i < 5; i++) g_start(); for (int i = 0; i < 5; i++) g_stop(); break;
    case 5: g_start(); break;                                 /* start then process exit without stop */
    case 6: g_start(); Sleep(200); g_stop(); Sleep(200); g_start(); Sleep(200); g_stop(); break;
    default: return 98;
    }
    g_stop();
    return dx_rc();
}
#define SEQ(name, n) TEST(dx_notify_seq_##name) { DX_REQ_NOTIFY(); DX_CHILD_OK("dx_devnotify_seq", #n, 90000); }
SEQ(stop_without_start, 0)
SEQ(start_stop, 1)
SEQ(start_twice_stop_once, 2)
SEQ(stop_twice, 3)
SEQ(five_start_five_stop, 4)
SEQ(start_then_exit, 5)
SEQ(spaced_cycles, 6)

/* Exit while other threads are still inside the calls. */
static DWORD WINAPI spin_pairs(LPVOID p) { for (;;) { g_start(); g_stop(); } return 0; }
CHILD(dx_devnotify_exit_busy) {
    g_start = (void (WINAPI *)(void))UN(WebAuthNCtapStartDeviceChangeNotify);
    g_stop = (void (WINAPI *)(void))UN(WebAuthNCtapStopDeviceChangeNotify);
    if (!g_start || !g_stop) return 97;
    for (int i = 0; i < 4; i++) CreateThread(NULL, 0, spin_pairs, NULL, 0, NULL);
    Sleep(500);
    ExitProcess(0);
    return 0;
}
TEST(dx_notify_process_exit_while_calls_in_flight) {
    DX_REQ_NOTIFY();
    DX_CHILD_OK("dx_devnotify_exit_busy", "", 60000);
    DX_CHILD_OK("dx_devnotify_seq", "0", 60000);     /* a clean stop afterwards */
}
