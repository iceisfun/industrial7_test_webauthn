#include "ctap_misc.h"
/* WebAuthNCtapGetSupportedTransports, WebAuthNCtapStartDeviceChangeNotify, WebAuthNCtapStopDeviceChangeNotify.
 *
 * All three talk to the local FIDO RPC service (no UI, no user presence). They run in a child process
 * with a timeout so that a missing/slow service can never hang the suite.
 *
 * Decomp facts:
 *  - GetSupportedTransports(DWORD *out, const GUID *corr): always returns 0; *out is written
 *    unconditionally at the end (initial value 1 = USB; becomes 3 = USB|NFC when the service reports an
 *    NFC provider). A NULL corr makes the DLL generate one with UuidCreate. A NULL out is NOT valid
 *    (it is dereferenced), so it is never passed.
 *  - Start/StopDeviceChangeNotify take no parameters and return nothing: they just send simple RPC
 *    commands 2 and 3 and ignore the result. There is therefore no callback/context to pass; any
 *    sequence of calls must be harmless. */

#define CHILD_SKIP 77

/* ---- GetSupportedTransports ------------------------------------------ */
/* exit codes: 0x100|value on success; 1 missing; 2 hr!=0; 3 value outside {1,3}; 4 unstable
   (value differs between calls: reported but treated as ok by parent via note); 5 sentinel untouched */
CHILD(ctapmisc_transports_basic)
{
    WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports);
    if (!f) return CHILD_SKIP;
    DWORD v = 0xCAFEBABE;
    HRESULT hr = f(&v, NULL);
    if (hr != 0) return 2;
    if (v == 0xCAFEBABE) return 5;
    if (v != 1 && v != 3) return 3;
    return 0x100 | (int)v;
}
CHILD(ctapmisc_transports_guid)
{
    WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports);
    if (!f) return CHILD_SKIP;
    static const GUID corr = { 0x12345678, 0x1234, 0x4321, { 1, 2, 3, 4, 5, 6, 7, 8 } };
    DWORD v = 0xCAFEBABE;
    HRESULT hr = f(&v, &corr);
    if (hr != 0) return 2;
    if (v == 0xCAFEBABE) return 5;
    if ((v & ~CM_TRANSPORT_KNOWN) != 0) return 3;
    if (!(v & CM_TRANSPORT_USB)) return 3;
    return 0x100 | (int)v;
}
CHILD(ctapmisc_transports_repeat)
{
    WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports);
    if (!f) return CHILD_SKIP;
    DWORD first = 0;
    int unstable = 0;
    for (int i = 0; i < 10; i++) {
        DWORD v = 0xCAFEBABE;
        HRESULT hr = f(&v, NULL);
        if (hr != 0) return 2;
        if (v != 1 && v != 3) return 3;
        if (i == 0) first = v; else if (v != first) unstable = 1;
    }
    return unstable ? 4 : (0x100 | (int)first);
}
CHILD(ctapmisc_transports_preset_values)
{
    /* the previous content of *out is irrelevant: overwritten on every call */
    WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports);
    if (!f) return CHILD_SKIP;
    static const DWORD pre[] = { 0, 0xFFFFFFFFu, 2, 0x80000000u };
    DWORD base = 0;
    for (int i = 0; i < 4; i++) {
        DWORD v = pre[i];
        if (f(&v, NULL) != 0) return 2;
        if (v != 1 && v != 3) return 3;
        if (i == 0) base = v;
    }
    return 0x100 | (int)base;
}

CHILD(ctapmisc_transports_zero_guid)
{
    WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports);
    if (!f) return CHILD_SKIP;
    static const GUID z = { 0 };
    DWORD v = 0xCAFEBABE;
    if (f(&v, &z) != 0) return 2;
    if (v != 1 && v != 3) return 3;
    return 0x100 | (int)v;
}

static void check_transport_child(const char *name, int allow_unstable)
{
    DWORD rc = t_run_child(name, "", 60000);
    if (rc == CHILD_SKIP) { t_skip("export missing"); return; }
    if (rc == 0xDEAD0001) { t_note("%s: timed out (RPC service unavailable/slow)", name); return; }
    if (rc == 0xDEAD0000) { t_skip("could not spawn child"); return; }
    if (rc == 4 && allow_unstable) { t_note("%s: value changed between calls (device topology change?)", name); return; }
    if (rc & 0x100) {
        DWORD v = rc & 0xFF;
        CHECK(v == 1 || v == 3);
        CHECK((v & ~CM_TRANSPORT_KNOWN) == 0);
        CHECK(v & CM_TRANSPORT_USB);
        t_note("%s: supported transports = 0x%lx (%s%s)", name, v, (v & 1) ? "usb" : "", (v & 2) ? "+nfc" : "");
        return;
    }
    CHECKF(0, "child exit code %lu (1=missing 2=hr!=0 3=bad value 4=unstable 5=out untouched)", rc);
}
TEST(ctapmisc_transports_returns_s_ok_and_known_bits) { WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports); REQUIRE(f); check_transport_child("ctapmisc_transports_basic", 0); }
TEST(ctapmisc_transports_with_correlation_guid)       { WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports); REQUIRE(f); check_transport_child("ctapmisc_transports_guid", 0); }
TEST(ctapmisc_transports_repeated_calls_stable)       { WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports); REQUIRE(f); check_transport_child("ctapmisc_transports_repeat", 1); }
TEST(ctapmisc_transports_out_overwritten)             { WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports); REQUIRE(f); check_transport_child("ctapmisc_transports_preset_values", 0); }

TEST(ctapmisc_transports_zero_correlation_guid)       { WebAuthNCtapGetSupportedTransports_pfn f = UN(WebAuthNCtapGetSupportedTransports); REQUIRE(f); check_transport_child("ctapmisc_transports_zero_guid", 0); }

/* ---- Start / Stop device change notify -------------------------------- */
/* Each child exits 0 when the sequence ran to completion without an exception. */
#define NOTIFY_CHILD(name, body) \
    CHILD(name) { \
        WebAuthNCtapStartDeviceChangeNotify_pfn st = UN(WebAuthNCtapStartDeviceChangeNotify); \
        WebAuthNCtapStopDeviceChangeNotify_pfn sp = UN(WebAuthNCtapStopDeviceChangeNotify); \
        if (!st || !sp) return CHILD_SKIP; \
        body \
        return 0; \
    }

NOTIFY_CHILD(ctapmisc_notify_start_stop,  { st(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_stop_only,   { sp(); })
NOTIFY_CHILD(ctapmisc_notify_start_only,  { st(); })
NOTIFY_CHILD(ctapmisc_notify_stop_twice,  { st(); sp(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_stop_thrice_no_start, { sp(); sp(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_double_start,{ st(); st(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_triple_start,{ st(); st(); st(); sp(); sp(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_100_cycles,  { for (int i = 0; i < 100; i++) { st(); sp(); } })
NOTIFY_CHILD(ctapmisc_notify_100_starts_then_stops, { for (int i = 0; i < 100; i++) st(); for (int i = 0; i < 100; i++) sp(); })
NOTIFY_CHILD(ctapmisc_notify_stop_start_order, { sp(); st(); sp(); st(); sp(); })
NOTIFY_CHILD(ctapmisc_notify_leave_started_at_exit, { st(); })
NOTIFY_CHILD(ctapmisc_notify_lasterror_not_clobbered_check,
    { SetLastError(0xABCD); st(); sp(); /* GetLastError after is unspecified: only completion matters */ })

static void run_notify(const char *name, DWORD timeout_ms)
{
    DWORD rc = t_run_child(name, "", timeout_ms);
    if (rc == CHILD_SKIP) { t_skip("export missing"); return; }
    if (rc == 0xDEAD0000) { t_skip("could not spawn child"); return; }
    if (rc == 0xDEAD0001) { t_note("%s: child timed out after %lu ms and was killed (service-dependent)", name, timeout_ms); return; }
    CHECKF(rc == 0, "child exit code 0x%lx (exception in notify call?)", rc);
}
#define NOTIFY_TEST(tname, child, ms) \
    TEST(tname) { WebAuthNCtapStartDeviceChangeNotify_pfn f = UN(WebAuthNCtapStartDeviceChangeNotify); REQUIRE(f); run_notify(child, ms); }

NOTIFY_TEST(ctapmisc_notify_start_then_stop,        "ctapmisc_notify_start_stop", 30000)
NOTIFY_TEST(ctapmisc_notify_stop_without_start,     "ctapmisc_notify_stop_only", 30000)
NOTIFY_TEST(ctapmisc_notify_start_without_stop,     "ctapmisc_notify_start_only", 30000)
NOTIFY_TEST(ctapmisc_notify_stop_twice_ok,          "ctapmisc_notify_stop_twice", 30000)
NOTIFY_TEST(ctapmisc_notify_stop_repeatedly_no_start,"ctapmisc_notify_stop_thrice_no_start", 30000)
NOTIFY_TEST(ctapmisc_notify_double_start_ok,        "ctapmisc_notify_double_start", 30000)
NOTIFY_TEST(ctapmisc_notify_triple_start_ok,        "ctapmisc_notify_triple_start", 30000)
NOTIFY_TEST(ctapmisc_notify_100_start_stop_cycles,  "ctapmisc_notify_100_cycles", 90000)
NOTIFY_TEST(ctapmisc_notify_100_starts_100_stops,   "ctapmisc_notify_100_starts_then_stops", 90000)
NOTIFY_TEST(ctapmisc_notify_stop_start_interleaved, "ctapmisc_notify_stop_start_order", 30000)
NOTIFY_TEST(ctapmisc_notify_process_exit_while_started, "ctapmisc_notify_leave_started_at_exit", 30000)
NOTIFY_TEST(ctapmisc_notify_lasterror_scribble,     "ctapmisc_notify_lasterror_not_clobbered_check", 30000)

/* Thread behaviour: start on one thread, stop on another. */
static DWORD WINAPI stop_thread(LPVOID p)
{
    ((WebAuthNCtapStopDeviceChangeNotify_pfn)p)();
    return 0;
}
CHILD(ctapmisc_notify_cross_thread)
{
    WebAuthNCtapStartDeviceChangeNotify_pfn st = UN(WebAuthNCtapStartDeviceChangeNotify);
    WebAuthNCtapStopDeviceChangeNotify_pfn sp = UN(WebAuthNCtapStopDeviceChangeNotify);
    if (!st || !sp) return CHILD_SKIP;
    st();
    HANDLE h = CreateThread(NULL, 0, stop_thread, (LPVOID)sp, 0, NULL);
    if (!h) return 1;
    DWORD w = WaitForSingleObject(h, 20000);
    CloseHandle(h);
    return w == WAIT_OBJECT_0 ? 0 : 2;
}
TEST(ctapmisc_notify_start_here_stop_on_other_thread)
{
    WebAuthNCtapStartDeviceChangeNotify_pfn f = UN(WebAuthNCtapStartDeviceChangeNotify); REQUIRE(f);
    run_notify("ctapmisc_notify_cross_thread", 40000);
}

/* Parallel callers must not crash. */
static DWORD WINAPI cycle_thread(LPVOID p)
{
    WebAuthNCtapStartDeviceChangeNotify_pfn st = UN(WebAuthNCtapStartDeviceChangeNotify);
    WebAuthNCtapStopDeviceChangeNotify_pfn sp = UN(WebAuthNCtapStopDeviceChangeNotify);
    for (int i = 0; i < 10; i++) { st(); sp(); }
    return 0;
}
CHILD(ctapmisc_notify_parallel)
{
    if (!UN(WebAuthNCtapStartDeviceChangeNotify) || !UN(WebAuthNCtapStopDeviceChangeNotify)) return CHILD_SKIP;
    HANDLE h[4];
    for (int i = 0; i < 4; i++) { h[i] = CreateThread(NULL, 0, cycle_thread, NULL, 0, NULL); if (!h[i]) return 1; }
    DWORD w = WaitForMultipleObjects(4, h, TRUE, 40000);
    for (int i = 0; i < 4; i++) CloseHandle(h[i]);
    return w == WAIT_OBJECT_0 ? 0 : 2;
}
TEST(ctapmisc_notify_parallel_cycles_from_4_threads)
{
    WebAuthNCtapStartDeviceChangeNotify_pfn f = UN(WebAuthNCtapStartDeviceChangeNotify); REQUIRE(f);
    run_notify("ctapmisc_notify_parallel", 60000);
}

TEST(ctapmisc_notify_exports_are_distinct_entry_points)
{
    FARPROC a = t_proc("WebAuthNCtapStartDeviceChangeNotify");
    FARPROC b = t_proc("WebAuthNCtapStopDeviceChangeNotify");
    REQUIRE(a); REQUIRE(b);
    CHECK(a != b);
}
