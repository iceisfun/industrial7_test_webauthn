/* Cancellation-id lifecycle: create many ids, cancel subsets, cancel twice, cancel from other threads.
 * WebAuthNCancelCurrentOperation on an id with no pending operation is a no-op that returns S_OK
 * (the exported wrapper discards the inner status), so every cancel below must return 0.
 * Nothing here starts an operation, so no UI can appear. */
#include "dx_common.h"

#define DX_REQ_ALL() dx_api a_; if (!dx_resolve(&a_)) { t_skip("missing export"); return; }

static dx_api g_a;
static int g_remote_c;
static ULONGLONG g_dl;
static volatile LONG g_slow;

static int cancel_ok(const GUID *g, const char *what) {
    HRESULT hr = g_a.cancel(g);
    if (g_remote_c) return 1;
    if (hr != 0) { DXCF(hr == 0, "%s: cancel hr=0x%08lx", what, (unsigned long)hr); return 0; }
    return 1;
}
static int mk(GUID *g) {
    memset(g, 0, sizeof *g);
    HRESULT hr = g_a.cid(g);
    if (hr == DX_HR_UUID_LOCAL_ONLY) return 0;
    DXCF(hr == 0, "GetCancellationId hr=0x%08lx", (unsigned long)hr);
    return hr == 0;
}

typedef struct { GUID *ids; size_t lo, hi; int step; } slice;
static DWORD WINAPI cancel_slice(LPVOID p) {
    slice *s = (slice *)p;
    for (size_t i = s->lo; i < s->hi && GetTickCount64() < g_dl; i += s->step) cancel_ok(&s->ids[i], "slice");
    return 0;
}
static DWORD WINAPI create_slice(LPVOID p) {
    slice *s = (slice *)p;
    for (size_t i = s->lo; i < s->hi; i++) mk(&s->ids[i]);
    return 0;
}

CHILD(dx_cancel) {
    int mode = argc > 1 ? atoi(argv[1]) : 0; size_t count = argc > 2 ? (size_t)atoi(argv[2]) : 1000;
    if (count < 2 || count > 100000) return 98;
    if (!dx_resolve(&g_a)) return 97;
    g_remote_c = dx_is_remote();
    g_dl = GetTickCount64() + 90000;
    GUID *ids = (GUID *)calloc(count, sizeof(GUID));
    size_t i;
    if (mode == 0) {                              /* create all, cancel odd, then even, then everything again */
        for (i = 0; i < count; i++) mk(&ids[i]);
        GUID *cp = (GUID *)malloc(count * sizeof(GUID)); memcpy(cp, ids, count * sizeof(GUID));
        size_t d = dx_dups(cp, count);
        DXCF(d == 0, "%lu duplicate ids in %lu", (unsigned long)d, (unsigned long)count);
        free(cp);
        for (i = 0; i < count; i++) DXC(!dx_guid_zero(&ids[i]));
        for (i = 1; i < count && GetTickCount64() < g_dl; i += 2) cancel_ok(&ids[i], "odd");
        for (i = 0; i < count && GetTickCount64() < g_dl; i += 2) cancel_ok(&ids[i], "even");
        for (i = 0; i < count && GetTickCount64() < g_dl; i++) cancel_ok(&ids[i], "again");
        if (i < count) t_note("deadline reached after %lu repeated cancels", (unsigned long)i);
    } else if (mode == 1) {                       /* four threads cancel overlapping stripes of the same ids */
        for (i = 0; i < count; i++) mk(&ids[i]);
        slice s[4]; HANDLE th[4];
        for (int k = 0; k < 4; k++) { s[k].ids = ids; s[k].lo = (size_t)(k % 2); s[k].hi = count; s[k].step = 2; th[k] = CreateThread(NULL, 0, cancel_slice, &s[k], 0, NULL); }
        if (WaitForMultipleObjects(4, th, TRUE, 100000) != WAIT_OBJECT_0) { printf("  FAIL hang\n"); TerminateProcess(GetCurrentProcess(), 99); }
    } else if (mode == 2) {                       /* special values and heavy repetition of one id */
        GUID z, ff; memset(&z, 0, sizeof z); memset(&ff, 0xFF, sizeof ff);
        cancel_ok(&z, "GUID_NULL"); cancel_ok(&ff, "all-ones");
        DXC(g_a.cancel(NULL) == 0);
        GUID one; mk(&one);
        for (i = 0; i < count && GetTickCount64() < g_dl; i++) cancel_ok(&one, "same id");
        for (i = 0; i < 1000 && i < count; i++) { GUID r; mk(&r); r.Data1 ^= (DWORD)i; cancel_ok(&r, "perturbed"); }
    } else if (mode == 3) {                       /* create and cancel interleaved (cancel the id from 16 steps ago) */
        for (i = 0; i < count && GetTickCount64() < g_dl; i++) {
            mk(&ids[i]);
            if (i >= 16) cancel_ok(&ids[i - 16], "ring");
        }
        for (i = count > 16 ? count - 16 : 0; i < count; i++) cancel_ok(&ids[i], "ring tail");
    } else if (mode == 4) {                       /* ids created on threads that have already exited */
        size_t per = count / 4; slice s[4]; HANDLE th[4];
        for (int k = 0; k < 4; k++) { s[k].ids = ids; s[k].lo = k * per; s[k].hi = (k == 3) ? count : (k + 1) * per; s[k].step = 1; th[k] = CreateThread(NULL, 0, create_slice, &s[k], 0, NULL); }
        WaitForMultipleObjects(4, th, TRUE, 60000);
        for (int k = 0; k < 4; k++) CloseHandle(th[k]);
        GUID *cp = (GUID *)malloc(count * sizeof(GUID)); memcpy(cp, ids, count * sizeof(GUID));
        DXC(dx_dups(cp, count) == 0); free(cp);
        for (i = 0; i < count && GetTickCount64() < g_dl; i++) cancel_ok(&ids[i], "after thread exit");
    } else if (mode == 5) {                       /* creators and cancellers run at the same time on disjoint halves */
        size_t half = count / 2; slice c = { ids, 0, half, 1 }, k2 = { ids, half, count, 1 }, x = { ids, 0, half, 1 };
        create_slice(&c);                         /* first half exists up front */
        HANDLE t1 = CreateThread(NULL, 0, create_slice, &k2, 0, NULL);
        HANDLE t2 = CreateThread(NULL, 0, cancel_slice, &x, 0, NULL);
        HANDLE t3 = CreateThread(NULL, 0, cancel_slice, &x, 0, NULL);
        HANDLE all[3] = { t1, t2, t3 };
        if (WaitForMultipleObjects(3, all, TRUE, 100000) != WAIT_OBJECT_0) { printf("  FAIL hang\n"); TerminateProcess(GetCurrentProcess(), 99); }
        GUID *cp = (GUID *)malloc(count * sizeof(GUID)); memcpy(cp, ids, count * sizeof(GUID));
        DXC(dx_dups(cp, count) == 0); free(cp);
    } else if (mode == 6) {                       /* cancel immediately, twice, then once more after a delay */
        for (i = 0; i < count && GetTickCount64() < g_dl; i++) { GUID g; if (!mk(&g)) continue; cancel_ok(&g, "1st"); cancel_ok(&g, "2nd"); if (i % 100 == 0) { Sleep(1); cancel_ok(&g, "3rd"); } }
    } else return 98;
    free(ids);
    t_note("cancel mode %d count %lu done", mode, (unsigned long)count);
    return dx_rc();
}

TEST(dx_cancel_10000_create_cancel_half)    { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "0 10000", 150000); }
TEST(dx_cancel_1000_create_cancel_half)     { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "0 1000", 100000); }
TEST(dx_cancel_100_create_cancel_half)      { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "0 100", 60000); }
TEST(dx_cancel_2_ids_smallest_case)         { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "0 2", 60000); }
TEST(dx_cancel_threads_overlapping_10000)   { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "1 10000", 150000); }
TEST(dx_cancel_threads_overlapping_1000)    { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "1 1000", 100000); }
TEST(dx_cancel_special_ids_and_repeat_1000) { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "2 1000", 100000); }
TEST(dx_cancel_special_ids_and_repeat_10000){ DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "2 10000", 150000); }
TEST(dx_cancel_interleaved_ring_5000)       { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "3 5000", 120000); }
TEST(dx_cancel_ids_from_exited_threads)     { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "4 4000", 120000); }
TEST(dx_cancel_create_while_cancelling)     { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "5 4000", 120000); }
TEST(dx_cancel_double_cancel_each_id)       { DX_REQ_ALL(); DX_CHILD_OK("dx_cancel", "6 2000", 120000); }

/* ---- in-process checks that need no child: pure id generation / NULL handling ---- */
TEST(dx_cancel_null_returns_ok) {
    DX_REQ_ALL();
    for (int i = 0; i < 100; i++) EXPECT_EQ(a_.cancel(NULL), 0);
}
TEST(dx_cancel_null_guid_returns_ok) {
    DX_REQ_ALL();
    GUID z; memset(&z, 0, sizeof z);
    HRESULT hr = a_.cancel(&z);
    if (dx_is_remote()) t_note("remote session: cancel(GUID_NULL) hr=0x%08lx", (unsigned long)hr); else EXPECT_EQ(hr, 0);
}
TEST(dx_cancel_ids_unique_and_nonzero_2000) {
    DX_REQ_ALL();
    enum { N = 2000 }; static GUID v[N]; int n = 0;
    for (int i = 0; i < N; i++) {
        memset(&v[n], 0, sizeof(GUID));
        HRESULT hr = a_.cid(&v[n]);
        if (hr == 0) { CHECK(!dx_guid_zero(&v[n])); n++; } else EXPECT_EQ(hr, DX_HR_UUID_LOCAL_ONLY);
    }
    CHECK(dx_dups(v, n) == 0);
}
TEST(dx_cancel_id_format_note) {
    DX_REQ_ALL();
    GUID g; memset(&g, 0, sizeof g);
    HRESULT hr = a_.cid(&g);
    t_note("GetCancellationId hr=0x%08lx version nibble=%u variant bits=%u", (unsigned long)hr, (g.Data3 >> 12) & 0xF, g.Data4[0] >> 6);
}
TEST(dx_cancel_id_overwrites_previous_content) {
    DX_REQ_ALL();
    GUID g; memset(&g, 0xA5, sizeof g);
    GUID before = g;
    HRESULT hr = a_.cid(&g);
    if (hr == 0) CHECK(memcmp(&g, &before, sizeof g) != 0);
}
