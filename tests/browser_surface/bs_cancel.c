/* (e) Cancellation id lifecycle with two threads: WebAuthNGetCancellationId / WebAuthNCancelCurrentOperation.
 * No operation is ever started, so cancelling is always a request for an id nobody is waiting on. */
#include "bs.h"
#include <stdlib.h>

#define N 300
typedef struct { GUID ids[N]; HRESULT hr[N]; HRESULT chr[N]; int cancel; } worker;

static int cmpg(const void *a, const void *b) { return memcmp(a, b, sizeof(GUID)); }

static DWORD WINAPI get_thread(LPVOID p) {
    worker *w = p; WebAuthNGetCancellationId_pfn g = UN(WebAuthNGetCancellationId);
    WebAuthNCancelCurrentOperation_pfn c = UN(WebAuthNCancelCurrentOperation);
    for (int i = 0; i < N; i++) {
        memset(&w->ids[i], 0xCC, sizeof(GUID));
        w->hr[i] = g(&w->ids[i]);
        if (w->cancel) w->chr[i] = c(&w->ids[i]);
    }
    return 0;
}
static void run_two(worker *a, worker *b) {
    HANDLE h[2];
    h[0] = CreateThread(NULL, 0, get_thread, a, 0, NULL);
    h[1] = CreateThread(NULL, 0, get_thread, b, 0, NULL);
    for (int i = 0; i < 2; i++) { CHECK(h[i] != NULL); if (h[i]) { WaitForSingleObject(h[i], 60000); CloseHandle(h[i]); } }
}
static void check_unique(worker *a, worker *b, int cancelled) {
    static GUID all[2 * N];
    for (int i = 0; i < N; i++) {
        EXPECT_EQ(a->hr[i], S_OK); EXPECT_EQ(b->hr[i], S_OK);
        if (cancelled) { EXPECT_EQ(a->chr[i], S_OK); EXPECT_EQ(b->chr[i], S_OK); }
        all[i] = a->ids[i]; all[N + i] = b->ids[i];
    }
    qsort(all, 2 * N, sizeof(GUID), cmpg);
    int dup = 0; for (int i = 1; i < 2 * N; i++) if (!memcmp(&all[i], &all[i - 1], sizeof(GUID))) dup++;
    EXPECT_EQ(dup, 0);
    static const GUID nil; int nils = 0; for (int i = 0; i < 2 * N; i++) if (!memcmp(&all[i], &nil, sizeof nil)) nils++;
    EXPECT_EQ(nils, 0);
}
static worker wa, wb;

TEST(bs_cancel_two_threads_get_unique_ids) {
    REQUIRE(UN(WebAuthNGetCancellationId));
    memset(&wa, 0, sizeof wa); memset(&wb, 0, sizeof wb);
    run_two(&wa, &wb);
    check_unique(&wa, &wb, 0);
}
TEST(bs_cancel_two_threads_get_and_cancel_own_ids) {
    REQUIRE(UN(WebAuthNGetCancellationId)); REQUIRE(UN(WebAuthNCancelCurrentOperation));
    memset(&wa, 0, sizeof wa); memset(&wb, 0, sizeof wb); wa.cancel = wb.cancel = 1;
    run_two(&wa, &wb);
    check_unique(&wa, &wb, 1);
}
static DWORD WINAPI cancel_other(LPVOID p) {
    worker *w = p; WebAuthNCancelCurrentOperation_pfn c = UN(WebAuthNCancelCurrentOperation);
    for (int i = 0; i < N; i++) w->chr[i] = c(&w->ids[i]);
    return 0;
}
TEST(bs_cancel_id_from_one_thread_cancelled_by_another) {
    REQUIRE(UN(WebAuthNGetCancellationId)); REQUIRE(UN(WebAuthNCancelCurrentOperation));
    memset(&wa, 0, sizeof wa); memset(&wb, 0, sizeof wb);
    run_two(&wa, &wb);
    HANDLE h[2];
    h[0] = CreateThread(NULL, 0, cancel_other, &wb, 0, NULL);   /* each thread cancels the other's ids, twice over */
    h[1] = CreateThread(NULL, 0, cancel_other, &wa, 0, NULL);
    for (int i = 0; i < 2; i++) { CHECK(h[i] != NULL); if (h[i]) { WaitForSingleObject(h[i], 60000); CloseHandle(h[i]); } }
    for (int i = 0; i < N; i++) { EXPECT_EQ(wa.chr[i], S_OK); EXPECT_EQ(wb.chr[i], S_OK); }
}
static GUID g_shared;
static volatile LONG g_bad;
static DWORD WINAPI cancel_same(LPVOID p) {
    WebAuthNCancelCurrentOperation_pfn c = UN(WebAuthNCancelCurrentOperation);
    for (int i = 0; i < 500; i++) if (c(&g_shared) != S_OK) InterlockedIncrement(&g_bad);
    return 0;
}
TEST(bs_cancel_same_id_from_two_threads) {
    REQUIRE(UN(WebAuthNGetCancellationId)); REQUIRE(UN(WebAuthNCancelCurrentOperation));
    EXPECT_EQ(UN(WebAuthNGetCancellationId)(&g_shared), S_OK);
    g_bad = 0;
    HANDLE h[2];
    for (int i = 0; i < 2; i++) h[i] = CreateThread(NULL, 0, cancel_same, NULL, 0, NULL);
    for (int i = 0; i < 2; i++) { CHECK(h[i] != NULL); if (h[i]) { WaitForSingleObject(h[i], 60000); CloseHandle(h[i]); } }
    EXPECT_EQ(g_bad, 0);
}
TEST(bs_cancel_new_id_after_cancel_is_distinct) {
    REQUIRE(UN(WebAuthNGetCancellationId)); REQUIRE(UN(WebAuthNCancelCurrentOperation));
    GUID a, b;
    EXPECT_EQ(UN(WebAuthNGetCancellationId)(&a), S_OK);
    EXPECT_EQ(UN(WebAuthNCancelCurrentOperation)(&a), S_OK);
    EXPECT_EQ(UN(WebAuthNGetCancellationId)(&b), S_OK);
    CHECK(memcmp(&a, &b, sizeof a) != 0);
}
TEST(bs_cancel_id_format_note) {
    REQUIRE(UN(WebAuthNGetCancellationId));
    GUID g; EXPECT_EQ(UN(WebAuthNGetCancellationId)(&g), S_OK);
    t_note("cancellation id: version nibble %d, variant bits %d", (g.Data3 >> 12) & 0xF, (g.Data4[0] >> 6) & 3);
}
TEST(bs_cancel_unused_in_flight_note) {
    t_note("cancelling an operation that is in flight is not exercised: it needs a call that reaches the service");
}
