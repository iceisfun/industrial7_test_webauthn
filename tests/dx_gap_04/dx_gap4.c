#include "t.h"
#include <objbase.h>
#include <stdlib.h>
/* dx_gap_04: state-adjacent calls, run only with the destructive pass.
 *
 * WebAuthNDeletePlatformCredential(cbId, pbId): no argument validation. It enumerates the user's FIDO
 * platform keys read-only (NgcEnumUserIdKeys); only an exact id match deletes. When the enumeration ends
 * without a match the result is NTE_NOT_FOUND (0x80090011); any other failing enumeration status is returned
 * unchanged. The ids used here carry a corpus tag and a fixed random-looking tail: they cannot equal an id
 * produced by an authenticator, so nothing is ever deleted. Each call runs in a child process with a timeout.
 *
 * WebAuthNCancelCurrentOperation with ids nobody is using must be a harmless S_OK from any thread. */

UDECL(HRESULT, WebAuthNDeletePlatformCredential, (DWORD, const BYTE *));
UDECL(HRESULT, WebAuthNGetCancellationId, (GUID *));
UDECL(HRESULT, WebAuthNCancelCurrentOperation, (const GUID *));
#define DEL ((WebAuthNDeletePlatformCredential_pfn)t_proc_in("webauthn.dll", "WebAuthNDeletePlatformCredential"))
#define GID ((WebAuthNGetCancellationId_pfn)t_proc_in("webauthn.dll", "WebAuthNGetCancellationId"))
#define CAN ((WebAuthNCancelCurrentOperation_pfn)t_proc_in("webauthn.dll", "WebAuthNCancelCurrentOperation"))
#define NOEXP 0x7E7E7E7Eu

static void fill_id(BYTE *p, unsigned n, unsigned seed)
{
    static const char tag[] = "CORPUS-GAP04-NEVER-A-REAL-CREDENTIAL/";
    for (unsigned i = 0; i < n; i++) p[i] = i < sizeof tag - 1 ? (BYTE)tag[i] : (BYTE)((i * 167u + seed * 31u + 0x71u) ^ 0x9Cu);
}

/* argv: <len> <seed> <repeat> */
CHILD(gap4_del) {
    if (!DEL) return (int)NOEXP;
    unsigned len = argc > 1 ? (unsigned)atoi(argv[1]) : 16, seed = argc > 2 ? (unsigned)atoi(argv[2]) : 0;
    int rep = argc > 3 ? atoi(argv[3]) : 1;
    BYTE *b = (BYTE *)LocalAlloc(LPTR, len + 8);
    if (!b) return 0x7E7E0001;
    fill_id(b, len, seed);
    HRESULT first = 0;
    for (int i = 0; i < rep; i++) {
        HRESULT hr = DEL(len, b);
        if (i == 0) first = hr; else if (hr != first) return 0x7E7E0002;
    }
    return (int)first;
}
static void del_case(unsigned len, unsigned seed, int rep)
{
    if (!DEL) { t_skip("missing export: WebAuthNDeletePlatformCredential"); return; }
    if (t_is_wine()) { t_skip("not meaningful under an emulator"); return; }
    char a[64]; snprintf(a, sizeof a, "%u %u %d", len, seed, rep);
    DWORD r = t_run_child("gap4_del", a, 30000);
    if (r == 0xDEAD0000) { t_skip("could not spawn child"); return; }
    t_check(r != 0xDEAD0001, __FILE__, __LINE__, "child finished", "len %u timed out", len);
    if (r == NOEXP) { t_skip("export missing in child"); return; }
    t_check(r != 0x7E7E0002, __FILE__, __LINE__, "result stable across repeats", "len %u", len);
    t_check((int)r < 0, __FILE__, __LINE__, "nonexistent id is not deleted", "len %u got 0x%lx", len, (unsigned long)r);
    if (r == 0x80090011u) CHECK(1);
    else t_note("delete of nonexistent id (len %u) -> 0x%lx instead of NTE_NOT_FOUND (no provisioned platform keys, or enumeration failure)", len, (unsigned long)r);
}
#define D(len, seed) TEST(dxgap4_delete_nonexistent_len##len##_seed##seed) { del_case(len, seed, 1); }
D(16, 1) D(16, 2) D(20, 3) D(32, 4) D(32, 5) D(48, 6) D(64, 7) D(96, 8) D(128, 9) D(255, 10) D(1, 11) D(2, 12) D(3, 13)
TEST(dxgap4_delete_nonexistent_repeated_5) { del_case(32, 21, 5); }
TEST(dxgap4_delete_nonexistent_repeated_zero_len) { del_case(0, 22, 3); }

TEST(dxgap4_cancel_unused_ids_from_threads) {
    if (!GID || !CAN) { t_skip("missing exports"); return; }
    HRESULT hr = 0; GUID g; hr = GID(&g);
    EXPECT_EQ(hr, 0);
    int bad = 0;
    for (int i = 0; i < 300; i++) { GUID x; if (GID(&x) != 0 || CAN(&x) != 0) bad++; }
    EXPECT_EQ(bad, 0);
}
static volatile LONG g_bad;
static DWORD WINAPI cancel_thr(LPVOID p)
{
    for (int i = 0; i < 200; i++) { GUID x; if (GID(&x) != 0 || CAN(&x) != 0) InterlockedIncrement(&g_bad); }
    return 0;
}
TEST(dxgap4_cancel_concurrent_threads) {
    if (!GID || !CAN) { t_skip("missing exports"); return; }
    g_bad = 0;
    HANDLE th[6];
    for (int i = 0; i < 6; i++) th[i] = CreateThread(NULL, 0, cancel_thr, NULL, 0, NULL);
    for (int i = 0; i < 6; i++) if (th[i]) { WaitForSingleObject(th[i], 20000); CloseHandle(th[i]); }
    EXPECT_EQ(g_bad, 0);
}
