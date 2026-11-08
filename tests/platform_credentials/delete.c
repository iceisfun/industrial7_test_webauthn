#include "pc.h"
/* WebAuthNDeletePlatformCredential(cbCredentialId, pbCredentialId).
 *
 * Decomp: no argument validation at all. The function enumerates the user's FIDO platform keys
 * (NgcEnumUserIdKeys; read-only), and for each key of the relevant domain type that is not the logon
 * key compares its credential id (length first, then memcmp) with the caller's; only on an exact match
 * does it delete the key and return that deletion result. When the enumeration ends without a match
 * (enumeration status 0x8009002A, NTE_NO_MORE_ITEMS) it returns NTE_NOT_FOUND (0x80090011). Any other
 * negative enumeration status is returned as-is.
 *
 * No UI is involved, and an id that matches nothing deletes nothing. Every call runs in a child process
 * with a timeout so a stuck enumeration cannot hang the run. The ids are deterministic structured
 * patterns that cannot be real authenticator-generated credential ids. A buffer is always supplied for
 * non-zero lengths (a NULL buffer with a matching length would be handed to memcmp). */

#define CHILD_NOEXP 0x7E7E7E7Eu

/* argv: <length> <mode: z zero-filled | p pattern | n NULL pointer (length 0 only)> [repeat] */
CHILD(pc_delete) {
    pc_delete_fn f = pc_del();
    if (!f) return (int)CHILD_NOEXP;
    unsigned len = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
    char mode = argc > 2 ? argv[2][0] : 'p';
    int rep = argc > 3 ? atoi(argv[3]) : 1;
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, len + 8);
    if (!buf) return 0x7E7E0001;
    pc_fill_id(buf, len, mode == 'z' ? 0 : 1);
    HRESULT first = 0;
    for (int i = 0; i < rep; i++) {
        HRESULT hr = f(len, mode == 'n' ? NULL : buf);
        if (i == 0) first = hr; else if (hr != first) return 0x7E7E0002;
    }
    return (int)first;
}

static void run_delete(unsigned len, char mode, int rep)
{
    char a[64];
    if (!pc_del()) { t_skip("missing export: WebAuthNDeletePlatformCredential"); return; }
    snprintf(a, sizeof a, "%u %c %d", len, mode, rep);
    DWORD r = t_run_child("pc_delete", a, 20000);
    if (r == 0xDEAD0000) { t_skip("could not spawn child"); return; }
    CHECKF(r != 0xDEAD0001, "child timed out (len=%u)", len);
    if (r == CHILD_NOEXP) { t_skip("export missing in child"); return; }
    CHECKF(r != 0x7E7E0002, "result changed between repeated calls (len=%u)", len);
    CHECKF((int)r < 0, "expected a failure HRESULT, got 0x%lx (len=%u)", (unsigned long)r, len);
    if (r == (DWORD)PC_NTE_NOT_FOUND) { CHECK(1); }
    else {
        CHECK((int)r < 0);
        t_note("delete of nonexistent id (len=%u) returned 0x%lx rather than NTE_NOT_FOUND 0x80090011 (enumeration status is returned unchanged when it fails; machine without provisioned platform keys?)", len, (unsigned long)r);
    }
}

#define DEL_TEST(len) \
    TEST(pc_delete_nonexistent_len##len##_pattern) { run_delete(len, 'p', 1); } \
    TEST(pc_delete_nonexistent_len##len##_zero) { run_delete(len, 'z', 1); }
DEL_TEST(0)
DEL_TEST(1)
DEL_TEST(2)
DEL_TEST(15)
DEL_TEST(16)
DEL_TEST(17)
DEL_TEST(31)
DEL_TEST(32)
DEL_TEST(33)
DEL_TEST(63)
DEL_TEST(64)
DEL_TEST(65)
DEL_TEST(128)
DEL_TEST(255)
DEL_TEST(256)
DEL_TEST(1023)
DEL_TEST(1024)
DEL_TEST(1025)
DEL_TEST(4096)
DEL_TEST(65535)

TEST(pc_delete_zero_length_null_pointer) { run_delete(0, 'n', 1); }
TEST(pc_delete_repeat_same_result) { run_delete(32, 'p', 3); }
TEST(pc_delete_repeat_zero_len_same_result) { run_delete(0, 'p', 3); }
