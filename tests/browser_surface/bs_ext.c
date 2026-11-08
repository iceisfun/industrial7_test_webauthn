/* Extension identifiers in the option structures (hmac-secret, credProtect, credBlob, minPinLength, largeBlob,
 * prf and others browsers use). Every call carries a local fault (algorithm 0), so the observable facts are
 * which identifiers make the DLL read the extension payload before the call ends, and how much of it.
 *   NOTE ext <id> payload_read=0x..   (0 = payload not read on this path) */
#include "bs.h"

static const char *narrow(const WCHAR *w, char *out, size_t n) {
    size_t i = 0; for (; w[i] && i + 1 < n; i++) out[i] = (char)w[i]; out[i] = 0; return out;
}

TEST(bs_ext_payload_read_per_identifier) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    for (DWORD i = 0; i < BS_NEXT; i++) {
        char nm[40]; DWORD hr = 0;
        int e = bs_extent('m', "ext", i, 0, 0x20, &hr);
        t_note("ext %s payload_read=%d hr=0x%08lx", narrow(bs_ext_ids[i], nm, sizeof nm), e, (unsigned long)hr);
        CHECKF(e != BS_X_NO_RESULT, "%s: child timed out or crashed", nm);
        CHECKF(e >= 0 || e == BS_X_FAULT_AT_MAX, "%s: unexpected result %d", nm, e);
        if (e >= 0) CHECKF(hr == BS_ENC_FAIL, "%s: result 0x%08lx", nm, (unsigned long)hr);
        /* read sizes are build-dependent: recorded, not asserted (credProtect reads its two-DWORD structure,
         * an identifier nobody defined is not interpreted) */
        if (i == 1) t_note("ext credProtect payload size read=%d (two-DWORD structure expected 8)", e);
        if (i == BS_NEXT - 1) t_note("ext unknown identifier payload size read=%d (0 expected)", e);
    }
}
TEST(bs_ext_unknown_identifier_is_not_judged_at_entry) {
    REQUIRE(UN(WebAuthNAuthenticatorMakeCredential));
    DWORD hr = 0; int e = bs_extent('m', "ext", BS_NEXT - 1, 0, 0x20, &hr);
    CHECKF(e != BS_X_NO_RESULT, "child failed");
    if (e >= 0) CHECKF(hr == BS_ENC_FAIL, "got 0x%08lx", (unsigned long)hr);
}
