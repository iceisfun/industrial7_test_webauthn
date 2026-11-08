#include "cd.h"
/* PIN-carrying exports reached only through paths that end before any device selection.
 *
 * Reference behaviour relied on (decompilation of webauthn.dll, Windows 10):
 *  - WebAuthNCtapSetClientPin: *pRetries = 0 first; a NULL PIN returns NTE_INVALID_PARAMETER (0x80090027) before the
 *    device selector runs. A non-NULL PIN reaches the device selector, so it is never passed here.
 *  - WebAuthNCtapChangeClientPin: *pOut1 = *pOut2 = 0 first. If either PIN is NULL the function wipes (zero-fills,
 *    strlen*2 bytes) whichever PIN buffer is non-NULL and returns 0x80090027. With both PINs set it reaches the device
 *    selector, so that case is never exercised.
 *  - WebAuthNCtapChangeClientPinForSelectedDevice: *ppDev is read, then cleared. New PIN NULL -> old PIN wiped,
 *    0x80090027. Otherwise old/new are copied through CryptProtectMemory (no length validation of any kind) and wiped;
 *    unless the selected-device record is "complete" (see cd.h) the result is 0x80090027 and the record is released.
 */



TEST(ctapdev_setpin_null_pin_invalid_parameter) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    DWORD retries = SENT;
    SET_ERR(0);
    CDHR r = UN(WebAuthNCtapSetClientPin)(NULL, 0, NULL, NULL, &retries);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
}
TEST(ctapdev_setpin_null_pin_zeroes_retries) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    static const DWORD pre[] = { 0, 1, 8, 0x7FFFFFFF, 0xCCCCCCCC, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof pre / sizeof pre[0]; i++) {
        DWORD retries = pre[i];
        UN(WebAuthNCtapSetClientPin)(NULL, 0, NULL, NULL, &retries);
        CHECKF(retries == 0, "pre=0x%lx got=0x%lx", (unsigned long)pre[i], (unsigned long)retries);
    }
}
TEST(ctapdev_setpin_null_pin_ignores_flags_and_window) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    static const ULONG fl[] = { 0, 1, 0x2000000, 0x80000000, 0xFFFFFFFF };
    static const ULONG_PTR hw[] = { 0, 1, 0x10001, 0xDEAD0000 };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++)
        for (size_t j = 0; j < sizeof hw / sizeof hw[0]; j++) {
            DWORD retries = SENT;
            CDHR r = UN(WebAuthNCtapSetClientPin)((HWND)hw[j], fl[i], NULL, NULL, &retries);
            CHECKF(r == CD_NTE_INVALID_PARAMETER && retries == 0, "flags=0x%lx hwnd=%p r=0x%lx", (unsigned long)fl[i], (void *)hw[j], (unsigned long)r);
        }
}
TEST(ctapdev_setpin_null_pin_with_transaction_id) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    GUID g = { 0x11223344, 0x5566, 0x7788, { 1, 2, 3, 4, 5, 6, 7, 8 } }, copy = g;
    DWORD retries = SENT;
    CDHR r = UN(WebAuthNCtapSetClientPin)(NULL, 0, &g, NULL, &retries);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(!memcmp(&g, &copy, sizeof g));        /* caller GUID is not modified */
    GUID z; memset(&z, 0, sizeof z);
    retries = SENT;
    r = UN(WebAuthNCtapSetClientPin)(NULL, 0, &z, NULL, &retries);   /* all-zero GUID is used as given */
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
}
TEST(ctapdev_setpin_null_pin_repeatable) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    for (int i = 0; i < 200; i++) {
        DWORD retries = SENT;
        CDHR r = UN(WebAuthNCtapSetClientPin)(NULL, 0, NULL, NULL, &retries);
        if (r != CD_NTE_INVALID_PARAMETER || retries != 0) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); break; }
    }
}
TEST(ctapdev_setpin_null_pin_last_error_note) {
    REQUIRE(UN(WebAuthNCtapSetClientPin));
    DWORD retries = 0;
    SET_ERR(0x1234);
    CDHR r = UN(WebAuthNCtapSetClientPin)(NULL, 0, NULL, NULL, &retries);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    t_note("SetClientPin(NULL pin) GetLastError afterwards = %lu (result is returned as HRESULT, not via last error)", GetLastError());
}

/* ---- ChangeClientPin ---- */
TEST(ctapdev_changepin_both_null) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    DWORD a = SENT, b = SENT;
    CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, NULL, &a, &b);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    EXPECT_EQ(a, 0); EXPECT_EQ(b, 0);
}
TEST(ctapdev_changepin_outputs_zeroed_first) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    static const DWORD pre[] = { 1, 3, 0x7FFFFFFF, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof pre / sizeof pre[0]; i++) {
        DWORD a = pre[i], b = ~pre[i];
        UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, NULL, &a, &b);
        CHECKF(a == 0 && b == 0, "a=0x%lx b=0x%lx", (unsigned long)a, (unsigned long)b);
    }
}
TEST(ctapdev_changepin_old_null_wipes_new) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    WCHAR nw[32]; cd_pin_fill(nw, 32, 6, L'7');
    DWORD a = SENT, b = SENT;
    CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, nw, &a, &b);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(nw, 6)); CHECK(cd_pin_tail_intact(nw, 7, 32));
    EXPECT_EQ(a, 0); EXPECT_EQ(b, 0);
}
TEST(ctapdev_changepin_new_null_wipes_old) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    WCHAR ow[32]; cd_pin_fill(ow, 32, 5, L'8');
    DWORD a = SENT, b = SENT;
    CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, ow, NULL, &a, &b);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(ow, 5)); CHECK(cd_pin_tail_intact(ow, 6, 32));
}
static const size_t k_lens[] = { 0, 1, 2, 3, 4, 5, 8, 15, 16, 17, 31, 32, 33, 62, 63, 64, 65, 100, 127, 128, 255, 256, 511, 1000 };
TEST(ctapdev_changepin_wipe_length_table_new_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    for (size_t i = 0; i < sizeof k_lens / sizeof k_lens[0]; i++) {
        size_t n = k_lens[i], cap = n + 20; WCHAR *p = (WCHAR *)LocalAlloc(LPTR, cap * 2);
        cd_pin_fill(p, cap, n, L'x');
        DWORD a, b;
        CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, p, &a, &b);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(p, n) && cd_pin_tail_intact(p, n + 1, cap), "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(p);
    }
}
TEST(ctapdev_changepin_wipe_length_table_old_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    for (size_t i = 0; i < sizeof k_lens / sizeof k_lens[0]; i++) {
        size_t n = k_lens[i], cap = n + 20; WCHAR *p = (WCHAR *)LocalAlloc(LPTR, cap * 2);
        cd_pin_fill(p, cap, n, L'y');
        DWORD a, b;
        CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, p, NULL, &a, &b);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(p, n) && cd_pin_tail_intact(p, n + 1, cap), "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(p);
    }
}
TEST(ctapdev_changepin_embedded_nul_wipes_prefix_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    WCHAR p[16]; cd_pin_fill(p, 16, 0, 0);
    p[0] = L'a'; p[1] = L'b'; p[2] = 0; p[3] = L'c'; p[4] = L'd'; p[5] = 0;
    DWORD a, b;
    CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, p, &a, &b);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(p[0] == 0 && p[1] == 0);
    CHECK(p[3] == L'c' && p[4] == L'd');         /* characters after the first NUL are not touched */
}
TEST(ctapdev_changepin_nonbmp_and_surrogates_wiped) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    static const WCHAR pins[][8] = { { 0xD83D, 0xDD11, 0xD83D, 0xDD11, 0 }, { 0xD800, 0 }, { 0xDC00, 0xD800, 0 }, { 0xFFFF, 0xFFFE, 0 }, { 0x00E9, 0x20AC, 0x4E2D, 0 } };
    for (size_t i = 0; i < sizeof pins / sizeof pins[0]; i++) {
        WCHAR w[16]; cd_pin_fill(w, 16, 0, 0); size_t n = lstrlenW(pins[i]);
        memcpy(w, pins[i], (n + 1) * 2);
        DWORD a, b;
        CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, NULL, NULL, w, &a, &b);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(w, n), "pin #%zu r=0x%lx", i, (unsigned long)r);
    }
}
TEST(ctapdev_changepin_transaction_id_variants) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    GUID g = { 1, 2, 3, { 4, 5, 6, 7, 8, 9, 10, 11 } }, copy = g;
    DWORD a, b;
    CDHR r = UN(WebAuthNCtapChangeClientPin)(NULL, 0, &g, NULL, NULL, &a, &b);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(!memcmp(&g, &copy, sizeof g));
}
TEST(ctapdev_changepin_ignores_flags_and_window) {
    REQUIRE(UN(WebAuthNCtapChangeClientPin));
    static const ULONG fl[] = { 0, 0x2000000, 0xFFFFFFFF };
    for (size_t i = 0; i < 3; i++) {
        DWORD a = SENT, b = SENT;
        CDHR r = UN(WebAuthNCtapChangeClientPin)((HWND)(ULONG_PTR)0x10001, fl[i], NULL, NULL, NULL, &a, &b);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && a == 0 && b == 0, "flags=0x%lx", (unsigned long)fl[i]);
    }
}

/* ---- ChangeClientPinForSelectedDevice ---- */
typedef CDHR (*fsd_fn)(HWND, ULONG, const GUID *, WCHAR *, WCHAR *, void **);
static CDHR fsd(WCHAR *o, WCHAR *n, void **pp) { return UN(WebAuthNCtapChangeClientPinForSelectedDevice)(NULL, 0, NULL, o, n, pp); }

TEST(ctapdev_fsd_all_null_no_device) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    void *dev = NULL;
    CDHR r = fsd(NULL, NULL, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(dev == NULL);
}
TEST(ctapdev_fsd_old_only_wiped) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    WCHAR o[24]; cd_pin_fill(o, 24, 8, L'o'); void *dev = NULL;
    CDHR r = fsd(o, NULL, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(o, 8)); CHECK(cd_pin_tail_intact(o, 9, 24));
}
TEST(ctapdev_fsd_new_only_wiped_no_device) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    WCHAR n[24]; cd_pin_fill(n, 24, 8, L'n'); void *dev = NULL;
    CDHR r = fsd(NULL, n, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(n, 8)); CHECK(cd_pin_tail_intact(n, 9, 24)); CHECK(dev == NULL);
}
TEST(ctapdev_fsd_both_pins_no_device_wiped) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    WCHAR o[24], n[24]; cd_pin_fill(o, 24, 6, L'o'); cd_pin_fill(n, 24, 7, L'n'); void *dev = NULL;
    CDHR r = fsd(o, n, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(o, 6)); CHECK(cd_pin_tail_intact(o, 7, 24));
    CHECK(cd_pin_wiped(n, 7)); CHECK(cd_pin_tail_intact(n, 8, 24));
    CHECK(dev == NULL);
}
TEST(ctapdev_fsd_wipe_length_table_new_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    for (size_t i = 0; i < sizeof k_lens / sizeof k_lens[0]; i++) {
        size_t n = k_lens[i], cap = n + 20; WCHAR *p = (WCHAR *)LocalAlloc(LPTR, cap * 2); void *dev = NULL;
        cd_pin_fill(p, cap, n, L'z');
        CDHR r = fsd(NULL, p, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(p, n) && cd_pin_tail_intact(p, n + 1, cap) && !dev, "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(p);
    }
}
TEST(ctapdev_fsd_pin_length_not_validated_client_side) {
    /* PIN policy limits (4 code points minimum, 63 bytes maximum) are authenticator rules; at this layer a 1-char,
     * an empty and a 4000-char PIN take exactly the same path and return the same code. */
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    static const size_t ns[] = { 0, 1, 3, 63, 64, 2000, 4000 };
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        size_t n = ns[i]; WCHAR *o = (WCHAR *)LocalAlloc(LPTR, (n + 20) * 2), *w = (WCHAR *)LocalAlloc(LPTR, (n + 20) * 2); void *dev = NULL;
        cd_pin_fill(o, n + 20, n, L'1'); cd_pin_fill(w, n + 20, n, L'2');
        CDHR r = fsd(o, w, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(o, n) && cd_pin_wiped(w, n), "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(o); LocalFree(w);
    }
}
TEST(ctapdev_fsd_utf8_byte_limit_not_applied) {
    /* 40 x U+00E9 is 80 UTF-8 bytes (> 63) but only 40 UTF-16 units; 20 x U+4E2D is 60 bytes. Neither is rejected here. */
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    WCHAR a[64], b[64]; cd_pin_fill(a, 64, 40, 0x00E9); cd_pin_fill(b, 64, 20, 0x4E2D); void *dev = NULL;
    CDHR r = fsd(NULL, a, &dev); EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(a, 40));
    r = fsd(NULL, b, &dev); EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(b, 20));
}
TEST(ctapdev_fsd_embedded_nul_prefix_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    WCHAR p[16]; cd_pin_fill(p, 16, 0, 0);
    p[0] = L'1'; p[1] = L'2'; p[2] = L'3'; p[3] = L'4'; p[4] = 0; p[5] = L'5'; p[6] = L'6'; p[7] = 0;
    void *dev = NULL;
    CDHR r = fsd(NULL, p, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0);
    CHECK(p[5] == L'5' && p[6] == L'6');
}
TEST(ctapdev_fsd_surrogates_pass_through) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    static const WCHAR pins[][6] = { { 0xD800, 0 }, { 0xDC00, 0xD800, 0 }, { 0xD83D, 0xDD11, 0 }, { 0xFFFE, 0xFFFF, 0 } };
    for (size_t i = 0; i < 4; i++) {
        WCHAR w[16]; cd_pin_fill(w, 16, 0, 0); size_t n = lstrlenW(pins[i]); memcpy(w, pins[i], (n + 1) * 2); void *dev = NULL;
        CDHR r = fsd(NULL, w, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(w, n), "pin #%zu", i);
    }
}

/* Incomplete selected-device records: all of these end with 0x80090027, the record is consumed (the caller's slot is
 * cleared) and the PINs are wiped. A complete record is never used (it would trigger a device operation). */
static const struct { const char *tag; DWORD kind; int p20, p28; } k_devs[] = {
    { "all zero", 0, 0, 0 }, { "kind only", 1, 0, 0 }, { "kind+p20", 1, 1, 0 }, { "kind+p28", 1, 0, 1 },
    { "p20+p28 no kind", 0, 1, 1 }, { "p20 only", 0, 1, 0 }, { "p28 only", 0, 0, 1 }, { "kind 7 no ptrs", 7, 0, 0 },
};
TEST(ctapdev_fsd_incomplete_device_both_pins) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    BYTE dummy[16];
    for (size_t i = 0; i < sizeof k_devs / sizeof k_devs[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, k_devs[i].kind, k_devs[i].p20 ? dummy : NULL, k_devs[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); t_note("fixture %s unexpectedly complete; skipped", k_devs[i].tag); continue; }
        WCHAR o[16], n[16]; cd_pin_fill(o, 16, 5, L'a'); cd_pin_fill(n, 16, 5, L'b');
        CDHR r = fsd(o, n, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "%s r=0x%lx", k_devs[i].tag, (unsigned long)r);
        CHECKF(dev == NULL, "%s: slot cleared", k_devs[i].tag);
        CHECKF(cd_pin_wiped(o, 5) && cd_pin_wiped(n, 5), "%s: wiped", k_devs[i].tag);
    }
}
TEST(ctapdev_fsd_incomplete_device_new_pin_only) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    BYTE dummy[16];
    for (size_t i = 0; i < sizeof k_devs / sizeof k_devs[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, k_devs[i].kind, k_devs[i].p20 ? dummy : NULL, k_devs[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); continue; }
        WCHAR n[16]; cd_pin_fill(n, 16, 5, L'b');
        CDHR r = fsd(NULL, n, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && dev == NULL && cd_pin_wiped(n, 5), "%s", k_devs[i].tag);
    }
}
TEST(ctapdev_fsd_incomplete_device_no_new_pin) {
    /* New PIN NULL: only the old PIN is wiped; the device slot is still consumed. */
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    BYTE dummy[16];
    for (size_t i = 0; i < sizeof k_devs / sizeof k_devs[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, k_devs[i].kind, k_devs[i].p20 ? dummy : NULL, k_devs[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); continue; }
        WCHAR o[16]; cd_pin_fill(o, 16, 4, L'a');
        CDHR r = fsd(o, NULL, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && dev == NULL && cd_pin_wiped(o, 4), "%s r=0x%lx dev=%p", k_devs[i].tag, (unsigned long)r, dev);
    }
}
TEST(ctapdev_fsd_flags_hwnd_guid_not_inspected) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    GUID g = { 9, 8, 7, { 6, 5, 4, 3, 2, 1, 0, 9 } };
    static const ULONG fl[] = { 0, 0x2000000, 0xFFFFFFFF };
    for (size_t i = 0; i < 3; i++) {
        void *dev = NULL;
        CDHR r = UN(WebAuthNCtapChangeClientPinForSelectedDevice)((HWND)(ULONG_PTR)0x4242, fl[i], &g, NULL, NULL, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "flags=0x%lx", (unsigned long)fl[i]);
    }
}
TEST(ctapdev_fsd_repeatable_with_fresh_records) {
    REQUIRE(UN(WebAuthNCtapChangeClientPinForSelectedDevice));
    for (int i = 0; i < 300; i++) {
        void *dev = cd_dev_alloc(); WCHAR n[8]; cd_pin_fill(n, 8, 4, L'q');
        CDHR r = fsd(NULL, n, &dev);
        if (r != CD_NTE_INVALID_PARAMETER || dev != NULL || !cd_pin_wiped(n, 4)) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); if (dev) LocalFree(dev); break; }
    }
}
