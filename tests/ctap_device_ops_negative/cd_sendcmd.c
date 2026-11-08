#include "cd.h"
/* WebAuthNCtapSendCommand(hwnd, cbCbor, pbCbor, pcbOut, ppbOut, pin, ppSelectedDevice) through paths that end before
 * the RPC call to the authenticator service.
 *
 * Reference behaviour relied on:
 *  - *pcbOut = 0 and *ppbOut = NULL are written first (both pointers are required); *ppSelectedDevice (optional) is
 *    read and cleared, and the record it pointed to is released (LocalFree) on every return.
 *  - PIN == NULL: if a selected-device record was supplied the call returns NTE_INVALID_PARAMETER (0x80090027) no
 *    matter what the record contains. Otherwise the CBOR request (1..0x2000 bytes, non-NULL) is decoded; a NULL
 *    pointer, size 0 or size > 0x2000 fails with CtapCborErrorToWin32Error(3) = 1100 -> 0x8007044C; a decoded request
 *    without command data fails with 0x80090027.
 *  - PIN != NULL: the PIN is protected and the caller's buffer is wiped (strlen*2 bytes) before anything else; with no
 *    record, or an incomplete record, the call returns 0x80090027.
 * Well-formed CBOR commands are never submitted: they would be forwarded to the device.
 */

static CDHR sc(const BYTE *cb, DWORD n, DWORD *pout, BYTE **pp, WCHAR *pin, void **pdev) {
    return UN(WebAuthNCtapSendCommand)(NULL, n, cb, pout, pp, pin, pdev);
}
#define SC_INIT() DWORD cbOut = 0xCCCC; BYTE *out = (BYTE *)(ULONG_PTR)0x1; (void)out

TEST(ctapdev_send_zero_size_valid_pointer) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); BYTE b[4] = { 0xA0 };
    CDHR r = sc(b, 0, &cbOut, &out, NULL, NULL);
    EXPECT_EQ(r, CD_HR_CBOR_SIZE); EXPECT_EQ(cbOut, 0); CHECK(out == NULL);
}
TEST(ctapdev_send_null_buffer_sizes) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const DWORD sz[] = { 0, 1, 2, 16, 255, 0x1000, 0x2000 };
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        SC_INIT();
        CDHR r = sc(NULL, sz[i], &cbOut, &out, NULL, NULL);
        CHECKF(r == CD_HR_CBOR_SIZE && cbOut == 0 && out == NULL, "cb=%lu r=0x%lx", (unsigned long)sz[i], (unsigned long)r);
    }
}
TEST(ctapdev_send_oversize_rejected_before_read) {
    /* 0x2001 is the first rejected size; the buffer is never read so a 1-byte buffer is enough. */
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const DWORD sz[] = { 0x2001, 0x2002, 0x4000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF };
    BYTE b[1] = { 0xA0 };
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        SC_INIT();
        CDHR r = sc(b, sz[i], &cbOut, &out, NULL, NULL);
        CHECKF(r == CD_HR_CBOR_SIZE && cbOut == 0 && out == NULL, "cb=0x%lx r=0x%lx", (unsigned long)sz[i], (unsigned long)r);
    }
}
TEST(ctapdev_send_empty_cbor_map_rejected) {
    /* 0xA0 = empty map: decodes, has no command data. The reference maps this to ERROR_INVALID_DATA. */
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); BYTE b[1] = { 0xA0 };
    CDHR r = sc(b, 1, &cbOut, &out, NULL, NULL);
    CHECK(CD_FAILED(r)); EXPECT_EQ(cbOut, 0); CHECK(out == NULL);
    EXPECT_EQ(r, CD_HR_INVALID_DATA);
}
TEST(ctapdev_send_non_map_cbor_rejected) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const BYTE items[][2] = { {0x00,0}, {0x01,0}, {0x17,0}, {0x20,0}, {0x40,0}, {0x60,0}, {0x80,0}, {0xF4,0}, {0xF5,0}, {0xF6,0}, {0xF7,0}, {0xFF,0} };
    for (size_t i = 0; i < sizeof items / sizeof items[0]; i++) {
        SC_INIT(); BYTE b[2]; b[0] = items[i][0]; b[1] = 0;
        CDHR r = sc(b, 1, &cbOut, &out, NULL, NULL);
        CHECKF(CD_FAILED(r) && cbOut == 0 && out == NULL, "item 0x%02x r=0x%lx", b[0], (unsigned long)r);
        t_note("SendCommand cbor byte 0x%02x -> 0x%08lx", b[0], (unsigned long)r);
    }
}
TEST(ctapdev_send_truncated_cbor_rejected) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const BYTE t1[] = { 0xA1 }, t2[] = { 0xA1, 0x01 }, t3[] = { 0xA2, 0x01, 0x02 }, t4[] = { 0x58 }, t5[] = { 0x5A, 0xFF, 0xFF, 0xFF, 0xFF }, t6[] = { 0xBF };
    static const struct { const BYTE *p; DWORD n; } c[] = { {t1,1},{t2,2},{t3,3},{t4,1},{t5,5},{t6,1} };
    for (size_t i = 0; i < sizeof c / sizeof c[0]; i++) {
        SC_INIT();
        CDHR r = sc(c[i].p, c[i].n, &cbOut, &out, NULL, NULL);
        CHECKF(CD_FAILED(r) && cbOut == 0 && out == NULL, "case %zu r=0x%lx", i, (unsigned long)r);
        t_note("SendCommand truncated cbor case %zu -> 0x%08lx", i, (unsigned long)r);
    }
}
TEST(ctapdev_send_hwnd_not_validated) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const ULONG_PTR hw[] = { 0, 1, 0xDEADBEEF, 0x10001 };
    for (size_t i = 0; i < sizeof hw / sizeof hw[0]; i++) {
        SC_INIT();
        CDHR r = UN(WebAuthNCtapSendCommand)((HWND)hw[i], 0, NULL, &cbOut, &out, NULL, NULL);
        CHECKF(r == CD_HR_CBOR_SIZE, "hwnd=%p r=0x%lx", (void *)hw[i], (unsigned long)r);
    }
}
TEST(ctapdev_send_outputs_overwritten_even_on_failure) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const DWORD pre[] = { 1, 0x2000, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof pre / sizeof pre[0]; i++) {
        DWORD cbOut = pre[i]; BYTE *out = (BYTE *)(ULONG_PTR)0x1000;
        sc(NULL, 0, &cbOut, &out, NULL, NULL);
        CHECKF(cbOut == 0 && out == NULL, "pre=0x%lx", (unsigned long)pre[i]);
    }
}
TEST(ctapdev_send_repeatable) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    for (int i = 0; i < 300; i++) {
        SC_INIT();
        CDHR r = sc(NULL, 0, &cbOut, &out, NULL, NULL);
        if (r != CD_HR_CBOR_SIZE) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); break; }
    }
}

/* ---- selected-device argument ---- */
TEST(ctapdev_send_device_without_pin_is_invalid_parameter) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    BYTE dummy[16];
    for (size_t k = 0; k < 4; k++) {
        void *dev = cd_dev_alloc();
        switch (k) { case 0: break; case 1: cd_dev_set(dev, 1, NULL, NULL); break; case 2: cd_dev_set(dev, 1, dummy, dummy); break; default: cd_dev_set(dev, 0, dummy, dummy); }
        SC_INIT(); BYTE b[1] = { 0xA0 };
        CDHR r = sc(b, 1, &cbOut, &out, NULL, &dev);   /* even a "complete" record cannot be sent without a PIN */
        CHECKF(r == CD_NTE_INVALID_PARAMETER, "variant %zu r=0x%lx", k, (unsigned long)r);
        CHECKF(dev == NULL && cbOut == 0 && out == NULL, "variant %zu: outputs", k);
    }
}
TEST(ctapdev_send_device_takes_precedence_over_cbor_validation) {
    /* With a record present the CBOR is not even looked at. */
    REQUIRE(UN(WebAuthNCtapSendCommand));
    void *dev = cd_dev_alloc(); SC_INIT();
    CDHR r = sc(NULL, 0, &cbOut, &out, NULL, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(dev == NULL);
    dev = cd_dev_alloc();
    r = sc(NULL, 0xFFFFFFFF, &cbOut, &out, NULL, &dev);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(dev == NULL);
}
TEST(ctapdev_send_null_device_slot_pointer_allowed) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); CDHR r = sc(NULL, 0, &cbOut, &out, NULL, NULL);
    EXPECT_EQ(r, CD_HR_CBOR_SIZE);
}
TEST(ctapdev_send_device_slot_holding_null_behaves_like_absent) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    void *dev = NULL; SC_INIT();
    CDHR r = sc(NULL, 0, &cbOut, &out, NULL, &dev);
    EXPECT_EQ(r, CD_HR_CBOR_SIZE); CHECK(dev == NULL);
}

/* ---- PIN argument ---- */
TEST(ctapdev_send_pin_without_device_wiped_and_rejected) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); WCHAR pin[24]; cd_pin_fill(pin, 24, 6, L'4'); BYTE b[1] = { 0xA0 };
    CDHR r = sc(b, 1, &cbOut, &out, pin, NULL);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(cd_pin_wiped(pin, 6)); CHECK(cd_pin_tail_intact(pin, 7, 24));
    EXPECT_EQ(cbOut, 0); CHECK(out == NULL);
}
TEST(ctapdev_send_pin_checked_before_cbor) {
    /* A PIN with an otherwise invalid CBOR request: the PIN branch wins (0x80090027, not 0x8007044C). */
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); WCHAR pin[8]; cd_pin_fill(pin, 8, 4, L'1');
    CDHR r = sc(NULL, 0, &cbOut, &out, pin, NULL);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_wiped(pin, 4));
}
TEST(ctapdev_send_pin_length_table) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const size_t ns[] = { 0, 1, 3, 4, 63, 64, 65, 200, 1000, 4000 };
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        size_t n = ns[i], cap = n + 20; WCHAR *p = (WCHAR *)LocalAlloc(LPTR, cap * 2); SC_INIT();
        cd_pin_fill(p, cap, n, L'5');
        CDHR r = sc(NULL, 0, &cbOut, &out, p, NULL);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(p, n) && cd_pin_tail_intact(p, n + 1, cap), "len=%zu r=0x%lx", n, (unsigned long)r);
        LocalFree(p);
    }
}
TEST(ctapdev_send_pin_embedded_nul) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); WCHAR p[12]; cd_pin_fill(p, 12, 0, 0);
    p[0] = L'a'; p[1] = L'b'; p[2] = L'c'; p[3] = 0; p[4] = L'd'; p[5] = L'e'; p[6] = 0;
    CDHR r = sc(NULL, 0, &cbOut, &out, p, NULL);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER);
    CHECK(p[0] == 0 && p[1] == 0 && p[2] == 0);
    CHECK(p[4] == L'd' && p[5] == L'e');
}
TEST(ctapdev_send_pin_with_incomplete_device) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    BYTE dummy[16];
    static const struct { DWORD kind; int p20, p28; } v[] = { {0,0,0}, {1,0,0}, {1,1,0}, {1,0,1}, {0,1,1} };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        void *dev = cd_dev_alloc(); cd_dev_set(dev, v[i].kind, v[i].p20 ? dummy : NULL, v[i].p28 ? dummy : NULL);
        if (cd_dev_complete(dev)) { LocalFree(dev); continue; }   /* a complete record would be forwarded to the device */
        SC_INIT(); WCHAR pin[12]; cd_pin_fill(pin, 12, 5, L'9'); BYTE b[1] = { 0xA0 };
        CDHR r = sc(b, 1, &cbOut, &out, pin, &dev);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && dev == NULL && cd_pin_wiped(pin, 5), "variant %zu r=0x%lx", i, (unsigned long)r);
        CHECKF(cbOut == 0 && out == NULL, "variant %zu outputs", i);
    }
}
TEST(ctapdev_send_pin_surrogates_and_nonbmp) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    static const WCHAR pins[][6] = { { 0xD800, 0 }, { 0xDC00, 0xD800, 0 }, { 0xD83D, 0xDD11, 0 }, { 0x00E9, 0x4E2D, 0 } };
    for (size_t i = 0; i < 4; i++) {
        WCHAR w[12]; cd_pin_fill(w, 12, 0, 0); size_t n = lstrlenW(pins[i]); memcpy(w, pins[i], (n + 1) * 2); SC_INIT();
        CDHR r = sc(NULL, 0, &cbOut, &out, w, NULL);
        CHECKF(r == CD_NTE_INVALID_PARAMETER && cd_pin_wiped(w, n), "pin #%zu", i);
    }
}
TEST(ctapdev_send_pin_empty_string) {
    REQUIRE(UN(WebAuthNCtapSendCommand));
    SC_INIT(); WCHAR w[4]; cd_pin_fill(w, 4, 0, 0);
    CDHR r = sc(NULL, 0, &cbOut, &out, w, NULL);
    EXPECT_EQ(r, CD_NTE_INVALID_PARAMETER); CHECK(cd_pin_tail_intact(w, 1, 4));
}
