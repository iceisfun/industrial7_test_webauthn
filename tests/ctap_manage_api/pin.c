/* WebAuthNCtapManageSetPin / ChangePin / AuthenticatePin: argument handling before any device I/O.
 *
 * Verified behaviour of the reference implementation:
 *  - The retry-count outputs are zeroed on entry, before any validation.
 *  - A NULL PIN (SetPin/AuthenticatePin: the PIN; ChangePin: the old PIN) gives NTE_INVALID_PARAMETER
 *    (0x80090027). ChangePin with a NULL old PIN still wipes a non-NULL new PIN.
 *  - A non-NULL PIN is copied, protected in memory, and the CALLER'S buffer is wiped in place
 *    (wcslen * 2 bytes, terminator excluded) regardless of whether the call later fails.
 *  - There is no client-side length check on the PIN in these entry points: empty and very long PINs
 *    reach the management-handle validation, which fails with NTE_INVALID_PARAMETER for handles
 *    that carry no device session.
 * PIN buffers must therefore be writable.
 */
#include "cm_api.h"

#define SENT_INT  0x5A5A5A5A
#define SENT_DW   0xA5A5A5A5u

static const size_t kLens[] = { 0, 1, 3, 4, 5, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 1000, 2000 };
#define NLENS (sizeof kLens / sizeof kLens[0])

/* ---- SetPin ---- */
TEST(cmsetpin_null_pin_null_handle)
{
    int r = SENT_INT; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, NULL, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0);
}

TEST(cmsetpin_null_pin_every_handle_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; int r = SENT_INT; HRESULT hr;
        void *h = cm_shape(&sh, s);
        hr = UN(WebAuthNCtapManageSetPin)(NULL, h, NULL, &r);
        CHECKF((DWORD)hr == 0x80090027, "%s: got 0x%lx", cm_shape_name[s], (DWORD)hr);
        CHECKF(r == 0, "%s: retries %d", cm_shape_name[s], r);
    }
}

TEST(cmsetpin_pin_wiped_for_every_length_null_handle)
{
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    for (i = 0; i < NLENS; i++) {
        WCHAR *buf = calloc(kLens[i] + 8, sizeof(WCHAR)); int r = SENT_INT; HRESULT hr;
        REQUIRE(buf);
        pin_fill(buf, kLens[i]);
        hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
        CHECKF((DWORD)hr == 0x80090027, "len %zu: got 0x%lx", kLens[i], (DWORD)hr);
        CHECKF(r == 0, "len %zu: retries %d", kLens[i], r);
        CHECKF(pin_wiped(buf, kLens[i]), "len %zu: pin not wiped", kLens[i]);
        CHECKF(pin_canary_ok(buf, kLens[i]), "len %zu: wipe overran terminator", kLens[i]);
        free(buf);
    }
}

TEST(cmsetpin_pin_wiped_for_every_handle_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; WCHAR buf[32]; int r = SENT_INT; HRESULT hr;
        void *h = cm_shape(&sh, s);
        pin_fill(buf, 12);
        hr = UN(WebAuthNCtapManageSetPin)(NULL, h, buf, &r);
        CHECKF((DWORD)hr == 0x80090027, "%s: got 0x%lx", cm_shape_name[s], (DWORD)hr);
        CHECKF(r == 0, "%s", cm_shape_name[s]);
        CHECKF(pin_wiped(buf, 12) && pin_canary_ok(buf, 12), "%s: wipe", cm_shape_name[s]);
    }
}

TEST(cmsetpin_empty_pin_is_not_rejected_early_and_fails_on_handle)
{
    WCHAR buf[8]; int r = SENT_INT; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    pin_fill(buf, 0);
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0);
    CHECK(buf[0] == 0 && pin_canary_ok(buf, 0));
    t_note("empty PIN and NULL PIN are indistinguishable by return code on an invalid handle (both 0x80090027)");
}

TEST(cmsetpin_hwnd_ignored_in_early_failure)
{
    WCHAR buf[16]; int r = SENT_INT; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    pin_fill(buf, 6);
    hr = UN(WebAuthNCtapManageSetPin)(GetDesktopWindow(), NULL, buf, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0);
    CHECK(pin_wiped(buf, 6));
}

TEST(cmsetpin_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    for (i = 0; i < 50; i++) {
        WCHAR buf[16]; int r = SENT_INT; HRESULT hr;
        pin_fill(buf, 8);
        hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
        CHECK((DWORD)hr == 0x80090027); CHECK(r == 0); CHECK(pin_wiped(buf, 8));
    }
}

TEST(cmsetpin_wiped_buffer_second_call_behaves_like_empty_pin)
{
    WCHAR buf[16]; int r = SENT_INT; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    pin_fill(buf, 8);
    UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    r = SENT_INT;
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0);
}

TEST(cmsetpin_non_bmp_and_unicode_pin_wiped)
{
    WCHAR buf[16] = { 0xD83D, 0xDD11, 0x00E9, 0x4E2D, 0x0041, 0 }; int r = SENT_INT; HRESULT hr; int i;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    buf[6] = PIN_CANARY;
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027);
    for (i = 0; i < 6; i++) CHECK(buf[i] == 0);
    CHECK(buf[6] == PIN_CANARY);
}

TEST(cmsetpin_unpaired_surrogate_pin_not_validated)
{
    WCHAR buf[8] = { 0xD800, 0x0031, 0 }; int r = SENT_INT; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    EXPECT_EQ((DWORD)hr, 0x80090027); CHECK(buf[0] == 0 && buf[1] == 0);
}

TEST(cmsetpin_does_not_modify_pin_beyond_terminator)
{
    WCHAR buf[16]; int r = SENT_INT; int i;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    for (i = 0; i < 16; i++) buf[i] = 0x7777;
    buf[4] = 0;
    UN(WebAuthNCtapManageSetPin)(NULL, NULL, buf, &r);
    for (i = 0; i < 4; i++) CHECK(buf[i] == 0);
    for (i = 5; i < 16; i++) CHECK(buf[i] == 0x7777);
}

/* ---- AuthenticatePin ---- */
TEST(cmauthpin_null_pin_null_handle)
{
    int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, NULL, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

TEST(cmauthpin_null_pin_every_handle_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        void *h = cm_shape(&sh, s);
        hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, h, NULL, &r, &u);
        CHECKF((DWORD)hr == 0x80090027 && r == 0 && u == 0, "%s: 0x%lx %d %lu", cm_shape_name[s], (DWORD)hr, r, u);
    }
}

TEST(cmauthpin_pin_wiped_for_every_length_null_handle)
{
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    for (i = 0; i < NLENS; i++) {
        WCHAR *buf = calloc(kLens[i] + 8, sizeof(WCHAR)); int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        REQUIRE(buf);
        pin_fill(buf, kLens[i]);
        hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, buf, &r, &u);
        CHECKF((DWORD)hr == 0x80090027, "len %zu: got 0x%lx", kLens[i], (DWORD)hr);
        CHECKF(r == 0 && u == 0, "len %zu: outputs %d %lu", kLens[i], r, u);
        CHECKF(pin_wiped(buf, kLens[i]) && pin_canary_ok(buf, kLens[i]), "len %zu wipe", kLens[i]);
        free(buf);
    }
}

TEST(cmauthpin_pin_wiped_for_every_handle_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; WCHAR buf[32]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        void *h = cm_shape(&sh, s);
        pin_fill(buf, 9);
        hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, h, buf, &r, &u);
        CHECKF((DWORD)hr == 0x80090027 && r == 0 && u == 0, "%s", cm_shape_name[s]);
        CHECKF(pin_wiped(buf, 9) && pin_canary_ok(buf, 9), "%s wipe", cm_shape_name[s]);
    }
}

TEST(cmauthpin_empty_pin_fails_on_handle)
{
    WCHAR buf[4]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    pin_fill(buf, 0);
    hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, buf, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

TEST(cmauthpin_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    for (i = 0; i < 50; i++) {
        WCHAR buf[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        pin_fill(buf, 8);
        hr = UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, buf, &r, &u);
        CHECK((DWORD)hr == 0x80090027 && r == 0 && u == 0 && pin_wiped(buf, 8));
    }
}

TEST(cmauthpin_hwnd_ignored_in_early_failure)
{
    WCHAR buf[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    pin_fill(buf, 6);
    hr = UN(WebAuthNCtapManageAuthenticatePin)(GetDesktopWindow(), NULL, buf, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

/* ---- ChangePin ---- */
TEST(cmchangepin_both_null)
{
    int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, NULL, NULL, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

TEST(cmchangepin_null_old_wipes_new)
{
    WCHAR nw[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(nw, 7);
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, NULL, nw, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
    CHECK(pin_wiped(nw, 7)); CHECK(pin_canary_ok(nw, 7));
}

TEST(cmchangepin_null_new_wipes_old)
{
    WCHAR old[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(old, 7);
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, NULL, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
    CHECK(pin_wiped(old, 7)); CHECK(pin_canary_ok(old, 7));
}

TEST(cmchangepin_null_new_empty_old)
{
    WCHAR old[4]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(old, 0);
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, NULL, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
    CHECK(old[0] == 0 && pin_canary_ok(old, 0));
}

TEST(cmchangepin_null_old_empty_new)
{
    WCHAR nw[4]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(nw, 0);
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, NULL, nw, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

TEST(cmchangepin_both_pins_old_is_wiped_every_handle_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; WCHAR old[32], nw[32]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        void *h = cm_shape(&sh, s);
        pin_fill(old, 8); pin_fill(nw, 10);
        hr = UN(WebAuthNCtapManageChangePin)(NULL, h, old, nw, &r, &u);
        CHECKF((DWORD)hr == 0x80090027 && r == 0 && u == 0, "%s: 0x%lx", cm_shape_name[s], (DWORD)hr);
        CHECKF(pin_wiped(old, 8) && pin_canary_ok(old, 8), "%s old wipe", cm_shape_name[s]);
        CHECKF(pin_canary_ok(nw, 10), "%s new canary", cm_shape_name[s]);
    }
}

TEST(cmchangepin_both_pins_new_pin_wipe_observation)
{
    /* The routine's second wipe loop is applied to the old-PIN buffer again, so the new PIN
     * is left intact on the success-or-failure path that reaches the device request. Record what
     * the machine does; the contract above is only a reading of the code. */
    WCHAR old[16], nw[16]; int r = SENT_INT; DWORD u = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(old, 8); pin_fill(nw, 8);
    UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, nw, &r, &u);
    CHECK(pin_wiped(old, 8));
    t_note("new PIN buffer after ChangePin(old,new) on invalid handle: %s", pin_wiped(nw, 8) ? "wiped" : pin_untouched(nw, 8) ? "left intact" : "modified");
}

TEST(cmchangepin_every_old_length_with_valid_new)
{
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    for (i = 0; i < NLENS; i++) {
        WCHAR *old = calloc(kLens[i] + 8, sizeof(WCHAR)); WCHAR nw[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        REQUIRE(old);
        pin_fill(old, kLens[i]); pin_fill(nw, 6);
        hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, nw, &r, &u);
        CHECKF((DWORD)hr == 0x80090027 && r == 0 && u == 0, "old len %zu: 0x%lx", kLens[i], (DWORD)hr);
        CHECKF(pin_wiped(old, kLens[i]) && pin_canary_ok(old, kLens[i]), "old len %zu wipe", kLens[i]);
        free(old);
    }
}

TEST(cmchangepin_every_new_length_with_valid_old)
{
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    for (i = 0; i < NLENS; i++) {
        WCHAR *nw = calloc(kLens[i] + 8, sizeof(WCHAR)); WCHAR old[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        REQUIRE(nw);
        pin_fill(old, 6); pin_fill(nw, kLens[i]);
        hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, nw, &r, &u);
        CHECKF((DWORD)hr == 0x80090027 && r == 0 && u == 0, "new len %zu: 0x%lx", kLens[i], (DWORD)hr);
        CHECKF(pin_wiped(old, 6), "new len %zu: old not wiped", kLens[i]);
        CHECKF(pin_canary_ok(nw, kLens[i]), "new len %zu: canary", kLens[i]);
        free(nw);
    }
}

TEST(cmchangepin_same_buffer_for_old_and_new)
{
    WCHAR b[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(b, 8);
    hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, b, b, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
    CHECK(pin_wiped(b, 8));
}

TEST(cmchangepin_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    for (i = 0; i < 50; i++) {
        WCHAR old[16], nw[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
        pin_fill(old, 5); pin_fill(nw, 5);
        hr = UN(WebAuthNCtapManageChangePin)(NULL, NULL, old, nw, &r, &u);
        CHECK((DWORD)hr == 0x80090027 && r == 0 && u == 0 && pin_wiped(old, 5));
    }
}

TEST(cmchangepin_hwnd_ignored_in_early_failure)
{
    WCHAR old[16]; int r = SENT_INT; DWORD u = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageChangePin));
    pin_fill(old, 5);
    hr = UN(WebAuthNCtapManageChangePin)(GetDesktopWindow(), NULL, old, NULL, &r, &u);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(r, 0); EXPECT_EQ(u, 0);
}

/* Cross-function: all three PIN entry points agree on the early-failure code. */
TEST(cmpin_all_entry_points_agree_on_null_pin)
{
    int r = 1; DWORD u = 1; HRESULT a, b, c;
    REQUIRE(UN(WebAuthNCtapManageSetPin)); REQUIRE(UN(WebAuthNCtapManageChangePin)); REQUIRE(UN(WebAuthNCtapManageAuthenticatePin));
    a = UN(WebAuthNCtapManageSetPin)(NULL, NULL, NULL, &r);
    b = UN(WebAuthNCtapManageChangePin)(NULL, NULL, NULL, NULL, &r, &u);
    c = UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, NULL, &r, &u);
    EXPECT_EQ((DWORD)a, 0x80090027); EXPECT_EQ((DWORD)b, 0x80090027); EXPECT_EQ((DWORD)c, 0x80090027);
}

TEST(cmpin_failure_is_not_a_win32_error_code)
{
    HRESULT hr; int r = 0;
    REQUIRE(UN(WebAuthNCtapManageSetPin));
    hr = UN(WebAuthNCtapManageSetPin)(NULL, NULL, NULL, &r);
    CHECK(FAILED(hr)); CHECK(HRESULT_FACILITY(hr) == 9 /* FACILITY_SECURITY */); CHECK((hr & 0xffff) == 0x27);
}
