#include "ctap_misc.h"
/* WebAuthNCtapGetWnfLocalizedString(a, b, c, d, &psz, &flag)
 *
 * Decomp-derived semantics:
 *  - On entry *ppsz = NULL and *pdwFallback = 0 (both are written before any lookup; neither may be NULL).
 *  - When b == 9 the lookup table below is searched on (a, c, d); otherwise a second, larger table is
 *    searched on (a, b, d). A table entry with key 0 for 'a' or 'd' is a wildcard.
 *  - A table hit loads a string resource of the DLL (LoadStringW copied into a LocalAlloc'd,
 *    NUL-terminated buffer) and returns S_OK with *pdwFallback == 0.
 *  - A miss sets *pdwFallback = 1 and formats the generic resource 0x1FB with (a, b, c) as inserts.
 *  - The caller owns *ppsz and frees it with LocalFree. On failure *ppsz stays NULL.
 * Table for b == 9 (c is an HRESULT, string resource id in the second column):
 *   0x800700AA->0x192  0x800705B4->0x193  0x80090035->0x193  0x80070032->0x194  0x80090023->0x198
 *   0x80090320->0x191  0x8009030D->0x190  0x800703EA->0x195  0x800701B1->0x195
 *   and, only when a == 2:  0x8010002F->0x197  0x80100069->0x196  0x80100017->0x197  0x8010001F->0x197 */

static HRESULT call(DWORD a, int b, int c, int d, LPWSTR *s, DWORD *fb)
{
    WebAuthNCtapGetWnfLocalizedString_pfn f = UN(WebAuthNCtapGetWnfLocalizedString);
    return f(a, b, c, d, s, fb);
}
static void freestr(LPWSTR s) { if (s) LocalFree(s); }

static const struct { int hr; unsigned res; unsigned a; } tab9[] = {
    { (int)0x800700AA, 0x192, 0 }, { (int)0x800705B4, 0x193, 0 }, { (int)0x80090035, 0x193, 0 },
    { (int)0x80070032, 0x194, 0 }, { (int)0x80090023, 0x198, 0 }, { (int)0x80090320, 0x191, 0 },
    { (int)0x8009030D, 0x190, 0 }, { (int)0x800703EA, 0x195, 0 }, { (int)0x800701B1, 0x195, 0 },
    { (int)0x8010002F, 0x197, 2 }, { (int)0x80100069, 0x196, 2 }, { (int)0x80100017, 0x197, 2 },
    { (int)0x8010001F, 0x197, 2 },
};

TEST(ctapmisc_wnf_table_hits_succeed_without_fallback)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    for (unsigned i = 0; i < sizeof tab9 / sizeof *tab9; i++) {
        LPWSTR s = (LPWSTR)(ULONG_PTR)1; DWORD fb = 0x55;
        HRESULT hr = call(tab9[i].a, 9, tab9[i].hr, 0, &s, &fb);
        CHECKF(hr == 0, "hr entry %u: 0x%08lx", i, (unsigned long)hr);
        CHECKF(fb == 0, "fallback flag entry %u = %lu", i, fb);
        CHECKF(s != NULL && s != (LPWSTR)1 && s[0] != 0, "string entry %u", i);
        if (s && s != (LPWSTR)1) freestr(s);
    }
}
TEST(ctapmisc_wnf_table_strings_localalloc_and_terminated)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    for (unsigned i = 0; i < sizeof tab9 / sizeof *tab9; i++) {
        LPWSTR s = NULL; DWORD fb = 9;
        HRESULT hr = call(tab9[i].a, 9, tab9[i].hr, 0, &s, &fb);
        if (hr != 0 || !s) { CHECKF(0, "entry %u failed 0x%08lx", i, (unsigned long)hr); continue; }
        SIZE_T cb = LocalSize(s);                      /* proves the buffer is a LocalAlloc block */
        CHECKF(cb != 0 && cb != (SIZE_T)-1, "LocalSize entry %u", i);
        size_t len = lstrlenW(s);
        CHECKF((len + 1) * 2 <= cb, "entry %u not NUL terminated within block", i);
        t_note("wnf[9, 0x%08x] res 0x%x len %zu: %.60ls", (unsigned)tab9[i].hr, tab9[i].res, len, s);
        freestr(s);
    }
}
TEST(ctapmisc_wnf_same_resource_same_string)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    LPWSTR s1 = NULL, s2 = NULL; DWORD f1, f2;
    CHECK(call(0, 9, (int)0x800705B4, 0, &s1, &f1) == 0);       /* both map to resource 0x193 */
    CHECK(call(0, 9, (int)0x80090035, 0, &s2, &f2) == 0);
    if (s1 && s2) { EXPECT_WSTR(s1, s2); CHECK(s1 != s2); }
    freestr(s1); freestr(s2);
    s1 = s2 = NULL;
    CHECK(call(0, 9, (int)0x800703EA, 0, &s1, &f1) == 0);       /* both map to resource 0x195 */
    CHECK(call(0, 9, (int)0x800701B1, 0, &s2, &f2) == 0);
    if (s1 && s2) EXPECT_WSTR(s1, s2);
    freestr(s1); freestr(s2);
}
TEST(ctapmisc_wnf_different_resources_different_strings)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    LPWSTR s1 = NULL, s2 = NULL; DWORD f;
    CHECK(call(0, 9, (int)0x800700AA, 0, &s1, &f) == 0);        /* 0x192 */
    CHECK(call(0, 9, (int)0x80090320, 0, &s2, &f) == 0);        /* 0x191 */
    if (s1 && s2) CHECK(lstrcmpW(s1, s2) != 0);
    freestr(s1); freestr(s2);
}
TEST(ctapmisc_wnf_repeat_returns_fresh_equal_allocations)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    LPWSTR s1 = NULL, s2 = NULL; DWORD f;
    CHECK(call(0, 9, (int)0x800705B4, 0, &s1, &f) == 0);
    CHECK(call(0, 9, (int)0x800705B4, 0, &s2, &f) == 0);
    if (s1 && s2) { CHECK(s1 != s2); EXPECT_WSTR(s1, s2); }
    freestr(s1); freestr(s2);
}
TEST(ctapmisc_wnf_param_d_is_wildcard_for_9_table_entries)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    int ds[] = { 0, 1, 5, 0x7fffffff, -1 };
    for (int i = 0; i < 5; i++) {
        LPWSTR s = NULL; DWORD fb = 7;
        HRESULT hr = call(0, 9, (int)0x800705B4, ds[i], &s, &fb);
        CHECKF(hr == 0 && fb == 0 && s, "d=%d hr=0x%08lx fb=%lu", ds[i], (unsigned long)hr, fb);
        freestr(s);
    }
}
TEST(ctapmisc_wnf_param_a_is_wildcard_for_generic_9_entries)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    DWORD as[] = { 0, 1, 2, 3, 100, 0xFFFFFFFFu };
    for (int i = 0; i < 6; i++) {
        LPWSTR s = NULL; DWORD fb = 7;
        HRESULT hr = call(as[i], 9, (int)0x80090035, 0, &s, &fb);
        CHECKF(hr == 0 && fb == 0 && s, "a=%lu hr=0x%08lx fb=%lu", as[i], (unsigned long)hr, fb);
        freestr(s);
    }
}
TEST(ctapmisc_wnf_smartcard_entries_require_a_equals_2)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    static const int hrs[] = { (int)0x8010002F, (int)0x80100069, (int)0x80100017, (int)0x8010001F };
    for (int i = 0; i < 4; i++) {
        LPWSTR s = NULL; DWORD fb = 0;
        HRESULT hr = call(2, 9, hrs[i], 0, &s, &fb);
        CHECKF(hr == 0 && fb == 0 && s, "a=2 hr=0x%08x", hrs[i]);
        freestr(s);
        for (DWORD a = 0; a <= 4; a++) {
            if (a == 2) continue;
            s = NULL; fb = 0;
            hr = call(a, 9, hrs[i], 0, &s, &fb);
            CHECKF(fb == 1, "a=%lu hr=0x%08x should fall back, fb=%lu", a, hrs[i], fb);
            freestr(s);
        }
    }
}
TEST(ctapmisc_wnf_unmapped_hresult_uses_fallback)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    int hrs[] = { 0, (int)0x80004005, (int)0x12345678, (int)0x80090034, (int)0x800705B5, (int)0xFFFFFFFF };
    for (int i = 0; i < 6; i++) {
        LPWSTR s = NULL; DWORD fb = 0;
        HRESULT hr = call(0, 9, hrs[i], 0, &s, &fb);
        CHECKF(fb == 1, "hr=0x%08x fb=%lu", hrs[i], fb);
        CHECKF(hr == 0, "hr=0x%08x result 0x%08lx", hrs[i], (unsigned long)hr);
        CHECKF(s && s[0], "string present for 0x%08x", hrs[i]);
        if (s) t_note("fallback[9, 0x%08x] = %.80ls", hrs[i], s);
        freestr(s);
    }
}
TEST(ctapmisc_wnf_fallback_string_owned_by_caller)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    LPWSTR s = NULL; DWORD fb = 0;
    HRESULT hr = call(0x7777, 9, 0x13572468, 0, &s, &fb);
    CHECK(hr == 0 && fb == 1);
    if (s) { CHECK(LocalSize(s) >= 2); CHECK(LocalFree(s) == NULL); }
}
TEST(ctapmisc_wnf_fallback_unknown_category_not_9)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    /* category values far outside any plausible table key take the generic fallback */
    int cats[] = { 0x7fff0001, (int)0xC0DE0001, -12345 };
    for (int i = 0; i < 3; i++) {
        LPWSTR s = NULL; DWORD fb = 0;
        HRESULT hr = call(0x7ffe0000, cats[i], 1, 1, &s, &fb);
        CHECKF(hr == 0 && fb == 1 && s, "cat=0x%x hr=0x%08lx fb=%lu", cats[i], (unsigned long)hr, fb);
        freestr(s);
    }
}
TEST(ctapmisc_wnf_outputs_reset_even_when_prepoisoned)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    /* both outputs are initialised to 0 first, then set; a pre-poisoned fallback flag must not leak */
    LPWSTR s = (LPWSTR)(ULONG_PTR)0x1; DWORD fb = 0xFFFFFFFFu;
    HRESULT hr = call(0, 9, (int)0x800700AA, 0, &s, &fb);
    CHECK(hr == 0);
    EXPECT_EQ(fb, 0);
    CHECK(s != (LPWSTR)1);
    freestr(s == (LPWSTR)1 ? NULL : s);
    s = (LPWSTR)(ULONG_PTR)0x1; fb = 0xFFFFFFFFu;
    hr = call(0, 9, 0x13572468, 0, &s, &fb);
    EXPECT_EQ(fb, 1);
    freestr(s == (LPWSTR)1 ? NULL : s);
}
TEST(ctapmisc_wnf_second_table_probe_no_crash)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    int bad = 0;
    for (int b = 0; b < 40; b++) {
        if (b == 9) continue;
        for (DWORD a = 0; a < 4; a++) {
            LPWSTR s = NULL; DWORD fb = 0xFF;
            HRESULT hr = call(a, b, 0, 0, &s, &fb);
            if (!(fb == 0 || fb == 1)) bad++;
            if (hr >= 0 && !s) bad++;
            if (hr < 0 && s) bad++;
            if (s) t_note("wnf[a=%lu,b=%d] fb=%lu %.50ls", a, b, fb, s);
            freestr(s);
        }
    }
    CHECK(bad == 0);
}
TEST(ctapmisc_wnf_failure_leaves_string_null_invariant)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    for (DWORD a = 0; a < 200; a += 7) {
        LPWSTR s = (LPWSTR)1; DWORD fb = 3;
        HRESULT hr = call(a, 9, (int)(0x80090000 + a), 0, &s, &fb);
        CHECKF((hr >= 0) == (s != NULL), "a=%lu hr=0x%08lx s=%p", a, (unsigned long)hr, s);
        if (hr >= 0) freestr(s);
    }
}
TEST(ctapmisc_wnf_stress_alloc_free_1000)
{
    REQUIRE(UN(WebAuthNCtapGetWnfLocalizedString));
    int ok = 0;
    for (int i = 0; i < 1000; i++) {
        LPWSTR s = NULL; DWORD fb;
        if (call(0, 9, tab9[i % 13].hr, 0, &s, &fb) == 0 && s) ok++;
        freestr(s);
    }
    CHECK(ok == 1000);
}
