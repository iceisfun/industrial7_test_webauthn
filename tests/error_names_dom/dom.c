#include "en_common.h"

#define DOM_TEST(id, idx) \
TEST(domerr_code_##id) { \
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f); \
    HRESULT r = f((HRESULT)en_table[idx].code); \
    EXPECT_EQ((unsigned)r, en_table[idx].dom); \
}
DOM_TEST(s_ok, 0)
DOM_TEST(nte_exists, 1)
DOM_TEST(nte_not_found, 2)
DOM_TEST(nte_keyset_full, 3)
DOM_TEST(nte_invalid_parameter, 4)
DOM_TEST(nte_not_supported, 5)
DOM_TEST(nte_80090035, 6)
DOM_TEST(nte_80090036, 7)
DOM_TEST(win32_not_supported, 8)
DOM_TEST(win32_cancelled, 9)
DOM_TEST(win32_timeout, 10)

TEST(domerr_table_all) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        CHECKF((unsigned)f((HRESULT)en_table[i].code) == en_table[i].dom, "%s", en_table[i].sym);
}
TEST(domerr_success_is_zero_not_unknown) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    EXPECT_EQ((unsigned)f(S_OK), 0);
    CHECK(SUCCEEDED(f(S_OK)));
    CHECK(FAILED(f(E_FAIL)));
}
TEST(domerr_domain_values_use_facility_0x070_prefix) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    for (size_t i = 1; i < EN_N; i++) {
        unsigned r = (unsigned)f((HRESULT)en_table[i].code);
        CHECKF((r >> 16) == 0x8070, "%s -> 0x%08x", en_table[i].sym, r);
    }
}
TEST(domerr_five_distinct_categories) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    unsigned v[] = {0x80700000u, 0x80700009u, 0x8070000Bu, 0x8070001Au, 0x80700023u};
    HRESULT in[] = {E_FAIL, (HRESULT)0x80090027, (HRESULT)0x8009000F, (HRESULT)0x80090029, (HRESULT)0x80090011};
    for (int i = 0; i < 5; i++) {
        EXPECT_EQ((unsigned)f(in[i]), v[i]);
        for (int j = i + 1; j < 5; j++) CHECK(v[i] != v[j]);
    }
}
TEST(domerr_ntstatus_and_zero_neighbours) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    EXPECT_EQ((unsigned)f(1), 0x80700000u);
    EXPECT_EQ((unsigned)f(-1), 0x80700000u);
    EXPECT_EQ((unsigned)f((HRESULT)0x7FFFFFFF), 0x80700000u);
    EXPECT_EQ((unsigned)f((HRESULT)0x80000000), 0x80700000u);
    EXPECT_EQ((unsigned)f((HRESULT)0xC0000022), 0x80700000u);
}
TEST(domerr_common_hresults_unknown) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    unsigned c[] = {0x80004001u, 0x80004002u, 0x80004003u, 0x80004004u, 0x80004005u, 0x8000FFFFu,
        0x80070005u, 0x80070006u, 0x8007000Eu, 0x80070057u, 0x8007007Au, 0x8007001Fu,
        0x8009000Eu, 0x80090010u, 0x80090026u, 0x80090028u, 0x8009002Eu, 0x80090030u};
    for (size_t i = 0; i < sizeof c / sizeof *c; i++)
        CHECKF((unsigned)f((HRESULT)c[i]) == 0x80700000u, "0x%08x", c[i]);
}
#define DUNK(id, v) TEST(domerr_unknown_##id) { \
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f); \
    EXPECT_EQ((unsigned)f((HRESULT)(v)), 0x80700000u); }
DUNK(e_fail, 0x80004005u)
DUNK(e_invalidarg, 0x80070057u)
DUNK(e_accessdenied, 0x80070005u)
DUNK(e_outofmemory, 0x8007000Eu)
DUNK(e_notimpl, 0x80004001u)
DUNK(nte_no_memory, 0x8009000Eu)
DUNK(nte_device_not_ready, 0x80090030u)
DUNK(raw_win32_not_supported, 50)
DUNK(raw_win32_cancelled, 1223)
DUNK(raw_win32_timeout, 1460)
DUNK(dom_unknown_idempotent, 0x80700000u)
DUNK(dom_notallowed_value, 0x80700023u)
DUNK(dom_constraint_value, 0x8070001Au)
DUNK(dom_invalidstate_value, 0x8070000Bu)
DUNK(dom_notsupported_value, 0x80700009u)
DUNK(minus_one, 0xFFFFFFFFu)

TEST(domerr_neighbours_pm3) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        for (int d = -3; d <= 3; d++) {
            unsigned c = en_table[i].code + (unsigned)d;
            CHECKF((unsigned)f((HRESULT)c) == en_expect_dom(c), "0x%08x (near %s)", c, en_table[i].sym);
        }
}
TEST(domerr_neighbours_bitflips) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        for (int b = 0; b < 32; b++) {
            unsigned c = en_table[i].code ^ (1u << b);
            CHECKF((unsigned)f((HRESULT)c) == en_expect_dom(c), "0x%08x (flip %d of %s)", c, b, en_table[i].sym);
        }
}
TEST(domerr_neighbours_win32_facility_variants) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    unsigned lows[] = {0x32, 0x4C7, 0x5B4};
    unsigned hi[] = {0x00000000u, 0x00070000u, 0x80000000u, 0x80070000u, 0x80090000u, 0xC0070000u, 0xC0000000u, 0x88070000u, 0x80080000u};
    for (size_t a = 0; a < 3; a++)
        for (size_t b = 0; b < sizeof hi / sizeof *hi; b++) {
            unsigned c = hi[b] | lows[a];
            CHECKF((unsigned)f((HRESULT)c) == en_expect_dom(c), "0x%08x", c);
        }
}
TEST(domerr_sweep_0_to_ffff) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0; c <= 0xFFFF; c++)
        if ((unsigned)f((HRESULT)c) != en_expect_dom(c)) { if (bad++ < 8) CHECKF(0, "0x%04x", c); }
    CHECK(bad == 0);
}
TEST(domerr_sweep_nte_range) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80090000u; c <= 0x8009FFFFu; c++)
        if ((unsigned)f((HRESULT)c) != en_expect_dom(c)) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    CHECK(bad == 0);
}
TEST(domerr_sweep_win32_hresult_range) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80070000u; c <= 0x8007FFFFu; c++)
        if ((unsigned)f((HRESULT)c) != en_expect_dom(c)) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    CHECK(bad == 0);
}
TEST(domerr_sweep_dom_range) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80700000u; c <= 0x8070FFFFu; c++)
        if ((unsigned)f((HRESULT)c) != 0x80700000u) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    CHECK(bad == 0);
}
TEST(domerr_sweep_negative_small) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0xFFFF0000u; c != 0; c++)
        if ((unsigned)f((HRESULT)c) != 0x80700000u) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    CHECK(bad == 0);
}
TEST(domerr_sweep_facility_win32_codes) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0; unsigned lows[] = {0x32, 0x4C7, 0x5B4, 0x0F, 0x11, 0x23, 0x27, 0x29, 0x35, 0x36};
    for (unsigned hi = 0; hi <= 0xFFFF; hi++)
        for (size_t k = 0; k < sizeof lows / sizeof *lows; k++) {
            unsigned c = (hi << 16) | lows[k];
            if ((unsigned)f((HRESULT)c) != en_expect_dom(c)) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
        }
    CHECK(bad == 0);
}
TEST(domerr_sweep_high_bit_stride) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    int bad = 0;
    for (unsigned long long c = 0; c <= 0xFFFFFFFFull; c += 0x10001ull)
        if ((unsigned)f((HRESULT)(unsigned)c) != en_expect_dom((unsigned)c)) { if (bad++ < 8) CHECKF(0, "0x%08x", (unsigned)c); }
    CHECK(bad == 0);
}
TEST(domerr_does_not_touch_lasterror) {
    WebAuthNGetW3CExceptionDOMError_pfn f = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(f);
    SET_ERR(0x4321); f(E_FAIL); EXPECT_EQ(GetLastError(), 0x4321);
    SET_ERR(0x4321); f(S_OK);   EXPECT_EQ(GetLastError(), 0x4321);
}

/* ---- cross-function consistency: name <-> DOM value ---------------------- */
static const struct { const wchar_t *name; unsigned dom; } en_pairs[] = {
    {L"Success", 0}, {L"UnknownError", 0x80700000u}, {L"NotSupportedError", 0x80700009u},
    {L"InvalidStateError", 0x8070000Bu}, {L"ConstraintError", 0x8070001Au}, {L"NotAllowedError", 0x80700023u},
};
TEST(errname_dom_consistency_table) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName);
    WebAuthNGetW3CExceptionDOMError_pfn d = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(n); REQUIRE(d);
    for (size_t i = 0; i < EN_N; i++) {
        PCWSTR s = n((HRESULT)en_table[i].code); unsigned r = (unsigned)d((HRESULT)en_table[i].code);
        int found = 0;
        for (size_t k = 0; k < sizeof en_pairs / sizeof *en_pairs; k++)
            if (!lstrcmpW(s, en_pairs[k].name)) { found = 1; CHECKF(r == en_pairs[k].dom, "%s", en_table[i].sym); }
        CHECKF(found, "%s", en_table[i].sym);
    }
}
TEST(errname_dom_consistency_sweep) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName);
    WebAuthNGetW3CExceptionDOMError_pfn d = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(n); REQUIRE(d);
    int bad = 0;
    for (unsigned c = 0x80090000u; c < 0x80091000u; c++) {
        PCWSTR s = n((HRESULT)c); unsigned r = (unsigned)d((HRESULT)c);
        int ok = 0;
        for (size_t k = 0; k < sizeof en_pairs / sizeof *en_pairs; k++)
            if (!lstrcmpW(s, en_pairs[k].name) && r == en_pairs[k].dom) ok = 1;
        if (!ok && bad++ < 8) CHECKF(0, "0x%08x", c);
    }
    CHECK(bad == 0);
}

/* ---- threads -------------------------------------------------------- */
static volatile LONG g_bad;
static DWORD WINAPI worker(LPVOID p) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName);
    WebAuthNGetW3CExceptionDOMError_pfn d = UN(WebAuthNGetW3CExceptionDOMError);
    PCWSTR first[EN_N];
    for (size_t i = 0; i < EN_N; i++) first[i] = n((HRESULT)en_table[i].code);
    for (int r = 0; r < 3000; r++)
        for (size_t i = 0; i < EN_N; i++) {
            unsigned c = en_table[i].code + (r % 5 == 4 ? 1u : 0u);
            PCWSTR s = n((HRESULT)c);
            if (!s || lstrcmpW(s, en_expect_name(c))) InterlockedIncrement(&g_bad);
            if (r % 5 != 4 && s != first[i]) InterlockedIncrement(&g_bad);
            if ((unsigned)d((HRESULT)c) != en_expect_dom(c)) InterlockedIncrement(&g_bad);
        }
    return 0;
}
TEST(errname_dom_threads_8) {
    REQUIRE(UN(WebAuthNGetErrorName)); REQUIRE(UN(WebAuthNGetW3CExceptionDOMError));
    HANDLE h[8]; g_bad = 0; int n = 0;
    for (int i = 0; i < 8; i++) { h[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL); if (h[i]) n++; }
    CHECK(n == 8);
    DWORD w = WaitForMultipleObjects(n, h, TRUE, 20000);
    CHECK(w == WAIT_OBJECT_0);
    for (int i = 0; i < n; i++) CloseHandle(h[i]);
    CHECK(g_bad == 0);
}
static DWORD WINAPI worker_sweep(LPVOID p) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName);
    WebAuthNGetW3CExceptionDOMError_pfn d = UN(WebAuthNGetW3CExceptionDOMError);
    unsigned off = (unsigned)(ULONG_PTR)p;
    for (unsigned c = off; c < 0x20000; c += 8) {
        if (lstrcmpW(n((HRESULT)c), en_expect_name(c))) InterlockedIncrement(&g_bad);
        if ((unsigned)d((HRESULT)c) != en_expect_dom(c)) InterlockedIncrement(&g_bad);
    }
    return 0;
}
TEST(errname_dom_threads_8_partitioned_sweep) {
    REQUIRE(UN(WebAuthNGetErrorName)); REQUIRE(UN(WebAuthNGetW3CExceptionDOMError));
    HANDLE h[8]; g_bad = 0; int n = 0;
    for (int i = 0; i < 8; i++) { h[i] = CreateThread(NULL, 0, worker_sweep, (LPVOID)(ULONG_PTR)i, 0, NULL); if (h[i]) n++; }
    CHECK(n == 8);
    CHECK(WaitForMultipleObjects(n, h, TRUE, 20000) == WAIT_OBJECT_0);
    for (int i = 0; i < n; i++) CloseHandle(h[i]);
    CHECK(g_bad == 0);
}
static PCWSTR g_thr_ptr[EN_N];
static DWORD WINAPI worker_ptr(LPVOID p) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName);
    for (size_t i = 0; i < EN_N; i++) g_thr_ptr[i] = n((HRESULT)en_table[i].code);
    return 0;
}
TEST(errname_pointer_shared_across_threads) {
    WebAuthNGetErrorName_pfn n = UN(WebAuthNGetErrorName); REQUIRE(n);
    HANDLE h = CreateThread(NULL, 0, worker_ptr, NULL, 0, NULL);
    CHECK(h != NULL); if (!h) return;
    CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0);
    CloseHandle(h);
    for (size_t i = 0; i < EN_N; i++)
        CHECKF(g_thr_ptr[i] == n((HRESULT)en_table[i].code), "%s", en_table[i].sym);
}
