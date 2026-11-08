#include "en_common.h"

/* ---- per-code exact strings ---------------------------------------- */
#define NAME_TEST(id, idx) \
TEST(errname_code_##id) { \
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f); \
    PCWSTR s = f((HRESULT)en_table[idx].code); \
    CHECK(s != NULL); if (!s) return; \
    EXPECT_WSTR(s, en_table[idx].name); \
    EXPECT_EQ(lstrlenW(s), lstrlenW(en_table[idx].name)); \
    CHECK(s[lstrlenW(s)] == 0); \
    CHECK(f((HRESULT)en_table[idx].code) == s); \
}
NAME_TEST(s_ok, 0)
NAME_TEST(nte_exists, 1)
NAME_TEST(nte_not_found, 2)
NAME_TEST(nte_keyset_full, 3)
NAME_TEST(nte_invalid_parameter, 4)
NAME_TEST(nte_not_supported, 5)
NAME_TEST(nte_80090035, 6)
NAME_TEST(nte_80090036, 7)
NAME_TEST(win32_not_supported, 8)
NAME_TEST(win32_cancelled, 9)
NAME_TEST(win32_timeout, 10)

TEST(errname_s_ok_is_success_not_ok) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    PCWSTR s = f(S_OK);
    CHECK(s != NULL); if (!s) return;
    EXPECT_WSTR(s, L"Success");
    CHECK(lstrcmpW(s, L"Ok") != 0);
    CHECK(lstrcmpW(s, L"UnknownError") != 0);
}

TEST(errname_table_all) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++) {
        PCWSTR s = f((HRESULT)en_table[i].code);
        CHECKF(s != NULL, "%s", en_table[i].sym);
        if (s) CHECKF(!lstrcmpW(s, en_table[i].name), "%s", en_table[i].sym);
    }
}

/* ---- pointer identity: constant strings shared by every code that maps to them */
TEST(errname_same_name_same_pointer) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        for (size_t j = i + 1; j < EN_N; j++) {
            PCWSTR a = f((HRESULT)en_table[i].code), b = f((HRESULT)en_table[j].code);
            if (!lstrcmpW(en_table[i].name, en_table[j].name))
                CHECKF(a == b, "%s vs %s", en_table[i].sym, en_table[j].sym);
            else
                CHECKF(a != b, "%s vs %s", en_table[i].sym, en_table[j].sym);
        }
}
TEST(errname_unknown_same_pointer) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    PCWSTR a = f(E_FAIL);
    CHECK(a != NULL);
    CHECK(f(E_INVALIDARG) == a);
    CHECK(f(E_OUTOFMEMORY) == a);
    CHECK(f((HRESULT)0x12345678) == a);
    CHECK(f((HRESULT)0xFFFFFFFF) == a);
}
TEST(errname_pointers_stable_over_repeats) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    PCWSTR first[EN_N];
    for (size_t i = 0; i < EN_N; i++) first[i] = f((HRESULT)en_table[i].code);
    for (int r = 0; r < 200; r++)
        for (size_t i = 0; i < EN_N; i++)
            if (f((HRESULT)en_table[i].code) != first[i]) { CHECKF(0, "pointer changed %s", en_table[i].sym); return; }
    CHECK(1);
}
TEST(errname_pointer_inside_module_image) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    HMODULE m = GetModuleHandleA("webauthn.dll"); if (!m) { t_skip("module handle"); return; }
    for (size_t i = 0; i < EN_N; i++) {
        PCWSTR s = f((HRESULT)en_table[i].code);
        MEMORY_BASIC_INFORMATION mbi; memset(&mbi, 0, sizeof mbi);
        CHECK(VirtualQuery(s, &mbi, sizeof mbi) != 0);
        CHECKF(mbi.AllocationBase == (void *)m, "%s string not in webauthn.dll image", en_table[i].sym);
        if (i == 0) t_note("string protection=0x%lx", (unsigned long)mbi.Protect);
    }
    PCWSTR u = f(E_FAIL); MEMORY_BASIC_INFORMATION mbi;
    CHECK(VirtualQuery(u, &mbi, sizeof mbi) != 0);
    CHECK(mbi.AllocationBase == (void *)m);
}
TEST(errname_readable_to_terminator) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++) {
        PCWSTR s = f((HRESULT)en_table[i].code); if (!s) { CHECK(0); continue; }
        size_t n = 0; while (s[n] && n < 64) n++;
        CHECKF(n < 64 && n == wcslen(en_table[i].name), "%s", en_table[i].sym);
        CHECK(n >= 7);
    }
}
TEST(errname_never_null_never_empty) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    unsigned probes[] = {0, 1, 0xFFFFFFFFu, 0x80000000u, 0x7FFFFFFFu, 0x80004005u, 0x80070057u, 0x8007000Eu, 0x80070005u, 0x8009002Eu};
    for (size_t i = 0; i < sizeof probes / sizeof *probes; i++) {
        PCWSTR s = f((HRESULT)probes[i]);
        CHECK(s != NULL); if (s) CHECK(s[0] != 0);
    }
}
TEST(errname_does_not_touch_lasterror) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    SET_ERR(0x1234); f(E_FAIL); EXPECT_EQ(GetLastError(), 0x1234);
    SET_ERR(0x1234); f(S_OK);   EXPECT_EQ(GetLastError(), 0x1234);
    SET_ERR(0x1234); f((HRESULT)0x8009000F); EXPECT_EQ(GetLastError(), 0x1234);
}

/* ---- common HRESULTs that are NOT handled -> UnknownError ---------------- */
static const struct { unsigned c; const char *sym; } en_unhandled[] = {
    {0x00000001u,"S_FALSE"}, {0x80004001u,"E_NOTIMPL"}, {0x80004002u,"E_NOINTERFACE"}, {0x80004003u,"E_POINTER"},
    {0x80004004u,"E_ABORT"}, {0x80004005u,"E_FAIL"}, {0x8000FFFFu,"E_UNEXPECTED"}, {0x80070005u,"E_ACCESSDENIED"},
    {0x80070006u,"E_HANDLE"}, {0x8007000Eu,"E_OUTOFMEMORY"}, {0x80070057u,"E_INVALIDARG"},
    {0x8007001Fu,"ERROR_GEN_FAILURE"}, {0x80070031u,"ERROR_NOT_SUPPORTED-1"}, {0x80070033u,"ERROR_NOT_SUPPORTED+1"},
    {0x800700E8u,"x"}, {0x8007007Au,"ERROR_INSUFFICIENT_BUFFER"}, {0x800700EAu,"ERROR_MORE_DATA"},
    {0x800705B3u,"TIMEOUT-1"}, {0x800705B5u,"TIMEOUT+1"}, {0x800704C6u,"CANCELLED-1"}, {0x800704C8u,"CANCELLED+1"},
    {0x800704C7u ^ 0x10000u, "flip16"}, {0x00000032u,"ERROR_NOT_SUPPORTED raw"}, {0x000004C7u,"ERROR_CANCELLED raw"},
    {0x000005B4u,"ERROR_TIMEOUT raw"}, {0x80090001u,"NTE_BAD_UID"}, {0x80090002u,"NTE_BAD_HASH"},
    {0x80090005u,"NTE_BAD_DATA"}, {0x8009000Eu,"NTE_NO_MEMORY"}, {0x80090010u,"NTE_PERM"}, {0x80090012u,"NTE_NO_KEY"},
    {0x80090026u,"NTE_INVALID_HANDLE"}, {0x80090028u,"NTE_BUFFER_TOO_SMALL"}, {0x8009002Au,"NTE_NO_MORE_ITEMS"},
    {0x8009002Eu,"NTE_DEVICE_NOT_READY"}, {0x80090022u,"NTE_TOKEN_KEYSET-1"}, {0x80090024u,"NTE_TOKEN_KEYSET+1"},
    {0x80090034u,"0x80090034"}, {0x80090037u,"0x80090037"}, {0x80090030u,"NTE_DEVICE_NOT_READY alt"},
    {0x80090008u,"NTE_BAD_ALGID"}, {0x8009000Du,"NTE_NO_KEY2"}, {0x8009001Fu,"x"}, {0x80090020u,"x"},
    {0x80100001u,"x"}, {0x80280000u,"x"}, {0x80700000u,"DOM unknown"}, {0x80700009u,"DOM NotSupported"},
    {0x8070000Bu,"DOM InvalidState"}, {0x8070001Au,"DOM Constraint"}, {0x80700023u,"DOM NotAllowed"},
    {0x7FFFFFFFu,"INT_MAX"}, {0x80000000u,"INT_MIN"}, {0xFFFFFFFFu,"-1"}, {0xFFFFFFFEu,"-2"},
    {0x80090023u + 0x10000u,"hi"}, {0x00090023u,"low-half"}, {0x0009000Fu,"low-half2"},
};
TEST(errname_unhandled_codes_unknown) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < sizeof en_unhandled / sizeof *en_unhandled; i++) {
        PCWSTR s = f((HRESULT)en_unhandled[i].c);
        CHECKF(s && !lstrcmpW(s, L"UnknownError"), "0x%08x %s", en_unhandled[i].c, en_unhandled[i].sym);
    }
}
#define UNK_TEST(id, v) TEST(errname_unknown_##id) { \
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f); \
    PCWSTR s = f((HRESULT)(v)); CHECK(s != NULL); if (s) EXPECT_WSTR(s, L"UnknownError"); }
UNK_TEST(e_fail, 0x80004005u)
UNK_TEST(e_invalidarg, 0x80070057u)
UNK_TEST(e_accessdenied, 0x80070005u)
UNK_TEST(e_outofmemory, 0x8007000Eu)
UNK_TEST(e_notimpl, 0x80004001u)
UNK_TEST(nte_no_memory, 0x8009000Eu)
UNK_TEST(nte_device_not_ready, 0x80090030u)
UNK_TEST(nte_buffer_too_small, 0x80090028u)
UNK_TEST(s_false, 1)
UNK_TEST(minus_one, 0xFFFFFFFFu)
UNK_TEST(int_min, 0x80000000u)
UNK_TEST(int_max, 0x7FFFFFFFu)
UNK_TEST(raw_win32_not_supported, 50)
UNK_TEST(raw_win32_cancelled, 1223)
UNK_TEST(raw_win32_timeout, 1460)
UNK_TEST(dom_value_itself, 0x80700023u)

/* ---- neighbours of every handled code: +-1, +-2, single-bit flips -------- */
TEST(errname_neighbours_pm1_pm2) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        for (int d = -3; d <= 3; d++) {
            unsigned c = en_table[i].code + (unsigned)d;
            PCWSTR s = f((HRESULT)c);
            CHECKF(s && !lstrcmpW(s, en_expect_name(c)), "0x%08x (near %s)", c, en_table[i].sym);
        }
}
TEST(errname_neighbours_bitflips) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++)
        for (int b = 0; b < 32; b++) {
            unsigned c = en_table[i].code ^ (1u << b);
            PCWSTR s = f((HRESULT)c);
            CHECKF(s && !lstrcmpW(s, en_expect_name(c)), "0x%08x (flip %d of %s)", c, b, en_table[i].sym);
        }
}
TEST(errname_neighbours_win32_facility_variants) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    unsigned lows[] = {0x32, 0x4C7, 0x5B4};
    unsigned hi[] = {0x00000000u, 0x00070000u, 0x80000000u, 0x80070000u, 0x80090000u, 0xC0070000u, 0xC0000000u, 0x88070000u, 0x80080000u};
    for (size_t a = 0; a < 3; a++)
        for (size_t b = 0; b < sizeof hi / sizeof *hi; b++) {
            unsigned c = hi[b] | lows[a];
            PCWSTR s = f((HRESULT)c);
            CHECKF(s && !lstrcmpW(s, en_expect_name(c)), "0x%08x", c);
        }
}
TEST(errname_ntstatus_style_codes_unknown) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    unsigned c[] = {0xC0000001u, 0xC000000Du, 0xC0000022u, 0xC00000BBu, 0xC0000120u, 0x40000000u, 0x00000103u, 0xC0000005u, 0xC0000032u};
    for (size_t i = 0; i < sizeof c / sizeof *c; i++) {
        PCWSTR s = f((HRESULT)c[i]); CHECKF(s && !lstrcmpW(s, L"UnknownError"), "0x%08x", c[i]);
    }
}

/* ---- sweeps ---------------------------------------------------------- */
TEST(errname_sweep_0_to_ffff) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0; PCWSTR unk = f((HRESULT)0xFFFF);
    CHECK(unk && !lstrcmpW(unk, L"UnknownError"));
    for (unsigned c = 0; c <= 0xFFFF; c++) {
        PCWSTR s = f((HRESULT)c);
        if (!s || lstrcmpW(s, en_expect_name(c))) { if (bad++ < 8) CHECKF(0, "0x%04x", c); }
        else if (c && s != unk) { if (bad++ < 8) CHECKF(0, "0x%04x pointer", c); }
    }
    CHECK(bad == 0);
}
TEST(errname_sweep_nte_range) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80090000u; c <= 0x8009FFFFu; c++) {
        PCWSTR s = f((HRESULT)c);
        if (!s || lstrcmpW(s, en_expect_name(c))) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    }
    CHECK(bad == 0);
}
TEST(errname_sweep_win32_hresult_range) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80070000u; c <= 0x8007FFFFu; c++) {
        PCWSTR s = f((HRESULT)c);
        if (!s || lstrcmpW(s, en_expect_name(c))) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    }
    CHECK(bad == 0);
}
TEST(errname_sweep_dom_range) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0x80700000u; c <= 0x8070FFFFu; c++) {
        PCWSTR s = f((HRESULT)c);
        if (!s || lstrcmpW(s, L"UnknownError")) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    }
    CHECK(bad == 0);
}
TEST(errname_sweep_negative_small) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned c = 0xFFFF0000u; c != 0; c++) {
        PCWSTR s = f((HRESULT)c);
        if (!s || lstrcmpW(s, L"UnknownError")) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
    }
    CHECK(bad == 0);
}
TEST(errname_sweep_facility_strides) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned hi = 0; hi <= 0xFFFF; hi++)
        for (unsigned lo = 0; lo < 0x40; lo += 1) {
            unsigned c = (hi << 16) | lo;
            PCWSTR s = f((HRESULT)c);
            if (!s || lstrcmpW(s, en_expect_name(c))) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
        }
    CHECK(bad == 0);
}
TEST(errname_sweep_facility_win32_codes) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0; unsigned lows[] = {0x32, 0x4C7, 0x5B4, 0x0F, 0x11, 0x23, 0x27, 0x29, 0x35, 0x36};
    for (unsigned hi = 0; hi <= 0xFFFF; hi++)
        for (size_t k = 0; k < sizeof lows / sizeof *lows; k++) {
            unsigned c = (hi << 16) | lows[k];
            PCWSTR s = f((HRESULT)c);
            if (!s || lstrcmpW(s, en_expect_name(c))) { if (bad++ < 8) CHECKF(0, "0x%08x", c); }
        }
    CHECK(bad == 0);
}
TEST(errname_sweep_high_bit_stride) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    int bad = 0;
    for (unsigned long long c = 0; c <= 0xFFFFFFFFull; c += 0x10001ull) {
        PCWSTR s = f((HRESULT)(unsigned)c);
        if (!s || lstrcmpW(s, en_expect_name((unsigned)c))) { if (bad++ < 8) CHECKF(0, "0x%08x", (unsigned)c); }
    }
    CHECK(bad == 0);
}

/* ---- string shape: names are plain ASCII identifiers, distinct set of 6 ---- */
TEST(errname_strings_are_ascii_identifiers) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    for (size_t i = 0; i < EN_N; i++) {
        PCWSTR s = f((HRESULT)en_table[i].code); if (!s) { CHECK(0); continue; }
        for (size_t k = 0; s[k]; k++)
            CHECKF((s[k] >= L'A' && s[k] <= L'Z') || (s[k] >= L'a' && s[k] <= L'z'), "%s char %zu", en_table[i].sym, k);
    }
}
TEST(errname_exactly_six_distinct_strings) {
    WebAuthNGetErrorName_pfn f = UN(WebAuthNGetErrorName); REQUIRE(f);
    PCWSTR seen[16]; int n = 0;
    for (unsigned c = 0; c < 0x400; c++) {
        PCWSTR s = f((HRESULT)c), t = f((HRESULT)(0x80090000u | c));
        PCWSTR both[2] = {s, t};
        for (int k = 0; k < 2; k++) {
            int dup = 0; for (int j = 0; j < n; j++) if (seen[j] == both[k]) dup = 1;
            if (!dup && n < 16) seen[n++] = both[k];
        }
    }
    EXPECT_EQ(n, 6); /* Success, InvalidState, NotAllowed, Constraint, NotSupported, Unknown */
}
