/* DPAPI-NG style protection descriptors: create / inspect / close, named descriptor lookup, and the
 * argument checks of NCryptProtectSecret. Only the machine-local "LOCAL=" / "SID=" rule forms are used and
 * every protection call is silent (no window handle), so no user interface can appear. */
#include "gap1.h"

#define SENT_P ((void *)(ULONG_PTR)0x1234)

static const WCHAR *k_bad_rules[] = { L"NOSUCHRULE=abc", L"LOCAL", L"=" };
static const WCHAR *k_odd_rules[] = { L"LOCAL=bogus", L"SID=notasid", L"LOCAL=" };

/* ---- NCryptCreateProtectionDescriptor ---------------------------------------------------------- */
TEST(gap1_cpd_null_out_pointer) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    G_EQ(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, NULL), G_NTE_INVALID_PARAM);
    G_EQ(UN(NCryptCreateProtectionDescriptor)(NULL, 0, NULL), G_NTE_INVALID_PARAM);
    G_EQ(UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0xFFFFFFFF, NULL), G_NTE_INVALID_PARAM);
}

TEST(gap1_cpd_null_or_empty_rule_resets_output) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    void *h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(NULL, 0, &h), G_NTE_INVALID_PARAM);
    CHECK(h == NULL);                                          /* the output is cleared before the rule is examined */
    h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(L"", 0, &h), G_NTE_INVALID_PARAM);
    CHECK(h == NULL);
    h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(NULL, 0xFFFFFFFF, &h), G_NTE_INVALID_PARAM);   /* rule is checked before flags */
    CHECK(h == NULL);
}

TEST(gap1_cpd_bad_flags) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    /* accepted bits: NCRYPT_NAMED_DESCRIPTOR_FLAG (1) and NCRYPT_MACHINE_KEY_FLAG (0x20) only */
    static const DWORD fl[] = { 2, 4, 8, 0x10, 0x40, 0x80, 0x100, 0x200, 0x10000, 0x80000000, 0xFFFFFFDE, 0xFFFFFFFF, 0x22, 0x41 };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        void *h = SENT_P;
        DWORD st = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", fl[i], &h);
        CHECKF(st == G_NTE_BAD_FLAGS, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        CHECK(h == NULL);
    }
}

TEST(gap1_cpd_valid_rules) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    static const WCHAR *ok[] = { L"LOCAL=user", L"LOCAL=machine", L"LOCAL=logon", L"SID=S-1-1-0", L"SID=S-1-5-18" };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        void *h = NULL;
        DWORD st = UN(NCryptCreateProtectionDescriptor)(ok[i], 0, &h);
        CHECKF(st == 0, "%ls st=0x%08lx", ok[i], (unsigned long)st);
        CHECK(h != NULL);
        if (st == 0 && h) G_EQ(UN(NCryptCloseProtectionDescriptor)(h), 0);
    }
}

TEST(gap1_cpd_machine_flag_with_local_machine) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *h = NULL;
    DWORD st = UN(NCryptCreateProtectionDescriptor)(L"LOCAL=machine", NCRYPT_MACHINE_KEY_FLAG, &h);
    CHECKF(st == 0, "st=0x%08lx", (unsigned long)st);
    if (st == 0 && h) UN(NCryptCloseProtectionDescriptor)(h);
}

TEST(gap1_cpd_webcredentials_rule) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *h = NULL;
    DWORD st = UN(NCryptCreateProtectionDescriptor)(L"WEBCREDENTIALS=gap1name", 0, &h);
    t_note("CreateProtectionDescriptor(WEBCREDENTIALS) -> 0x%08lx", (unsigned long)st);
    if (st == 0 && h) UN(NCryptCloseProtectionDescriptor)(h);
}

TEST(gap1_cpd_invalid_rules) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    for (size_t i = 0; i < sizeof k_bad_rules / sizeof *k_bad_rules; i++) {
        void *h = SENT_P;
        DWORD st = UN(NCryptCreateProtectionDescriptor)(k_bad_rules[i], 0, &h);
        CHECKF(st != 0, "'%ls' accepted", k_bad_rules[i]);
        CHECKF(h == NULL, "'%ls' left a handle", k_bad_rules[i]);
        t_note("CreateProtectionDescriptor('%ls') -> 0x%08lx", k_bad_rules[i], (unsigned long)st);
    }
}

TEST(gap1_cpd_named_unknown_name) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    WCHAR name[64]; wsprintfW(name, L"gap1_unregistered_%lu", (unsigned long)GetCurrentProcessId());
    void *h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(name, 1 /* NCRYPT_NAMED_DESCRIPTOR_FLAG */, &h), G_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
    h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(name, 1 | NCRYPT_MACHINE_KEY_FLAG, &h), G_HR_FILE_NOT_FOUND);
    CHECK(h == NULL);
}

TEST(gap1_cpd_named_flag_still_validates_other_flag_bits) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor));
    void *h = SENT_P;
    G_EQ(UN(NCryptCreateProtectionDescriptor)(L"gap1_unregistered", 1 | 2, &h), G_NTE_BAD_FLAGS);
    CHECK(h == NULL);
}

TEST(gap1_cpd_borderline_rules_recorded) {
    REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    for (size_t i = 0; i < sizeof k_odd_rules / sizeof *k_odd_rules; i++) {
        void *h = SENT_P;
        DWORD st = UN(NCryptCreateProtectionDescriptor)(k_odd_rules[i], 0, &h);
        t_note("CreateProtectionDescriptor('%ls') -> 0x%08lx", k_odd_rules[i], (unsigned long)st);
        if (st == 0 && h && h != SENT_P) UN(NCryptCloseProtectionDescriptor)(h);
        else CHECK(h == NULL);
    }
}

/* ---- NCryptQueryProtectionDescriptorName ------------------------------------------------------------ */
TEST(gap1_qpdn_null_or_empty_name) {
    REQUIRE(UN(NCryptQueryProtectionDescriptorName));
    SIZE_T cch = 5; WCHAR buf[16];
    G_EQ(UN(NCryptQueryProtectionDescriptorName)(NULL, buf, &cch, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(cch, 0);                                        /* the length is cleared on entry */
    cch = 5;
    G_EQ(UN(NCryptQueryProtectionDescriptorName)(L"", buf, &cch, 0), G_NTE_INVALID_PARAM);
    EXPECT_EQ(cch, 0);
    cch = 5;
    G_EQ(UN(NCryptQueryProtectionDescriptorName)(NULL, NULL, &cch, 0xFFFFFFFF), G_NTE_INVALID_PARAM);   /* name before flags */
}

TEST(gap1_qpdn_bad_flags) {
    REQUIRE(UN(NCryptQueryProtectionDescriptorName));
    /* only NCRYPT_MACHINE_KEY_FLAG (0x20) is accepted */
    static const DWORD fl[] = { 1, 2, 4, 0x10, 0x40, 0x80, 0x100, 0x80000000, 0xFFFFFFDF, 0xFFFFFFFF, 0x21 };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        SIZE_T cch = 5; WCHAR buf[16];
        DWORD st = UN(NCryptQueryProtectionDescriptorName)(L"gap1_unregistered", buf, &cch, fl[i]);
        CHECKF(st == G_NTE_BAD_FLAGS, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        EXPECT_EQ(cch, 0);
    }
}

TEST(gap1_qpdn_unregistered_name) {
    REQUIRE(UN(NCryptQueryProtectionDescriptorName));
    WCHAR name[64]; wsprintfW(name, L"gap1_unregistered_q_%lu", (unsigned long)GetCurrentProcessId());
    static const DWORD fl[] = { 0, NCRYPT_MACHINE_KEY_FLAG };
    for (size_t i = 0; i < 2; i++) {
        SIZE_T cch = 5; WCHAR buf[16] = { 7 };
        DWORD st = UN(NCryptQueryProtectionDescriptorName)(name, buf, &cch, fl[i]);
        CHECKF(st == G_HR_FILE_NOT_FOUND, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        EXPECT_EQ(cch, 0);
        st = UN(NCryptQueryProtectionDescriptorName)(name, NULL, &cch, fl[i]);
        CHECKF(st == G_HR_FILE_NOT_FOUND, "size query flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
    }
}

/* ---- NCryptGetProtectionDescriptorInfo / NCryptCloseProtectionDescriptor ----------------------------- */
TEST(gap1_gpdi_null_out_checked_first) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo));
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)(NULL, NULL, 1, NULL), G_NTE_INVALID_PARAM);
    void *h = NULL;
    REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &h) != 0) { t_skip("descriptor unavailable"); return; }
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, NULL), G_NTE_INVALID_PARAM);
    UN(NCryptCloseProtectionDescriptor)(h);
}

TEST(gap1_gpdi_invalid_handle) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo));
    void *info = SENT_P;
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)(NULL, NULL, 1, &info), G_NTE_INVALID_HANDLE);
    CHECK(info == SENT_P);                                     /* untouched when the handle is rejected */
}

TEST(gap1_gpdi_wrong_object_type) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo));
    NEED_KSP(p);
    void *info = SENT_P;
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)((void *)p, NULL, 1, &info), G_NTE_INVALID_HANDLE);
    CHECK(info == SENT_P);
    g_free(p);
}

TEST(gap1_gpdi_bad_info_type) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo)); REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *h = NULL;
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &h) != 0) { t_skip("descriptor unavailable"); return; }
    static const DWORD types[] = { 0, 2, 3, 0x10, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        void *info = SENT_P;
        DWORD st = UN(NCryptGetProtectionDescriptorInfo)(h, NULL, types[i], &info);
        CHECKF(st == G_NTE_NOT_SUPPORTED, "type 0x%lx st=0x%08lx", (unsigned long)types[i], (unsigned long)st);
        CHECK(info == NULL);                                   /* cleared once the handle has been accepted */
    }
    UN(NCryptCloseProtectionDescriptor)(h);
}

TEST(gap1_gpdi_descriptor_string) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo)); REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    static const struct { const WCHAR *rule, *must; } t[] = { { L"LOCAL=user", L"LOCAL" }, { L"LOCAL=machine", L"LOCAL" }, { L"SID=S-1-1-0", L"S-1-1-0" } };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        void *h = NULL, *info = NULL;
        if (UN(NCryptCreateProtectionDescriptor)(t[i].rule, 0, &h) != 0) { t_note("%ls unavailable", t[i].rule); continue; }
        DWORD st = UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1 /* NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING */, &info);
        CHECKF(st == 0, "%ls st=0x%08lx", t[i].rule, (unsigned long)st);
        if (st == 0 && info) {
            const WCHAR *s = (const WCHAR *)info;
            CHECK(s[0] != 0);
            CHECKF(wcsstr(s, t[i].must) != NULL, "'%ls' lacks '%ls'", s, t[i].must);
            t_note("descriptor string for '%ls' = '%ls'", t[i].rule, s);
            CHECK(LocalFree(info) == NULL);                    /* default allocator is LocalAlloc */
        }
        UN(NCryptCloseProtectionDescriptor)(h);
    }
}

TEST(gap1_gpdi_repeatable) {
    REQUIRE(UN(NCryptGetProtectionDescriptorInfo)); REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *h = NULL;
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &h) != 0) { t_skip("descriptor unavailable"); return; }
    void *a = NULL, *b = NULL;
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &a), 0);
    G_EQ(UN(NCryptGetProtectionDescriptorInfo)(h, NULL, 1, &b), 0);
    CHECK(a != NULL && b != NULL && a != b);                   /* each call returns a fresh allocation */
    if (a && b) CHECK(!lstrcmpW((WCHAR *)a, (WCHAR *)b));
    if (a) LocalFree(a);
    if (b) LocalFree(b);
    UN(NCryptCloseProtectionDescriptor)(h);
}

TEST(gap1_cpd_close_invalid) {
    REQUIRE(UN(NCryptCloseProtectionDescriptor));
    G_EQ(UN(NCryptCloseProtectionDescriptor)(NULL), G_NTE_INVALID_HANDLE);
}

TEST(gap1_cpd_close_wrong_object_type) {
    REQUIRE(UN(NCryptCloseProtectionDescriptor));
    NEED_KSP(p);
    G_EQ(UN(NCryptCloseProtectionDescriptor)((void *)p), G_NTE_INVALID_HANDLE);
    DWORD cb = 0;
    G_EQ(U(NCryptGetProperty)(p, NCRYPT_NAME_PROPERTY, NULL, 0, &cb, 0), 0);    /* the provider handle was not released */
    g_free(p);
}

/* ---- NCryptProtectSecret ------------------------------------------------------------------------------ */
static DWORD protect(void *h, DWORD fl, const BYTE *d, ULONG cb, BYTE **out, ULONG *outcb) {
    return UN(NCryptProtectSecret)(h, fl, d, cb, NULL, NULL, out, outcb);
}

TEST(gap1_ps_outputs_cleared_on_failure) {
    REQUIRE(UN(NCryptProtectSecret));
    BYTE d[4] = { 1, 2, 3, 4 };
    BYTE *blob = (BYTE *)(ULONG_PTR)0x1234; ULONG cb = 99;
    DWORD st = protect(NULL, 0, d, sizeof d, &blob, &cb);
    G_EQ(st, G_NTE_INVALID_HANDLE);
    CHECK(blob == NULL);
    EXPECT_EQ(cb, 0);
}

TEST(gap1_ps_null_or_empty_data) {
    REQUIRE(UN(NCryptProtectSecret));
    BYTE d[4] = { 1, 2, 3, 4 };
    BYTE *blob = (BYTE *)(ULONG_PTR)0x1234; ULONG cb = 99;
    G_EQ(protect(NULL, 0, NULL, 4, &blob, &cb), G_NTE_INVALID_PARAM);       /* data is checked before the handle */
    CHECK(blob == NULL); EXPECT_EQ(cb, 0);
    blob = (BYTE *)(ULONG_PTR)0x1234; cb = 99;
    G_EQ(protect(NULL, 0, d, 0, &blob, &cb), G_NTE_INVALID_PARAM);
    CHECK(blob == NULL); EXPECT_EQ(cb, 0);
    G_EQ(protect(NULL, 0xFFFFFFFF, NULL, 0, &blob, &cb), G_NTE_INVALID_PARAM);   /* ... and before the flags */
}

TEST(gap1_ps_bad_flags_precede_handle_check) {
    REQUIRE(UN(NCryptProtectSecret));
    /* only NCRYPT_SILENT_FLAG (0x40) is accepted */
    static const DWORD fl[] = { 1, 2, 4, 8, 0x10, 0x20, 0x80, 0x100, 0x80000000, 0xFFFFFFBF, 0xFFFFFFFF, 0x41 };
    BYTE d[4] = { 1, 2, 3, 4 };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        BYTE *blob = (BYTE *)(ULONG_PTR)0x1234; ULONG cb = 99;
        DWORD st = protect(NULL, fl[i], d, sizeof d, &blob, &cb);
        CHECKF(st == G_NTE_BAD_FLAGS, "flags 0x%lx st=0x%08lx", (unsigned long)fl[i], (unsigned long)st);
        CHECK(blob == NULL); EXPECT_EQ(cb, 0);
    }
}

TEST(gap1_ps_silent_flag_reaches_handle_check) {
    REQUIRE(UN(NCryptProtectSecret));
    BYTE d[4] = { 1, 2, 3, 4 }; BYTE *blob = NULL; ULONG cb = 0;
    G_EQ(protect(NULL, NCRYPT_SILENT_FLAG, d, sizeof d, &blob, &cb), G_NTE_INVALID_HANDLE);
}

TEST(gap1_ps_wrong_object_type) {
    REQUIRE(UN(NCryptProtectSecret));
    NEED_KSP(p);
    BYTE d[4] = { 1, 2, 3, 4 }; BYTE *blob = NULL; ULONG cb = 0;
    G_EQ(protect((void *)p, NCRYPT_SILENT_FLAG, d, sizeof d, &blob, &cb), G_NTE_INVALID_HANDLE);
    g_free(p);
}

TEST(gap1_ps_local_user_protects_silently) {
    REQUIRE(UN(NCryptProtectSecret)); REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *h = NULL;
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &h) != 0) { t_skip("descriptor unavailable"); return; }
    BYTE secret[32]; for (int i = 0; i < 32; i++) secret[i] = (BYTE)(i * 7 + 3);
    BYTE *b1 = NULL, *b2 = NULL; ULONG c1 = 0, c2 = 0;
    DWORD s1 = protect(h, NCRYPT_SILENT_FLAG, secret, sizeof secret, &b1, &c1);
    t_note("ProtectSecret(LOCAL=user, silent) -> 0x%08lx, blob %lu bytes", (unsigned long)s1, (unsigned long)c1);
    if (s1 == 0) {
        CHECK(b1 != NULL);
        CHECK(c1 > sizeof secret);
        DWORD s2 = protect(h, NCRYPT_SILENT_FLAG, secret, sizeof secret, &b2, &c2);
        if (s2 == 0 && b1 && b2) CHECK(c1 != c2 || memcmp(b1, b2, c1) != 0);     /* protection is randomized */
        if (b2) LocalFree(b2);
    } else {
        CHECK(b1 == NULL); EXPECT_EQ(c1, 0);
    }
    if (b1) LocalFree(b1);
    UN(NCryptCloseProtectionDescriptor)(h);
}
