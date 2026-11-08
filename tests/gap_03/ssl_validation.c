/* SSL protocol provider exports of ncrypt.dll: argument validation that happens before any provider code runs.
 * Only calls whose rejection is visible in the Windows 10 implementation ahead of provider dispatch are made. */
#include "gap3.h"

static const char *const EXPORTS[] = {
    "SslImportKey", "SslImportMasterKey", "SslIncrementProviderReferenceCount", "SslLookupCipherLengths",
    "SslLookupCipherSuiteInfo", "SslOpenPrivateKey", "SslOpenProvider", "SslSignHash", "SslVerifySignature",
};
static const unsigned ORDS[] = { 141, 142, 143, 144, 145, 146, 147, 148, 149 };

/* ---- exports resolve, are not forwarders, no W/A variants ---------------------------------------- */
TEST(gap3_exports_resolve_in_ncrypt) {
    HMODULE m = t_module("ncrypt.dll");
    if (!m) { t_skip("ncrypt.dll missing"); return; }
    for (int i = 0; i < 9; i++) {
        FARPROC p = GetProcAddress(m, EXPORTS[i]);
        CHECKF(p != NULL, "%s", EXPORTS[i]);
        if (!p) continue;
        FARPROC q = t_proc_in("ncrypt.dll", EXPORTS[i]);
        CHECK(p == q);
        /* A real function body inside ncrypt itself (not a forwarder into another module). */
        HMODULE owner = NULL;
        BOOL ok = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner);
        CHECK(ok); CHECK(owner == m);
    }
}
TEST(gap3_exports_by_ordinal) {
    if (t_is_wine()) { t_skip("ordinals differ under wine"); return; }
    HMODULE m = t_module("ncrypt.dll");
    if (!m) { t_skip("ncrypt.dll missing"); return; }
    for (int i = 0; i < 9; i++) {
        FARPROC byname = GetProcAddress(m, EXPORTS[i]);
        FARPROC byord = GetProcAddress(m, (LPCSTR)(ULONG_PTR)ORDS[i]);
        CHECKF(byname != NULL && byname == byord, "%s ord %u", EXPORTS[i], ORDS[i]);
    }
}
TEST(gap3_exports_have_no_ansi_wide_variants) {
    HMODULE m = t_module("ncrypt.dll");
    if (!m) { t_skip("ncrypt.dll missing"); return; }
    for (int i = 0; i < 9; i++) {
        char nm[80];
        const char *sfx[] = { "A", "W", "Ex" };
        for (int s = 0; s < 3; s++) {
            snprintf(nm, sizeof nm, "%s%s", EXPORTS[i], sfx[s]);
            SET_ERR(0);
            FARPROC p = GetProcAddress(m, nm);
            CHECKF(p == NULL, "%s", nm);
            if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
        }
    }
}
TEST(gap3_exports_name_is_case_sensitive) {
    HMODULE m = t_module("ncrypt.dll");
    if (!m) { t_skip("ncrypt.dll missing"); return; }
    for (int i = 0; i < 9; i++) {
        char nm[80]; snprintf(nm, sizeof nm, "%s", EXPORTS[i]);
        nm[3] = (char)(nm[3] | 0x20);   /* "Ssl" + lower-cased 4th char */
        if (!strcmp(nm, EXPORTS[i])) continue;
        SET_ERR(0);
        CHECKF(GetProcAddress(m, nm) == NULL, "%s", nm);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

/* ---- SslOpenProvider: failures that precede any provider resolution ------------------------------ */
TEST(gap3_open_null_out_rejected) {
    SslOpenProvider_pfn f = UN(SslOpenProvider); NEED(f);
    EXPECT_EQ((DWORD)f(NULL, NULL, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f(NULL, L"Microsoft SSL Protocol Provider", 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f(NULL, L"no such provider", 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f(NULL, L"", 0), (DWORD)NTE_INVALID_PARAMETER_);
}
TEST(gap3_open_nonzero_flags_rejected) {
    SslOpenProvider_pfn f = UN(SslOpenProvider); NEED(f);
    for (unsigned i = 1; i < N_ODD_FLAGS; i++) {
        PROVH h = (PROVH)(ULONG_PTR)0x1234;
        LONG r = f(&h, NULL, odd_flags[i]);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_PARAMETER_, "flags 0x%lx got 0x%lx", (unsigned long)odd_flags[i], (unsigned long)r);
        CHECKF(h == (PROVH)(ULONG_PTR)0x1234, "out handle untouched on failure, flags 0x%lx", (unsigned long)odd_flags[i]);
    }
}
TEST(gap3_open_nonzero_flags_checked_before_name) {
    SslOpenProvider_pfn f = UN(SslOpenProvider); NEED(f);
    const WCHAR *names[] = { L"Microsoft SSL Protocol Provider", L"no such provider", L"" };
    for (int n = 0; n < 3; n++) for (unsigned i = 1; i < N_ODD_FLAGS; i++) {
        PROVH h = (PROVH)(ULONG_PTR)0x77;
        LONG r = f(&h, names[n], odd_flags[i]);
        CHECK((DWORD)r == (DWORD)NTE_INVALID_PARAMETER_);
        CHECK(h == (PROVH)(ULONG_PTR)0x77);
    }
}
TEST(gap3_open_null_out_checked_before_flags) {
    SslOpenProvider_pfn f = UN(SslOpenProvider); NEED(f);
    for (unsigned i = 0; i < N_ODD_FLAGS; i++)
        EXPECT_EQ((DWORD)f(NULL, NULL, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
}
TEST(gap3_open_failure_does_not_set_last_error_contract) {
    /* The status is the return value; GetLastError is not part of the contract. Record it only. */
    SslOpenProvider_pfn f = UN(SslOpenProvider); NEED(f);
    PROVH h = NULL; SET_ERR(0xABCD);
    LONG r = f(&h, NULL, 1);
    CHECK((DWORD)r == (DWORD)NTE_INVALID_PARAMETER_);
    t_note("SslOpenProvider bad flags: GetLastError afterwards = %lu", GetLastError());
}

/* ---- SslIncrementProviderReferenceCount ---------------------------------------------------------- */
TEST(gap3_incref_null_handle) {
    SslIncrementProviderReferenceCount_pfn f = UN(SslIncrementProviderReferenceCount); NEED(f);
    LONG r = f(NULL);
    CHECKF((DWORD)r == (DWORD)STATUS_INVALID_HANDLE_, "got 0x%lx", (unsigned long)r);
    t_note("documentation lists NTE_INVALID_HANDLE; the raw NTSTATUS 0xC0000008 is what the function returns (not normalised)");
}
TEST(gap3_incref_bad_headers) {
    SslIncrementProviderReferenceCount_pfn f = UN(SslIncrementProviderReferenceCount); NEED(f);
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        LONG r = f((PROVH)&p);
        CHECKF((DWORD)r == (DWORD)STATUS_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        CHECKF(p.w[4] == 7, "%s: reference count must not change on failure", bad_prov[i].what);
    }
}
TEST(gap3_incref_key_object_is_not_a_provider) {
    SslIncrementProviderReferenceCount_pfn f = UN(SslIncrementProviderReferenceCount); NEED(f);
    FAKE_PROV k; fake_prov(&k, SSLKEY_SIZE, SSLKEY_MAGIC, 0);
    EXPECT_EQ((DWORD)f((PROVH)&k), (DWORD)STATUS_INVALID_HANDLE_);
    CHECK(k.w[4] == 7);
}
TEST(gap3_incref_accepts_minimal_valid_header) {
    /* Validation is purely structural: size >= 0x178, magic 0x44444441, closed flag 0. Only the counter is touched. */
    SslIncrementProviderReferenceCount_pfn f = UN(SslIncrementProviderReferenceCount); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    EXPECT_EQ((DWORD)f((PROVH)&p), 0);
    CHECK(p.w[4] == 8);
    EXPECT_EQ((DWORD)f((PROVH)&p), 0);
    CHECK(p.w[4] == 9);
    fake_prov(&p, 0x180, SSLPROV_MAGIC, 0);   /* larger size is fine */
    EXPECT_EQ((DWORD)f((PROVH)&p), 0);
    CHECK(p.w[4] == 8);
    fake_prov(&p, 0xFFFFFFFFu, SSLPROV_MAGIC, 0);
    EXPECT_EQ((DWORD)f((PROVH)&p), 0);
    CHECK(p.w[4] == 8);
}

/* ---- SslLookupCipherLengths ------------------------------------------------------------------------ */
TEST(gap3_lookup_lengths_null_provider) {
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths); NEED(f);
    BYTE out[64];
    EXPECT_EQ((DWORD)f(NULL, 0x0303, 0x2F, 1, out, 0x14, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, 0, 0, 0, NULL, 0, 0), (DWORD)NTE_INVALID_HANDLE_);
}
TEST(gap3_lookup_lengths_bad_provider_headers) {
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths); NEED(f);
    BYTE out[64];
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        LONG r = f((PROVH)&p, 0x0303, 0x2F, 1, out, 0x14, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
}
TEST(gap3_lookup_lengths_handle_checked_before_buffer) {
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths); NEED(f);
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        LONG r = f((PROVH)&p, 0, 0, 0, NULL, 0, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
}
TEST(gap3_lookup_lengths_bad_buffer_with_valid_header) {
    /* A header-valid provider reaches the buffer checks, which happen before the interface-version check and
     * before any provider call: NULL buffer or cbCipherLengths < 0x14 gives NTE_INVALID_PARAMETER. */
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);   /* interface version word = 0 (< 2) */
    BYTE out[64]; memset(out, 0xCC, sizeof out);
    EXPECT_EQ((DWORD)f((PROVH)&p, 0x0303, 0x2F, 1, NULL, 0x14, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f((PROVH)&p, 0x0303, 0x2F, 1, NULL, 0, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f((PROVH)&p, 0x0303, 0x2F, 1, NULL, 0xFFFFFFFFu, 0), (DWORD)NTE_INVALID_PARAMETER_);
    static const DWORD small[] = { 0, 1, 4, 8, 0x10, 0x13 };
    for (unsigned i = 0; i < sizeof small / sizeof small[0]; i++) {
        LONG r = f((PROVH)&p, 0x0303, 0x2F, 1, out, small[i], 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_PARAMETER_, "cb=%lu got 0x%lx", (unsigned long)small[i], (unsigned long)r);
    }
    for (unsigned i = 0; i < sizeof out; i++) if (out[i] != 0xCC) { CHECKF(0, "output buffer modified at %u", i); break; }
}
TEST(gap3_lookup_lengths_old_interface_version_rejected) {
    /* With cb >= 0x14 and a non-NULL buffer the 16-bit interface version at provider+0x20 must be >= 2,
     * otherwise NTE_NOT_SUPPORTED. The provider function is never called. */
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths); NEED(f);
    FAKE_PROV p; BYTE out[64];
    for (ULONG ver = 0; ver < 2; ver++) {
        fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0); p.w[8] = ver;
        LONG r = f((PROVH)&p, 0x0303, 0x2F, 1, out, 0x14, 0);
        CHECKF((DWORD)r == 0x80090029u, "version %lu got 0x%lx", (unsigned long)ver, (unsigned long)r);
        r = f((PROVH)&p, 0, 0, 0, out, sizeof out, 0xFFFFFFFFu);
        CHECKF((DWORD)r == 0x80090029u, "version %lu large cb got 0x%lx", (unsigned long)ver, (unsigned long)r);
    }
    /* only the low 16 bits count */
    fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0); p.w[8] = 0x00010000u;
    EXPECT_EQ((DWORD)f((PROVH)&p, 0x0303, 0x2F, 1, out, 0x14, 0), 0x80090029u);
}

/* ---- SslLookupCipherSuiteInfo --------------------------------------------------------------------- */
TEST(gap3_lookup_suite_null_provider) {
    SslLookupCipherSuiteInfo_pfn f = UN(SslLookupCipherSuiteInfo); NEED(f);
    BYTE out[512];
    EXPECT_EQ((DWORD)f(NULL, 0x0303, 0x2F, 1, out, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, 0, 0, 0, NULL, 0), (DWORD)NTE_INVALID_HANDLE_);
}
TEST(gap3_lookup_suite_bad_provider_headers) {
    SslLookupCipherSuiteInfo_pfn f = UN(SslLookupCipherSuiteInfo); NEED(f);
    BYTE out[512]; memset(out, 0xCC, sizeof out);
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        LONG r = f((PROVH)&p, 0x0303, 0x2F, 1, out, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        r = f((PROVH)&p, 0, 0, 0, NULL, 0xFFFFFFFFu);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s (NULL out) got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
    for (unsigned i = 0; i < sizeof out; i++) if (out[i] != 0xCC) { CHECKF(0, "output modified at %u", i); break; }
}

/* ---- SslImportKey -------------------------------------------------------------------------------- */
TEST(gap3_importkey_null_provider) {
    SslImportKey_pfn f = UN(SslImportKey); NEED(f);
    KEYH k = (KEYH)(ULONG_PTR)0x55; BYTE blob[16] = {0};
    EXPECT_EQ((DWORD)f(NULL, &k, L"OpaqueKeyBlob", blob, sizeof blob, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(k == (KEYH)(ULONG_PTR)0x55);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL, NULL, 0, 0), (DWORD)NTE_INVALID_HANDLE_);
}
TEST(gap3_importkey_bad_provider_headers) {
    SslImportKey_pfn f = UN(SslImportKey); NEED(f);
    BYTE blob[16] = {0};
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        KEYH k = (KEYH)(ULONG_PTR)0x55;
        LONG r = f((PROVH)&p, &k, L"OpaqueKeyBlob", blob, sizeof blob, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        CHECK(k == (KEYH)(ULONG_PTR)0x55);
        /* the provider handle is checked before the NULL output pointer */
        r = f((PROVH)&p, NULL, L"OpaqueKeyBlob", blob, sizeof blob, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s NULL phKey got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
}
TEST(gap3_importkey_null_phkey_with_valid_header) {
    SslImportKey_pfn f = UN(SslImportKey); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE blob[16] = {0};
    for (unsigned i = 0; i < N_ODD_FLAGS; i++) {
        EXPECT_EQ((DWORD)f((PROVH)&p, NULL, L"OpaqueKeyBlob", blob, sizeof blob, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
        EXPECT_EQ((DWORD)f((PROVH)&p, NULL, NULL, NULL, 0, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
    }
    CHECK(p.w[4] == 7);   /* no reference taken */
}

/* ---- SslImportMasterKey --------------------------------------------------------------------------- */
TEST(gap3_importmaster_null_handles) {
    SslImportMasterKey_pfn f = UN(SslImportMasterKey); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    KEYH out = (KEYH)(ULONG_PTR)0x66; BYTE enc[16] = {0};
    EXPECT_EQ((DWORD)f(NULL, (KEYH)&k, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f((PROVH)&p, NULL, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, NULL, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL, 0, 0, NULL, NULL, 0, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(out == (KEYH)(ULONG_PTR)0x66);
}
TEST(gap3_importmaster_bad_provider_headers) {
    SslImportMasterKey_pfn f = UN(SslImportMasterKey); NEED(f);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE enc[16] = {0};
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        KEYH out = (KEYH)(ULONG_PTR)0x66;
        LONG r = f((PROVH)&p, (KEYH)&k, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        CHECK(out == (KEYH)(ULONG_PTR)0x66);
    }
}
TEST(gap3_importmaster_bad_key_headers) {
    SslImportMasterKey_pfn f = UN(SslImportMasterKey); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE enc[16] = {0};
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        KEYH out = (KEYH)(ULONG_PTR)0x66;
        LONG r = f((PROVH)&p, (KEYH)&k, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_key[i].what, (unsigned long)r);
        CHECK(out == (KEYH)(ULONG_PTR)0x66);
        /* handle validity takes precedence over the NULL output pointer */
        r = f((PROVH)&p, (KEYH)&k, NULL, 0x0303, 0x2F, NULL, enc, sizeof enc, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s NULL out got 0x%lx", bad_key[i].what, (unsigned long)r);
    }
    CHECK(p.w[4] == 7);
}
TEST(gap3_importmaster_null_output_with_valid_handles) {
    SslImportMasterKey_pfn f = UN(SslImportMasterKey); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE enc[16] = {0};
    EXPECT_EQ((DWORD)f((PROVH)&p, (KEYH)&k, NULL, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f((PROVH)&p, (KEYH)&k, NULL, 0, 0, NULL, NULL, 0, 0xFFFFFFFFu), (DWORD)NTE_INVALID_PARAMETER_);
    CHECK(p.w[4] == 7);
}

/* ---- SslOpenPrivateKey --------------------------------------------------------------------------- */
TEST(gap3_openprivkey_null_provider) {
    SslOpenPrivateKey_pfn f = UN(SslOpenPrivateKey); NEED(f);
    KEYH k = (KEYH)(ULONG_PTR)0x88; BYTE cert[16] = {0};
    EXPECT_EQ((DWORD)f(NULL, &k, cert, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(k == (KEYH)(ULONG_PTR)0x88);
}
TEST(gap3_openprivkey_bad_provider_headers) {
    SslOpenPrivateKey_pfn f = UN(SslOpenPrivateKey); NEED(f);
    BYTE cert[16] = {0};
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        KEYH k = (KEYH)(ULONG_PTR)0x88;
        LONG r = f((PROVH)&p, &k, cert, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        CHECK(k == (KEYH)(ULONG_PTR)0x88);
        r = f((PROVH)&p, NULL, NULL, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s NULL args got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
}
TEST(gap3_openprivkey_null_out_or_cert_with_valid_header) {
    SslOpenPrivateKey_pfn f = UN(SslOpenPrivateKey); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE cert[16] = {0};
    KEYH k = (KEYH)(ULONG_PTR)0x88;
    for (unsigned i = 0; i < N_ODD_FLAGS; i++) {
        EXPECT_EQ((DWORD)f((PROVH)&p, NULL, cert, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
        EXPECT_EQ((DWORD)f((PROVH)&p, &k, NULL, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
        EXPECT_EQ((DWORD)f((PROVH)&p, NULL, NULL, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
    }
    CHECK(k == (KEYH)(ULONG_PTR)0x88);
    CHECK(p.w[4] == 7);
}

/* ---- SslSignHash ----------------------------------------------------------------------------------- */
TEST(gap3_signhash_null_handles) {
    SslSignHash_pfn f = UN(SslSignHash); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE hash[32] = {0}, sig[256]; DWORD cb = 0x1234;
    EXPECT_EQ((DWORD)f(NULL, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f((PROVH)&p, NULL, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL, 0, NULL, 0, NULL, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(cb == 0x1234);
}
TEST(gap3_signhash_bad_provider_headers) {
    SslSignHash_pfn f = UN(SslSignHash); NEED(f);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE hash[32] = {0}, sig[256];
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        DWORD cb = 0x1234;
        LONG r = f((PROVH)&p, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, &cb, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
        CHECK(cb == 0x1234);
    }
}
TEST(gap3_signhash_bad_key_headers) {
    SslSignHash_pfn f = UN(SslSignHash); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE hash[32] = {0}, sig[256];
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        DWORD cb = 0x1234;
        LONG r = f((PROVH)&p, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, &cb, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_key[i].what, (unsigned long)r);
        CHECK(cb == 0x1234);
        for (unsigned fl = 0; fl < N_ODD_FLAGS; fl++)
            CHECK((DWORD)f((PROVH)&p, (KEYH)&k, NULL, 0, NULL, 0, NULL, odd_flags[fl]) == (DWORD)NTE_INVALID_HANDLE_);
    }
}
TEST(gap3_signhash_provider_object_is_not_a_key) {
    SslSignHash_pfn f = UN(SslSignHash); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    FAKE_PROV p2; fake_prov(&p2, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE hash[32] = {0}, sig[64]; DWORD cb = 5;
    EXPECT_EQ((DWORD)f((PROVH)&p, (KEYH)&p2, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    /* and a key object is not a provider */
    FAKE_PROV kk; fake_prov(&kk, SSLKEY_SIZE, SSLKEY_MAGIC, 0);
    EXPECT_EQ((DWORD)f((PROVH)&kk, (KEYH)&kk, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(cb == 5);
}

/* ---- SslVerifySignature ---------------------------------------------------------------------------- */
TEST(gap3_verify_null_handles) {
    SslVerifySignature_pfn f = UN(SslVerifySignature); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE hash[32] = {0}, sig[64] = {0};
    EXPECT_EQ((DWORD)f(NULL, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f((PROVH)&p, NULL, hash, sizeof hash, sig, sizeof sig, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(NULL, NULL, NULL, 0, NULL, 0, 0), (DWORD)NTE_INVALID_HANDLE_);
}
TEST(gap3_verify_bad_provider_headers) {
    SslVerifySignature_pfn f = UN(SslVerifySignature); NEED(f);
    FAKE_KEY k; fake_key(&k, SSLKEY_SIZE, SSLKEY_MAGIC);
    BYTE hash[32] = {0}, sig[64] = {0};
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        LONG r = f((PROVH)&p, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_prov[i].what, (unsigned long)r);
    }
}
TEST(gap3_verify_bad_key_headers) {
    SslVerifySignature_pfn f = UN(SslVerifySignature); NEED(f);
    FAKE_PROV p; fake_prov(&p, SSLPROV_SIZE, SSLPROV_MAGIC, 0);
    BYTE hash[32] = {0}, sig[64] = {0};
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        for (unsigned fl = 0; fl < N_ODD_FLAGS; fl++) {
            LONG r = f((PROVH)&p, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, odd_flags[fl]);
            CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s flags 0x%lx got 0x%lx", bad_key[i].what, (unsigned long)odd_flags[fl], (unsigned long)r);
        }
    }
}
TEST(gap3_verify_note_not_called_by_windows) {
    t_note("MS docs: SslVerifySignature is not currently called by Windows; wrapper still validates both handles before dispatch");
}
