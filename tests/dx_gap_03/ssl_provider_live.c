/* SSL protocol provider exports of ncrypt.dll with a real provider handle (dx: creates and releases provider objects).
 * Everything is released at the end of each test. No hardware, UI or persistent state is involved. */
#include "gap3.h"

static const WCHAR DEFAULT_NAME[] = L"Microsoft SSL Protocol Provider";

/* Open the default provider or skip the test. */
static PROVH open_or_skip(int *skipped) {
    SslOpenProvider_pfn op = UN(SslOpenProvider);
    *skipped = 0;
    if (!op) { t_skip("missing export: SslOpenProvider"); *skipped = 1; return NULL; }
    if (t_is_wine()) { t_skip("Ssl* exports are unimplemented stubs under wine"); *skipped = 1; return NULL; }
    PROVH h = NULL;
    LONG r = op(&h, NULL, 0);
    if (r != 0 || !h) { t_skip("default SSL provider not openable (0x%lx)", (unsigned long)r); *skipped = 1; return NULL; }
    return h;
}
#define OPEN_PROV(h) int sk_; PROVH h = open_or_skip(&sk_); if (sk_) return
static void release(PROVH h) { SslFreeObject_pfn fr = UN(SslFreeObject); if (fr && h) fr(h); }
static ULONG *W(void *h) { return (ULONG *)h; }

/* ---- open ------------------------------------------------------------------------------------------ */
TEST(dxgap3_open_default_provider) {
    OPEN_PROV(h);
    CHECK(W(h)[0] == SSLPROV_SIZE);
    CHECK(W(h)[1] == SSLPROV_MAGIC);
    CHECK(W(h)[3] == 0);
    CHECK(W(h)[4] == 1);
    t_note("provider interface word (+0x20) = 0x%lx", (unsigned long)W(h)[8]);
    release(h);
}
TEST(dxgap3_open_explicit_default_name) {
    SslOpenProvider_pfn op = UN(SslOpenProvider); NEED(op);
    PROVH h = NULL;
    EXPECT_EQ((DWORD)op(&h, DEFAULT_NAME, 0), 0);
    CHECK(h != NULL);
    if (h) { CHECK(W(h)[1] == SSLPROV_MAGIC); CHECK(W(h)[4] == 1); }
    release(h);
}
TEST(dxgap3_open_twice_gives_distinct_handles) {
    SslOpenProvider_pfn op = UN(SslOpenProvider); NEED(op);
    PROVH a = NULL, b = NULL;
    EXPECT_EQ((DWORD)op(&a, NULL, 0), 0);
    EXPECT_EQ((DWORD)op(&b, NULL, 0), 0);
    CHECK(a != NULL && b != NULL && a != b);
    if (a) CHECK(W(a)[4] == 1);
    if (b) CHECK(W(b)[4] == 1);
    release(a); release(b);
}
TEST(dxgap3_open_unknown_provider_fails_without_output) {
    SslOpenProvider_pfn op = UN(SslOpenProvider); NEED(op);
    static const WCHAR *const names[] = { L"No Such SSL Provider", L"x" };
    for (int i = 0; i < 2; i++) {
        PROVH h = (PROVH)(ULONG_PTR)0x4321;
        LONG r = op(&h, names[i], 0);
        CHECKF(r != 0, "unknown provider name unexpectedly opened");
        if (r != 0) CHECK(h == (PROVH)(ULONG_PTR)0x4321);
        else release(h);
        t_note("SslOpenProvider(unknown name) -> 0x%lx", (unsigned long)r);
    }
}
TEST(dxgap3_open_bad_flags_does_not_load_provider) {
    SslOpenProvider_pfn op = UN(SslOpenProvider); NEED(op);
    for (unsigned i = 1; i < N_ODD_FLAGS; i++) {
        PROVH h = (PROVH)(ULONG_PTR)0x4321;
        EXPECT_EQ((DWORD)op(&h, NULL, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
        CHECK(h == (PROVH)(ULONG_PTR)0x4321);
    }
}

/* ---- reference counting and handle lifetime --------------------------------------------------------- */
TEST(dxgap3_refcount_increment_decrement) {
    OPEN_PROV(h);
    SslIncrementProviderReferenceCount_pfn inc = UN(SslIncrementProviderReferenceCount);
    SslDecrementProviderReferenceCount_pfn dec = UN(SslDecrementProviderReferenceCount);
    if (!inc || !dec) { release(h); t_skip("missing export"); return; }
    EXPECT_EQ((DWORD)inc(h), 0);   CHECK(W(h)[4] == 2);
    EXPECT_EQ((DWORD)inc(h), 0);   CHECK(W(h)[4] == 3);
    EXPECT_EQ((DWORD)dec(h), 0);   CHECK(W(h)[4] == 2);
    EXPECT_EQ((DWORD)dec(h), 0);   CHECK(W(h)[4] == 1);
    CHECK(W(h)[3] == 0);   /* still open */
    EXPECT_EQ((DWORD)inc(h), 0);   CHECK(W(h)[4] == 2);
    EXPECT_EQ((DWORD)dec(h), 0);
    release(h);
}
TEST(dxgap3_refcount_many_increments) {
    OPEN_PROV(h);
    SslIncrementProviderReferenceCount_pfn inc = UN(SslIncrementProviderReferenceCount);
    SslDecrementProviderReferenceCount_pfn dec = UN(SslDecrementProviderReferenceCount);
    if (!inc || !dec) { release(h); t_skip("missing export"); return; }
    for (int i = 0; i < 1000; i++) EXPECT_EQ((DWORD)inc(h), 0);
    CHECK(W(h)[4] == 1001);
    for (int i = 0; i < 1000; i++) EXPECT_EQ((DWORD)dec(h), 0);
    CHECK(W(h)[4] == 1);
    release(h);
}
TEST(dxgap3_free_with_outstanding_reference_invalidates_handle) {
    /* SslFreeObject marks the provider closed (+0xC = 1) and drops one reference. With a reference still held the
     * memory stays valid, but every export that validates the provider now rejects it. The last
     * SslDecrementProviderReferenceCount frees it. */
    OPEN_PROV(h);
    SslIncrementProviderReferenceCount_pfn inc = UN(SslIncrementProviderReferenceCount);
    SslDecrementProviderReferenceCount_pfn dec = UN(SslDecrementProviderReferenceCount);
    SslFreeObject_pfn fr = UN(SslFreeObject);
    SslLookupCipherSuiteInfo_pfn ls = UN(SslLookupCipherSuiteInfo);
    SslLookupCipherLengths_pfn ll = UN(SslLookupCipherLengths);
    SslOpenPrivateKey_pfn opk = UN(SslOpenPrivateKey);
    SslImportKey_pfn ik = UN(SslImportKey);
    if (!inc || !dec || !fr || !ls || !ll || !opk || !ik) { release(h); t_skip("missing export"); return; }
    EXPECT_EQ((DWORD)inc(h), 0);
    CHECK(W(h)[4] == 2);
    EXPECT_EQ((DWORD)fr(h), 0);
    CHECK(W(h)[3] == 1);
    CHECK(W(h)[4] == 1);
    BYTE buf[512]; KEYH k = (KEYH)(ULONG_PTR)9; BYTE cert[16] = {0};
    EXPECT_EQ((DWORD)inc(h), (DWORD)STATUS_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)ls(h, 0x0303, 0x2F, 1, buf, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)ll(h, 0x0303, 0x2F, 1, buf, 0x14, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)opk(h, &k, cert, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)ik(h, &k, L"x", cert, 16, 0), (DWORD)NTE_INVALID_HANDLE_);
    CHECK(k == (KEYH)(ULONG_PTR)9);
    CHECK(W(h)[4] == 1);
    EXPECT_EQ((DWORD)dec(h), 0);   /* last reference: memory released, h must not be used again */
}
TEST(dxgap3_free_provider_returns_success) {
    OPEN_PROV(h);
    SslFreeObject_pfn fr = UN(SslFreeObject);
    if (!fr) { t_skip("missing export"); return; }
    EXPECT_EQ((DWORD)fr(h), 0);
}
TEST(dxgap3_decrement_rejects_non_provider_headers) {
    SslDecrementProviderReferenceCount_pfn dec = UN(SslDecrementProviderReferenceCount); NEED(dec);
    for (unsigned i = 0; i < N_BAD_PROV; i++) {
        if (bad_prov[i].size >= SSLPROV_SIZE && bad_prov[i].magic == SSLPROV_MAGIC) continue;  /* closed flag is not checked here */
        FAKE_PROV p; fake_prov(&p, bad_prov[i].size, bad_prov[i].magic, bad_prov[i].closed);
        EXPECT_EQ((DWORD)dec((PROVH)&p), (DWORD)STATUS_INVALID_HANDLE_);
        CHECK(p.w[4] == 7);
    }
}

/* ---- validation with a real provider handle ----------------------------------------------------------- */
TEST(dxgap3_importkey_null_output_with_real_provider) {
    OPEN_PROV(h);
    SslImportKey_pfn f = UN(SslImportKey);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE blob[16] = {0};
    EXPECT_EQ((DWORD)f(h, NULL, L"OpaqueKeyBlob", blob, sizeof blob, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f(h, NULL, NULL, NULL, 0, 0), (DWORD)NTE_INVALID_PARAMETER_);
    CHECK(W(h)[4] == 1);
    release(h);
}
TEST(dxgap3_importmaster_handle_and_output_checks_with_real_provider) {
    OPEN_PROV(h);
    SslImportMasterKey_pfn f = UN(SslImportMasterKey);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE enc[16] = {0};
    FAKE_KEY good; fake_key(&good, SSLKEY_SIZE, SSLKEY_MAGIC);
    KEYH out = (KEYH)(ULONG_PTR)0x66;
    EXPECT_EQ((DWORD)f(h, NULL, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(h, (KEYH)h, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_HANDLE_);  /* provider object as key */
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        LONG r = f(h, (KEYH)&k, &out, 0x0303, 0x2F, NULL, enc, sizeof enc, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_key[i].what, (unsigned long)r);
    }
    CHECK(out == (KEYH)(ULONG_PTR)0x66);
    EXPECT_EQ((DWORD)f(h, (KEYH)&good, NULL, 0x0303, 0x2F, NULL, enc, sizeof enc, 0), (DWORD)NTE_INVALID_PARAMETER_);
    CHECK(W(h)[4] == 1);
    release(h);
}
TEST(dxgap3_openprivkey_argument_checks_with_real_provider) {
    OPEN_PROV(h);
    SslOpenPrivateKey_pfn f = UN(SslOpenPrivateKey);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE cert[16] = {0}; KEYH k = (KEYH)(ULONG_PTR)0x88;
    for (unsigned i = 0; i < N_ODD_FLAGS; i++) {
        EXPECT_EQ((DWORD)f(h, NULL, cert, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
        EXPECT_EQ((DWORD)f(h, &k, NULL, odd_flags[i]), (DWORD)NTE_INVALID_PARAMETER_);
    }
    CHECK(k == (KEYH)(ULONG_PTR)0x88);
    CHECK(W(h)[4] == 1);
    release(h);
}
TEST(dxgap3_signhash_key_checks_with_real_provider) {
    OPEN_PROV(h);
    SslSignHash_pfn f = UN(SslSignHash);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE hash[32] = {0}, sig[256]; DWORD cb = 0x1234;
    EXPECT_EQ((DWORD)f(h, NULL, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(h, (KEYH)h, hash, sizeof hash, sig, sizeof sig, &cb, 0), (DWORD)NTE_INVALID_HANDLE_);
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        LONG r = f(h, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, &cb, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_key[i].what, (unsigned long)r);
    }
    CHECK(cb == 0x1234);
    release(h);
}
TEST(dxgap3_verify_key_checks_with_real_provider) {
    OPEN_PROV(h);
    SslVerifySignature_pfn f = UN(SslVerifySignature);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE hash[32] = {0}, sig[64] = {0};
    EXPECT_EQ((DWORD)f(h, NULL, hash, sizeof hash, sig, sizeof sig, 0), (DWORD)NTE_INVALID_HANDLE_);
    EXPECT_EQ((DWORD)f(h, (KEYH)h, hash, sizeof hash, sig, sizeof sig, 0), (DWORD)NTE_INVALID_HANDLE_);
    for (unsigned i = 0; i < N_BAD_KEY; i++) {
        FAKE_KEY k; fake_key(&k, bad_key[i].size, bad_key[i].magic);
        LONG r = f(h, (KEYH)&k, hash, sizeof hash, sig, sizeof sig, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_HANDLE_, "%s got 0x%lx", bad_key[i].what, (unsigned long)r);
    }
    release(h);
}
TEST(dxgap3_lookup_lengths_buffer_protocol_with_real_provider) {
    OPEN_PROV(h);
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths);
    if (!f) { release(h); t_skip("missing export"); return; }
    BYTE out[64]; memset(out, 0xCC, sizeof out);
    EXPECT_EQ((DWORD)f(h, 0x0303, 0x2F, 1, NULL, 0x14, 0), (DWORD)NTE_INVALID_PARAMETER_);
    EXPECT_EQ((DWORD)f(h, 0x0303, 0x2F, 1, NULL, sizeof out, 0), (DWORD)NTE_INVALID_PARAMETER_);
    for (DWORD cb = 0; cb < 0x14; cb++) {
        LONG r = f(h, 0x0303, 0x2F, 1, out, cb, 0);
        CHECKF((DWORD)r == (DWORD)NTE_INVALID_PARAMETER_, "cb=%lu got 0x%lx", (unsigned long)cb, (unsigned long)r);
    }
    for (unsigned i = 0; i < sizeof out; i++) if (out[i] != 0xCC) { CHECKF(0, "buffer written on failure at %u", i); break; }
    release(h);
}
TEST(dxgap3_lookup_lengths_live_observation) {
    OPEN_PROV(h);
    SslLookupCipherLengths_pfn f = UN(SslLookupCipherLengths);
    if (!f) { release(h); t_skip("missing export"); return; }
    static const struct { DWORD proto, suite, ktype; } q[] = {
        { 0x0303, 0x002F, 1 }, { 0x0303, 0x003C, 1 }, { 0x0303, 0xC02F, 1 }, { 0x0303, 0xC02B, 3 }, { 0x0301, 0x0035, 1 },
        { 0x0303, 0xFFFF, 1 }, { 0, 0, 0 },
    };
    for (unsigned i = 0; i < sizeof q / sizeof q[0]; i++) {
        ULONG out[16]; memset(out, 0, sizeof out);
        LONG r = f(h, q[i].proto, q[i].suite, q[i].ktype, out, 0x14, 0);
        t_note("LookupCipherLengths proto=0x%lx suite=0x%lx ktype=%lu -> 0x%lx [%lu %lu %lu %lu %lu]", (unsigned long)q[i].proto,
               (unsigned long)q[i].suite, (unsigned long)q[i].ktype, (unsigned long)r, (unsigned long)out[0], (unsigned long)out[1],
               (unsigned long)out[2], (unsigned long)out[3], (unsigned long)out[4]);
    }
    release(h);
}
TEST(dxgap3_lookup_suite_info_live_observation) {
    OPEN_PROV(h);
    SslLookupCipherSuiteInfo_pfn f = UN(SslLookupCipherSuiteInfo);
    if (!f) { release(h); t_skip("missing export"); return; }
    static const struct { DWORD proto, suite, ktype; } q[] = {
        { 0x0303, 0x002F, 1 }, { 0x0303, 0xC02F, 1 }, { 0x0303, 0xC02B, 3 }, { 0x0303, 0xFFFF, 1 }, { 0, 0, 0 },
    };
    for (unsigned i = 0; i < sizeof q / sizeof q[0]; i++) {
        static BYTE out[4096]; memset(out, 0, sizeof out);
        LONG r = f(h, q[i].proto, q[i].suite, q[i].ktype, out, 0);
        t_note("LookupCipherSuiteInfo proto=0x%lx suite=0x%lx ktype=%lu -> 0x%lx, first dword 0x%lx", (unsigned long)q[i].proto,
               (unsigned long)q[i].suite, (unsigned long)q[i].ktype, (unsigned long)r, (unsigned long)*(ULONG *)out);
    }
    release(h);
}
