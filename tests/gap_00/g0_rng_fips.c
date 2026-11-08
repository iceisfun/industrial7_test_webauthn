#include "gap0.h"

/* ---- BCryptGenRandom --------------------------------------------------- */
TEST(gap0_genrandom_system_preferred_fills) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char a[64], b[64]; memset(a, 0, sizeof a); memset(b, 0, sizeof b);
    G0_OKST(U(BCryptGenRandom)(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    G0_OKST(U(BCryptGenRandom)(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    CHECK(memcmp(a, b, sizeof a) != 0);          /* 2^-512 chance of a false failure */
    unsigned char z[64] = {0}; CHECK(memcmp(a, z, sizeof a) != 0);
}
TEST(gap0_genrandom_does_not_overrun) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char buf[48]; memset(buf, 0xA5, sizeof buf);
    G0_OKST(U(BCryptGenRandom)(NULL, buf + 16, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    for (int i = 0; i < 16; i++) { CHECK(buf[i] == 0xA5); CHECK(buf[32 + i] == 0xA5); }
}
TEST(gap0_genrandom_sizes) {
    REQUIRE(U(BCryptGenRandom));
    static const ULONG sizes[] = {1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1000, 4096, 65536};
    static unsigned char buf[65536 + 8];
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        memset(buf, 0, sizeof buf); buf[sizes[i]] = 0x5A;
        G0_OKST(U(BCryptGenRandom)(NULL, buf, sizes[i], BCRYPT_USE_SYSTEM_PREFERRED_RNG));
        CHECK(buf[sizes[i]] == 0x5A);
        if (sizes[i] >= 16) { int nz = 0; for (ULONG k = 0; k < sizes[i]; k++) nz |= buf[k]; CHECK(nz != 0); }
    }
}
TEST(gap0_genrandom_zero_length) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char c = 0x77;
    NTSTATUS st = U(BCryptGenRandom)(NULL, &c, 0, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    t_note("GenRandom(cb=0) status 0x%08lx", (unsigned long)st);
    CHECK(c == 0x77);
}
TEST(gap0_genrandom_null_alg_without_flag) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[16];
    ST(U(BCryptGenRandom)(NULL, b, sizeof b, 0), G0_INVALID_HANDLE);
}
TEST(gap0_genrandom_flag_with_handle_rejected) {
    REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE h; unsigned char b[16];
    if (g0_open(&h, L"RNG", 0) < 0) { t_skip("RNG provider unavailable"); return; }
    ST(U(BCryptGenRandom)(h, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), G0_INVALID_PARAMETER);
    G0_OKST(U(BCryptGenRandom)(h, b, sizeof b, 0));
    g0_close(h);
}
TEST(gap0_genrandom_rng_pseudo_handle) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char a[32] = {0}, b[32] = {0};
    G0_OKST(U(BCryptGenRandom)(G0_PH_RNG, a, sizeof a, 0));
    G0_OKST(U(BCryptGenRandom)(G0_PH_RNG, b, sizeof b, 0));
    CHECK(memcmp(a, b, sizeof a) != 0);
    ST(U(BCryptGenRandom)(G0_PH_RNG, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG), G0_INVALID_PARAMETER);
}
TEST(gap0_genrandom_wrong_class_handle) {
    REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    BCRYPT_ALG_HANDLE h; unsigned char b[16];
    /* only handles of the RNG algorithm class are accepted (class check in the decompilation) */
    if (g0_open(&h, L"SHA256", 0) >= 0) { ST(U(BCryptGenRandom)(h, b, sizeof b, 0), G0_INVALID_HANDLE); g0_close(h); }
    if (g0_open(&h, L"AES", 0) >= 0)    { ST(U(BCryptGenRandom)(h, b, sizeof b, 0), G0_INVALID_HANDLE); g0_close(h); }
    ST(U(BCryptGenRandom)(G0_PH_SHA256, b, sizeof b, 0), G0_INVALID_HANDLE);
}
TEST(gap0_genrandom_all_rng_ids) {
    REQUIRE(U(BCryptGenRandom)); REQUIRE(U(BCryptOpenAlgorithmProvider));
    static const wchar_t *ids[] = {L"RNG", L"FIPS186DSARNG", L"DUALECRNG"};
    for (int i = 0; i < 3; i++) {
        BCRYPT_ALG_HANDLE h; unsigned char b[32] = {0};
        NTSTATUS st = g0_open(&h, ids[i], 0);
        if (st < 0) { t_note("RNG id %d open: 0x%08lx", i, (unsigned long)st); continue; }
        NTSTATUS g = U(BCryptGenRandom)(h, b, sizeof b, 0);
        t_note("GenRandom(%d) -> 0x%08lx", i, (unsigned long)g);
        g0_close(h);
    }
}
TEST(gap0_genrandom_entropy_in_buffer_flag) {
    REQUIRE(U(BCryptGenRandom));
    unsigned char b[32]; memset(b, 0x42, sizeof b);
    NTSTATUS st = U(BCryptGenRandom)(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG | BCRYPT_RNG_USE_ENTROPY_IN_BUFFER);
    t_note("GenRandom(system|use-entropy-in-buffer) -> 0x%08lx", (unsigned long)st);
}

/* ---- BCryptGetFipsAlgorithmMode --------------------------------------- */
UDECL(NTSTATUS, BCryptGetFipsAlgorithmMode, (BOOLEAN *));
static int g0_reg_dword(HKEY root, const char *sub, const char *val, DWORD *out) {
    HKEY k; DWORD type = 0, cb = 4, v = 0;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &k)) return 0;
    LONG r = RegQueryValueExA(k, val, NULL, &type, (BYTE *)&v, &cb);
    RegCloseKey(k);
    if (r || type != REG_DWORD || cb != 4) return 0;
    *out = v; return 1;
}
TEST(gap0_fips_null_pointer) {
    REQUIRE(UN(BCryptGetFipsAlgorithmMode));
    ST(UN(BCryptGetFipsAlgorithmMode)(NULL), G0_INVALID_PARAMETER);
}
TEST(gap0_fips_writes_boolean_and_succeeds) {
    REQUIRE(UN(BCryptGetFipsAlgorithmMode));
    for (unsigned pre = 0; pre < 2; pre++) {
        BOOLEAN f = (BOOLEAN)(pre ? 0xAA : 0x00);
        G0_OKST(UN(BCryptGetFipsAlgorithmMode)(&f));
        CHECK(f == 0 || f == 1);
    }
}
TEST(gap0_fips_matches_registry) {
    REQUIRE(UN(BCryptGetFipsAlgorithmMode));
    /* The decompilation reads Lsa\FipsAlgorithmPolicy\Enabled, Lsa\FipsAlgorithmPolicy (legacy value) and
     * Lsa\FipsAlgorithmPolicy\MDMEnabled; any non-zero DWORD enables the mode. */
    DWORD v, any = 0; int found = 0;
    if (g0_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "Enabled", &v)) { found = 1; any |= v != 0; }
    if (g0_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "FipsAlgorithmPolicy", &v)) { found = 1; any |= v != 0; }
    if (g0_reg_dword(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy", "MDMEnabled", &v)) { found = 1; any |= v != 0; }
    BOOLEAN f = 7;
    G0_OKST(UN(BCryptGetFipsAlgorithmMode)(&f));
    if (t_is_wine()) { t_note("wine: registry mapping not asserted (fips=%d registry=%d)", f, (int)any); return; }
    CHECKF((f != 0) == (any != 0), "fips=%d registry-any=%lu found=%d", f, (unsigned long)any, found);
}
TEST(gap0_fips_repeatable) {
    REQUIRE(UN(BCryptGetFipsAlgorithmMode));
    BOOLEAN a = 9, b = 9;
    G0_OKST(UN(BCryptGetFipsAlgorithmMode)(&a)); G0_OKST(UN(BCryptGetFipsAlgorithmMode)(&b));
    CHECK(a == b);
}

/* ---- BCryptFreeBuffer -------------------------------------------------- */
TEST(gap0_freebuffer_null_is_noop) {
    REQUIRE(U(BCryptFreeBuffer));
    U(BCryptFreeBuffer)(NULL);   /* returns void; frees only a non-NULL pointer */
    CHECK(1);
}
TEST(gap0_freebuffer_releases_enum_result) {
    REQUIRE(U(BCryptFreeBuffer)); REQUIRE(U(BCryptEnumAlgorithms));
    ULONG n = 0; BCRYPT_ALGORITHM_IDENTIFIER *l = NULL;
    for (int i = 0; i < 50; i++) {
        n = 0; l = NULL;
        G0_OKST(U(BCryptEnumAlgorithms)(0, &n, &l, 0));
        CHECK(n > 0 && l != NULL);
        U(BCryptFreeBuffer)(l);
    }
}
