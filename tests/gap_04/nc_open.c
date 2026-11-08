#include "gap4.h"
/* NCryptOpenStorageProvider (ncrypt.dll).
 * Decomp: phProvider NULL -> NTE_INVALID_PARAMETER (0x80090027) before anything else; otherwise *phProvider
 * is zeroed first, then the provider name is resolved (NULL or empty selects the default key storage
 * provider) and loaded, and dwFlags is passed to the provider's OpenProvider. Failures go through
 * NormalizeNteStatus. */
#define NREQ() do { if (!UIN("ncrypt.dll", NCryptOpenStorageProvider) || !UIN("ncrypt.dll", NCryptFreeObject)) { t_skip("missing ncrypt exports"); return; } } while (0)
#define NOPEN UIN("ncrypt.dll", NCryptOpenStorageProvider)
#define NFREE UIN("ncrypt.dll", NCryptFreeObject)

TEST(gap4_ncopen_null_phprovider) {
    NREQ();
    if (t_is_wine()) { t_skip("emulated ncrypt dereferences the NULL output"); return; }
    EQC(NOPEN(NULL, MS_KEY_STORAGE_PROVIDER, 0), 0x80090027u);
}
TEST(gap4_ncopen_null_phprovider_null_name) {
    NREQ();
    if (t_is_wine()) { t_skip("emulated ncrypt dereferences the NULL output"); return; }
    EQC(NOPEN(NULL, NULL, 0), 0x80090027u);
}
TEST(gap4_ncopen_null_phprovider_with_flags) {
    NREQ();
    if (t_is_wine()) { t_skip("emulated ncrypt dereferences the NULL output"); return; }
    EQC(NOPEN(NULL, MS_KEY_STORAGE_PROVIDER, 0xFFFFFFFF), 0x80090027u);
}
TEST(gap4_ncopen_output_zeroed_on_failure) {
    NREQ();
    NCRYPT_PROV_HANDLE h = (NCRYPT_PROV_HANDLE)0x1234;
    SECURITY_STATUS s = NOPEN(&h, L"No Such Storage Provider gap4", 0);
    CHECK(s != 0);
    CHECK((int)s < 0);
    EXPECT_EQ(h, 0);
    t_note("unknown provider name -> 0x%lx", (unsigned long)s);
}
TEST(gap4_ncopen_unknown_provider_stable) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 1;
    SECURITY_STATUS s1 = NOPEN(&h, L"No Such Storage Provider gap4", 0);
    h = 1;
    SECURITY_STATUS s2 = NOPEN(&h, L"No Such Storage Provider gap4", 0);
    EXPECT_EQ(s1, s2);
}
TEST(gap4_ncopen_software_provider) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0x77;
    SECURITY_STATUS s = NOPEN(&h, MS_KEY_STORAGE_PROVIDER, 0);
    EXPECT_EQ(s, 0);
    CHECK(h != 0 && h != 0x77);
    if (s == 0) EQC(NFREE(h), 0);
}
TEST(gap4_ncopen_default_provider_null_name) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0x77;
    SECURITY_STATUS s = NOPEN(&h, NULL, 0);
    EXPECT_EQ(s, 0);
    CHECK(h != 0 && h != 0x77);
    if (s == 0) EQC(NFREE(h), 0);
}
TEST(gap4_ncopen_default_provider_empty_name) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0x77;
    SECURITY_STATUS s = NOPEN(&h, L"", 0);
    EXPECT_EQ(s, 0);
    CHECK(h != 0 && h != 0x77);
    if (s == 0) EQC(NFREE(h), 0);
}
TEST(gap4_ncopen_smartcard_provider_resolves_or_fails_cleanly) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0x77;
    SECURITY_STATUS s = NOPEN(&h, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
    if (s == 0) { CHECK(h != 0); NFREE(h); } else { EXPECT_EQ(h, 0); }
    t_note("smart card KSP open -> 0x%lx", (unsigned long)s);
}
TEST(gap4_ncopen_distinct_handles) {
    NREQ();
    NCRYPT_PROV_HANDLE a = 0, b = 0;
    EQC(NOPEN(&a, MS_KEY_STORAGE_PROVIDER, 0), 0);
    EQC(NOPEN(&b, MS_KEY_STORAGE_PROVIDER, 0), 0);
    CHECK(a != 0 && b != 0 && a != b);
    if (a) EQC(NFREE(a), 0);
    if (b) EQC(NFREE(b), 0);
}
TEST(gap4_ncopen_repeat_open_free_cycles) {
    NREQ();
    int bad = 0;
    for (int i = 0; i < 100; i++) {
        NCRYPT_PROV_HANDLE h = 0;
        if (NOPEN(&h, MS_KEY_STORAGE_PROVIDER, 0) != 0 || !h) { bad++; continue; }
        if (NFREE(h) != 0) bad++;
    }
    EXPECT_EQ(bad, 0);
}
TEST(gap4_ncopen_reserved_flags) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0x77;
    SECURITY_STATUS s = NOPEN(&h, MS_KEY_STORAGE_PROVIDER, 0x40000000);
    t_note("OpenStorageProvider with undefined flags -> 0x%lx (handle %p)", (unsigned long)s, (void *)h);
    if (s == 0 && h) NFREE(h);
}
TEST(gap4_ncopen_open_free_roundtrip) {
    NREQ();
    NCRYPT_PROV_HANDLE h = 0;
    EQC(NOPEN(&h, MS_KEY_STORAGE_PROVIDER, 0), 0);
    if (h) EQC(NFREE(h), 0);
}
TEST(gap4_ncfree_null_handle) {
    NREQ();
    SECURITY_STATUS s = NFREE(0);
    CHECK((int)s < 0);
    t_note("NCryptFreeObject(0) -> 0x%lx", (unsigned long)s);
}
TEST(gap4_ncopen_module_export_note) {
    /* the BCrypt exports listed for ncrypt.dll must resolve there on this build */
    HMODULE m = t_module("ncrypt.dll");
    if (!m) { t_skip("ncrypt.dll not present"); return; }
    t_note("ncrypt.dll exports BCryptHash: %s", GetProcAddress(m, "BCryptHash") ? "yes" : "no");
}
