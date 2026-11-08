/* Whole-DLL export sweep, part 3: the bcrypt.dll / ncrypt.dll entry points a WebAuthn client relies on
 * resolve, ncrypt.dll forwards its BCrypt* names to bcrypt.dll, and the load-time dependencies of the
 * module are reported. */
#include "sweep.h"
#include "deps_table.h"
#include <bcrypt.h>
#include <ncrypt.h>

static int deps_ok(void) { return t_module("bcrypt.dll") != NULL && t_module("ncrypt.dll") != NULL; }

#define GEN_BC(N) \
    TEST(export_sweep_resolve_bcrypt_has_##N) { \
        if (!deps_ok()) { t_skip("bcrypt/ncrypt unavailable"); return; } \
        FARPROC p = t_proc_in("bcrypt.dll", #N); \
        CHECK(p != NULL); \
        if (p) { \
            IMAGE_NT_HEADERS64 *n = sw_nt(t_module("bcrypt.dll")); \
            CHECK(n != NULL); \
            /* the function lives inside bcrypt.dll's own image (not a forward to elsewhere) */ \
            CHECK((BYTE *)p > (BYTE *)t_module("bcrypt.dll") && (BYTE *)p < (BYTE *)t_module("bcrypt.dll") + (n ? n->OptionalHeader.SizeOfImage : 0)); \
        } \
    } \
    TEST(export_sweep_resolve_ncrypt_forwards_##N) { \
        if (!deps_ok()) { t_skip("bcrypt/ncrypt unavailable"); return; } \
        FARPROC a = t_proc_in("ncrypt.dll", #N), b = t_proc_in("bcrypt.dll", #N); \
        CHECK(b != NULL); \
        CHECKF(a == b, "ncrypt!" #N " does not forward to bcrypt!" #N); \
    }
SWEEP_BCRYPT(GEN_BC)

#define GEN_NC(N) \
    TEST(export_sweep_resolve_ncrypt_has_##N) { \
        if (!deps_ok()) { t_skip("bcrypt/ncrypt unavailable"); return; } \
        HMODULE m = t_module("ncrypt.dll"); \
        FARPROC p = GetProcAddress(m, #N); \
        CHECK(p != NULL); \
        IMAGE_NT_HEADERS64 *n = sw_nt(m); \
        CHECK(n != NULL); \
        if (p && n) CHECK((BYTE *)p > (BYTE *)m && (BYTE *)p < (BYTE *)m + n->OptionalHeader.SizeOfImage); \
        CHECK(GetProcAddress(t_module("bcrypt.dll"), #N) == NULL); \
    }
SWEEP_NCRYPT(GEN_NC)

TEST(export_sweep_resolve_deps_ordinals_reference_build) {
    if (!deps_ok()) { t_skip("bcrypt/ncrypt unavailable"); return; }
    static const struct { const char *dll, *name; unsigned ord; } t[] = {
        { "bcrypt.dll", "BCryptGenRandom", 30 }, { "bcrypt.dll", "BCryptHash", 35 },
        { "bcrypt.dll", "BCryptOpenAlgorithmProvider", 40 }, { "bcrypt.dll", "BCryptCloseAlgorithmProvider", 3 },
        { "ncrypt.dll", "NCryptOpenStorageProvider", 86 }, { "ncrypt.dll", "NCryptCreatePersistedKey", 63 },
        { "ncrypt.dll", "NCryptFreeObject", 76 }, { "ncrypt.dll", "NCryptFinalizeKey", 74 } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        FARPROC a = t_proc_in(t[i].dll, t[i].name), b = t_proc_ord(t[i].dll, t[i].ord);
        CHECK(a != NULL);
        if (a != b) t_note("%s!%s: ordinal %u does not match on this build", t[i].dll, t[i].name, t[i].ord);
    }
}

/* ---- trivially safe liveness calls -------------------------------------- */
TEST(export_sweep_resolve_bcryptgenrandom_system_rng) {
    typeof(&BCryptGenRandom) f = (typeof(&BCryptGenRandom))t_proc_in("bcrypt.dll", "BCryptGenRandom");
    REQUIRE(f);
    unsigned char a[32] = {0}, b[32] = {0};
    EQ1(f(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG), 0);
    EQ1(f(NULL, b, sizeof b, BCRYPT_USE_SYSTEM_PREFERRED_RNG), 0);
    CHECK(memcmp(a, b, sizeof a) != 0);
    unsigned char z[32] = {0};
    CHECK(memcmp(a, z, sizeof a) != 0);
}
TEST(export_sweep_resolve_bcryptgenrandom_via_ncrypt_forward) {
    typeof(&BCryptGenRandom) f = (typeof(&BCryptGenRandom))t_proc_in("ncrypt.dll", "BCryptGenRandom");
    REQUIRE(f);
    unsigned char a[16] = {0}, z[16] = {0};
    EQ1(f(NULL, a, sizeof a, BCRYPT_USE_SYSTEM_PREFERRED_RNG), 0);
    CHECK(memcmp(a, z, sizeof a) != 0);
}
TEST(export_sweep_resolve_bcrypthash_sha256_abc) {
    typeof(&BCryptOpenAlgorithmProvider) open = (typeof(&BCryptOpenAlgorithmProvider))t_proc_in("bcrypt.dll", "BCryptOpenAlgorithmProvider");
    typeof(&BCryptCloseAlgorithmProvider) cls = (typeof(&BCryptCloseAlgorithmProvider))t_proc_in("bcrypt.dll", "BCryptCloseAlgorithmProvider");
    typeof(&BCryptHash) hash = (typeof(&BCryptHash))t_proc_in("bcrypt.dll", "BCryptHash");
    REQUIRE(open); REQUIRE(cls); REQUIRE(hash);
    BCRYPT_ALG_HANDLE alg = NULL;
    EQ1(open(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0), 0);
    CHECK(alg != NULL); if (!alg) return;
    unsigned char out[32] = {0};
    EQ1(hash(alg, NULL, 0, (PUCHAR)"abc", 3, out, sizeof out), 0);
    static const unsigned char want[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    CHECK(!memcmp(out, want, 32));
    EQ1(cls(alg, 0), 0);
}
TEST(export_sweep_resolve_bcrypt_close_null_handle) {
    typeof(&BCryptCloseAlgorithmProvider) cls = (typeof(&BCryptCloseAlgorithmProvider))t_proc_in("bcrypt.dll", "BCryptCloseAlgorithmProvider");
    REQUIRE(cls);
    EQ1((DWORD)cls(NULL, 0), 0xC0000008);       /* STATUS_INVALID_HANDLE */
}
TEST(export_sweep_resolve_ncrypt_open_software_provider_and_free) {
    typeof(&NCryptOpenStorageProvider) open = (typeof(&NCryptOpenStorageProvider))t_proc_in("ncrypt.dll", "NCryptOpenStorageProvider");
    typeof(&NCryptFreeObject) fr = (typeof(&NCryptFreeObject))t_proc_in("ncrypt.dll", "NCryptFreeObject");
    REQUIRE(open); REQUIRE(fr);
    NCRYPT_PROV_HANDLE p = 0;
    SECURITY_STATUS s = open(&p, MS_KEY_STORAGE_PROVIDER, 0);
    if (s != 0) { t_note("NCryptOpenStorageProvider(MS_KEY_STORAGE_PROVIDER) = 0x%lx", (unsigned long)s); t_skip("key isolation service unavailable"); return; }
    CHECK(p != 0);
    EQ1(fr(p), 0);
}

/* ---- load-time dependencies, reported only -------------------------------- */
TEST(export_sweep_resolve_import_table_report) {
    SW_NEED_MODULE();
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    CHECK(n != NULL); if (!n) return;
    IMAGE_DATA_DIRECTORY *dd = &n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    int count = 0, has_bcrypt = 0, has_ncrypt = 0;
    if (dd->VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)h + dd->VirtualAddress);
        for (; d->Name && count < 200; d++, count++) {
            const char *nm = (const char *)h + d->Name;
            if (!lstrcmpiA(nm, "bcrypt.dll")) has_bcrypt = 1;
            if (!lstrcmpiA(nm, "ncrypt.dll")) has_ncrypt = 1;
            t_note("static import: %s", nm);
        }
    }
    t_note("%d static import modules; bcrypt=%d ncrypt=%d", count, has_bcrypt, has_ncrypt);
    CHECK(count > 0);
    IMAGE_DATA_DIRECTORY *dl = &n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (dl->VirtualAddress) {
        IMAGE_DELAYLOAD_DESCRIPTOR *d = (IMAGE_DELAYLOAD_DESCRIPTOR *)((BYTE *)h + dl->VirtualAddress);
        for (int i = 0; d->DllNameRVA && i < 200; d++, i++) t_note("delay import: %s", (const char *)h + d->DllNameRVA);
    }
    t_note("bcrypt.dll currently loaded: %d, ncrypt.dll: %d", GetModuleHandleA("bcrypt.dll") != NULL, GetModuleHandleA("ncrypt.dll") != NULL);
}
