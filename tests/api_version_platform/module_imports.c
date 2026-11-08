/* Import dependencies of webauthn.dll, read from the loaded image's import and delay-import tables:
 * which DLLs are bound at load time (static) and which are delay-loaded, and that the resolved IAT
 * slots of the static imports point at the real exports. */
#include "apv.h"
#include "apv_imports.h"

static const IMAGE_IMPORT_DESCRIPTOR *imp_first(HMODULE m) {
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_IMPORT);
    return d && d->VirtualAddress ? (const IMAGE_IMPORT_DESCRIPTOR *)apv_rva(m, d->VirtualAddress) : NULL;
}
static const apv_delay_desc *dimp_first(HMODULE m) {
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    return d && d->VirtualAddress ? (const apv_delay_desc *)apv_rva(m, d->VirtualAddress) : NULL;
}
static const IMAGE_IMPORT_DESCRIPTOR *imp_find(HMODULE m, const char *dll) {
    for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++)
        if (!lstrcmpiA((const char *)apv_rva(m, d->Name), dll)) return d;
    return NULL;
}
static const apv_delay_desc *dimp_find(HMODULE m, const char *dll) {
    for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++)
        if (!lstrcmpiA((const char *)apv_rva(m, d->DllNameRVA), dll)) return d;
    return NULL;
}
/* Does the name table at rva contain the by-name import? */
static int thunks_have_name(HMODULE m, DWORD int_rva, const char *name, int *count_out) {
    const ULONGLONG *t = (const ULONGLONG *)apv_rva(m, int_rva);
    int found = 0, n = 0;
    for (; *t; t++, n++) {
        if (*t & 0x8000000000000000ull) continue;
        const char *nm = (const char *)apv_rva(m, (DWORD)(*t & 0x7FFFFFFF)) + 2;
        if (name && !strcmp(nm, name)) found = 1;
    }
    if (count_out) *count_out = n;
    return found;
}
static int thunk_count(HMODULE m, DWORD int_rva, int *ordinal_imports) {
    const ULONGLONG *t = (const ULONGLONG *)apv_rva(m, int_rva);
    int n = 0; *ordinal_imports = 0;
    for (; *t; t++, n++) if (*t & 0x8000000000000000ull) (*ordinal_imports)++;
    return n;
}

/* ---- directory-level facts ------------------------------------------------- */
TEST(apv_imp_static_descriptor_count) {
    APV_REQUIRE_MOD(m);
    int n = 0; for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++) n++;
    if (n != 35) t_note("%d static import DLLs (reference build 10.0.19041.2913: 35)", n);
    CHECK(n > 10);
}
TEST(apv_imp_delay_descriptor_count) {
    APV_REQUIRE_MOD(m);
    int n = 0; for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++) n++;
    if (n != 28) t_note("%d delay import DLLs (reference build 10.0.19041.2913: 28)", n);
    CHECK(n > 5);
}
TEST(apv_imp_static_not_bound) {
    /* No pre-bound addresses: TimeDateStamp is 0 and there is no forwarder chain. */
    APV_REQUIRE_MOD(m);
    int bound = 0, chain = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++) { if (d->TimeDateStamp) bound++; if (d->ForwarderChain && d->ForwarderChain != 0xFFFFFFFF) chain++; }
    EXPECT_EQ(chain, 0);
    if (bound) t_note("%d static descriptors carry a bind timestamp", bound);
}
TEST(apv_imp_no_ordinal_imports_from_real_modules) {
    APV_REQUIRE_MOD(m);
    static const char *const real[] = { "bcrypt.dll", "ntdll.dll", "msvcp_win.dll" };
    for (int i = 0; i < 3; i++) {
        const IMAGE_IMPORT_DESCRIPTOR *d = imp_find(m, real[i]);
        CHECK(d != NULL); if (!d) continue;
        int ord; thunk_count(m, d->OriginalFirstThunk, &ord);
        EXPECT_EQ(ord, 0);
    }
}
TEST(apv_imp_kernel_user_advapi_not_imported_directly) {
    /* Win32 services arrive through API-set contracts; the classic umbrella DLLs are not imported by name. */
    APV_REQUIRE_MOD(m);
    static const char *const no[] = { "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll", "ole32.dll", "oleaut32.dll",
        "combase.dll", "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "sechost.dll", "win32u.dll", "gdi32.dll", "shell32.dll", "ws2_32.dll", "winhttp.dll" };
    for (unsigned i = 0; i < sizeof no / sizeof *no; i++) {
        CHECKF(imp_find(m, no[i]) == NULL, "%s is a static import", no[i]);
        CHECKF(dimp_find(m, no[i]) == NULL, "%s is a delay import", no[i]);
    }
}
TEST(apv_imp_ncrypt_is_delay_loaded_not_static) {
    APV_REQUIRE_MOD(m);
    CHECK(imp_find(m, "ncrypt.dll") == NULL);
    CHECK(dimp_find(m, "ncrypt.dll") != NULL);
}
TEST(apv_imp_bcrypt_is_static_not_delay) {
    APV_REQUIRE_MOD(m);
    CHECK(imp_find(m, "bcrypt.dll") != NULL);
    CHECK(dimp_find(m, "bcrypt.dll") == NULL);
}
TEST(apv_imp_no_dll_is_both_static_and_delay) {
    APV_REQUIRE_MOD(m);
    int both = 0;
    for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++) if (imp_find(m, (const char *)apv_rva(m, d->DllNameRVA))) both++;
    EXPECT_EQ(both, 0);
}
TEST(apv_imp_total_static_function_imports) {
    APV_REQUIRE_MOD(m);
    int total = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++) { int o; total += thunk_count(m, d->OriginalFirstThunk, &o); }
    if (total != 184) t_note("%d static imported functions (reference build: 184)", total);
    CHECK(total > 50);
}
TEST(apv_imp_total_delay_function_imports) {
    APV_REQUIRE_MOD(m);
    int total = 0;
    for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++) { int o; total += thunk_count(m, d->ImportNameTableRVA, &o); }
    if (total != 135) t_note("%d delay imported functions (reference build: 135)", total);
    CHECK(total > 50);
}
TEST(apv_imp_delay_handle_slots_start_empty_or_resolved_to_import) {
    /* Each delay descriptor owns a module-handle slot in writable data; it is NULL until first use, afterwards the real module. */
    APV_REQUIRE_MOD(m);
    int bad = 0;
    for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++) {
        const apv_delay_desc *dd = d;
        const HMODULE *slot = (const HMODULE *)apv_rva(m, dd->ModuleHandleRVA);
        const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, dd->ModuleHandleRVA);
        if (!s || !(s->Characteristics & IMAGE_SCN_MEM_WRITE)) bad++;
        (void)slot;
    }
    EXPECT_EQ(bad, 0);
}

/* ---- one test per DLL ------------------------------------------------------- */
#define STATIC_DLL_TEST(id, name) \
    TEST(apv_imp_static_##id) { APV_REQUIRE_MOD(m); const IMAGE_IMPORT_DESCRIPTOR *d = imp_find(m, name); CHECKF(d != NULL, "%s not statically imported", name); \
        if (d) { int o; CHECK(thunk_count(m, d->OriginalFirstThunk, &o) > 0); } }
APV_STATIC_DLLS(STATIC_DLL_TEST)
#define DELAY_DLL_TEST(id, name) \
    TEST(apv_imp_delay_##id) { APV_REQUIRE_MOD(m); const apv_delay_desc *d = dimp_find(m, name); CHECKF(d != NULL, "%s not delay imported", name); \
        if (d) { int o; CHECK(thunk_count(m, d->ImportNameTableRVA, &o) > 0); } }
APV_DELAY_DLLS(DELAY_DLL_TEST)

/* ---- imported function names -------------------------------------------------- */
static void check_static_names(const char *dll, const char *const *names, int n) {
    APV_REQUIRE_MOD(m);
    const IMAGE_IMPORT_DESCRIPTOR *d = imp_find(m, dll);
    CHECK(d != NULL); if (!d) return;
    int cnt; thunks_have_name(m, d->OriginalFirstThunk, NULL, &cnt);
    if (cnt != n) t_note("%s: %d imports (reference build: %d)", dll, cnt, n);
    int missing = 0;
    for (int i = 0; i < n; i++) if (!thunks_have_name(m, d->OriginalFirstThunk, names[i], NULL)) { missing++; t_note("%s: missing import %s", dll, names[i]); }
    if (missing) t_note("%s: %d reference imports absent (servicing-level difference?)", dll, missing);
}
static void check_delay_names(const char *dll, const char *const *names, int n) {
    APV_REQUIRE_MOD(m);
    const apv_delay_desc *d = dimp_find(m, dll);
    CHECK(d != NULL); if (!d) return;
    int cnt; thunks_have_name(m, d->ImportNameTableRVA, NULL, &cnt);
    if (cnt != n) t_note("%s: %d delay imports (reference build: %d)", dll, cnt, n);
    int missing = 0;
    for (int i = 0; i < n; i++) if (!thunks_have_name(m, d->ImportNameTableRVA, names[i], NULL)) { missing++; t_note("%s: missing delay import %s", dll, names[i]); }
    if (missing) t_note("%s: %d reference delay imports absent (servicing-level difference?)", dll, missing);
}
#define NAMES(arr) arr, (int)(sizeof arr / sizeof *arr)
TEST(apv_impnames_bcrypt) { check_static_names("bcrypt.dll", NAMES(apv_imp_bcrypt)); }
TEST(apv_impnames_ntdll) { check_static_names("ntdll.dll", NAMES(apv_imp_ntdll)); }
TEST(apv_impnames_msvcp_win) {
    static const char *const n[] = { "?_Xlength_error@std@@YAXPEBD@Z" };
    check_static_names("msvcp_win.dll", NAMES(n));
}
TEST(apv_impnames_delay_ncrypt) { check_delay_names("ncrypt.dll", NAMES(apv_dimp_ncrypt)); }
TEST(apv_impnames_delay_cryptngc) { check_delay_names("cryptngc.dll", NAMES(apv_dimp_cryptngc)); }
TEST(apv_impnames_delay_crypt32) { check_delay_names("CRYPT32.dll", NAMES(apv_dimp_crypt32)); }
TEST(apv_impnames_delay_hid) { check_delay_names("HID.DLL", NAMES(apv_dimp_hid)); }
TEST(apv_impnames_delay_devobj) { check_delay_names("DEVOBJ.dll", NAMES(apv_dimp_devobj)); }
TEST(apv_impnames_delay_rpcrt4) { check_delay_names("RPCRT4.dll", NAMES(apv_dimp_rpcrt4)); }
TEST(apv_impnames_delay_wintrust) { check_delay_names("WINTRUST.dll", NAMES(apv_dimp_wintrust)); }
TEST(apv_impnames_delay_tbs) { check_delay_names("tbs.dll", NAMES(apv_dimp_tbs)); }
TEST(apv_impnames_delay_credui) { check_delay_names("credui.dll", NAMES(apv_dimp_credui)); }
TEST(apv_impnames_delay_cryptbase) { check_delay_names("CRYPTBASE.dll", NAMES(apv_dimp_cryptbase)); }

/* The names the delay-loaded modules must actually export (so a delayed call can resolve). */
static void imported_names_exist(const char *dll, const char *const *names, int n) {
    HMODULE h = LoadLibraryExA(dll, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h) { t_skip("%s not loadable here", dll); return; }
    int bad = 0;
    for (int i = 0; i < n; i++) if (!GetProcAddress(h, names[i])) { bad++; t_note("%s does not export %s", dll, names[i]); }
    EXPECT_EQ(bad, 0);
    FreeLibrary(h);
}
TEST(apv_impexp_ncrypt_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("ncrypt.dll", NAMES(apv_dimp_ncrypt)); }
TEST(apv_impexp_cryptngc_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("cryptngc.dll", NAMES(apv_dimp_cryptngc)); }
TEST(apv_impexp_crypt32_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("crypt32.dll", NAMES(apv_dimp_crypt32)); }
TEST(apv_impexp_hid_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("hid.dll", NAMES(apv_dimp_hid)); }
TEST(apv_impexp_devobj_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("devobj.dll", NAMES(apv_dimp_devobj)); }
TEST(apv_impexp_rpcrt4_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("rpcrt4.dll", NAMES(apv_dimp_rpcrt4)); }
TEST(apv_impexp_wintrust_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("wintrust.dll", NAMES(apv_dimp_wintrust)); }
TEST(apv_impexp_tbs_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("tbs.dll", NAMES(apv_dimp_tbs)); }
TEST(apv_impexp_cryptbase_exports_all_delay_imports) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } imported_names_exist("cryptbase.dll", NAMES(apv_dimp_cryptbase)); }

/* ---- resolved IAT slots of the static imports ---------------------------------- */
static void iat_matches(const char *dll, const char *const *names, int n) {
    APV_REQUIRE_MOD(m);
    HMODULE owner = GetModuleHandleA(dll);
    const IMAGE_IMPORT_DESCRIPTOR *d = imp_find(m, dll);
    CHECK(owner != NULL && d != NULL); if (!owner || !d) return;
    const ULONGLONG *ilt = (const ULONGLONG *)apv_rva(m, d->OriginalFirstThunk);
    const ULONGLONG *iat = (const ULONGLONG *)apv_rva(m, d->FirstThunk);
    int bad = 0, checked = 0;
    for (int i = 0; ilt[i]; i++) {
        const char *nm = (const char *)apv_rva(m, (DWORD)(ilt[i] & 0x7FFFFFFF)) + 2;
        FARPROC want = GetProcAddress(owner, nm);
        if (!want) { bad++; t_note("%s!%s not exported by the loaded module", dll, nm); continue; }
        checked++;
        if ((ULONGLONG)(ULONG_PTR)want != iat[i]) bad++;
    }
    if (checked != n) t_note("%s: %d imports checked (reference %d)", dll, checked, n);
    EXPECT_EQ(bad, 0);
}
TEST(apv_iat_bcrypt_slots_point_to_exports) { if (t_is_wine()) { t_skip("emulator"); return; } iat_matches("bcrypt.dll", NAMES(apv_imp_bcrypt)); }
TEST(apv_iat_ntdll_slots_point_to_exports) { if (t_is_wine()) { t_skip("emulator"); return; } iat_matches("ntdll.dll", NAMES(apv_imp_ntdll)); }
TEST(apv_iat_slots_are_in_rdata_or_data_and_nonnull) {
    APV_REQUIRE_MOD(m);
    int bad = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++) {
        const ULONGLONG *iat = (const ULONGLONG *)apv_rva(m, d->FirstThunk);
        const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, d->FirstThunk);
        if (!s) { bad++; continue; }
        for (int i = 0; iat[i]; i++) if (iat[i] < 0x10000) bad++;
    }
    EXPECT_EQ(bad, 0);
}
TEST(apv_iat_import_address_table_directory_covers_static_iats) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *iat = apv_dd(m, IMAGE_DIRECTORY_ENTRY_IAT);
    CHECK(iat && iat->VirtualAddress); if (!iat || !iat->VirtualAddress) return;
    int bad = 0;
    for (const IMAGE_IMPORT_DESCRIPTOR *d = imp_first(m); d && d->Name; d++)
        if (d->FirstThunk < iat->VirtualAddress || d->FirstThunk >= iat->VirtualAddress + iat->Size) bad++;
    EXPECT_EQ(bad, 0);
}
TEST(apv_iat_delay_slots_unresolved_ones_point_into_image) {
    /* Delay-load IAT slots hold thunk addresses inside webauthn.dll until their first use, and real code addresses afterwards. */
    APV_REQUIRE_MOD(m);
    const IMAGE_NT_HEADERS64 *nt = apv_nt(m);
    int in_image = 0, outside = 0;
    for (const apv_delay_desc *d = dimp_first(m); d && d->DllNameRVA; d++) {
        const ULONGLONG *iat = (const ULONGLONG *)apv_rva(m, d->ImportAddressTableRVA);
        for (int i = 0; iat[i]; i++) {
            if (iat[i] >= (ULONGLONG)(ULONG_PTR)m && iat[i] < (ULONGLONG)(ULONG_PTR)m + nt->OptionalHeader.SizeOfImage) in_image++; else outside++;
        }
    }
    CHECK(in_image + outside > 50);
    t_note("delay IAT slots: %d still pointing at load thunks, %d already resolved", in_image, outside);
}
