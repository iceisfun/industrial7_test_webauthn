/* Export table of webauthn.dll: 56 named exports, ordinal base 1, ordinals 1..56 assigned in
 * ASCII name order, no forwarders. Tests are generated per export from apv_exports.h. */
#include "apv.h"
#include "apv_exports.h"

#define N_EXPORTS 56

/* ---- export directory structure ------------------------------------------ */
TEST(apv_exp_dir_present) { APV_REQUIRE_MOD(m); CHECK(apv_expdir(m) != NULL); }
TEST(apv_exp_dir_characteristics_zero) { APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m); CHECK(e != NULL); if (e) EXPECT_EQ(e->Characteristics, 0); }
TEST(apv_exp_dir_ordinal_base_1) { APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m); CHECK(e != NULL); if (e) EXPECT_EQ(e->Base, 1); }
TEST(apv_exp_dir_function_count_56) { APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m); CHECK(e != NULL); if (e) EXPECT_EQ(e->NumberOfFunctions, N_EXPORTS); }
TEST(apv_exp_dir_name_count_56) { APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m); CHECK(e != NULL); if (e) EXPECT_EQ(e->NumberOfNames, N_EXPORTS); }
TEST(apv_exp_dir_no_unnamed_exports) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (e) EXPECT_EQ(e->NumberOfFunctions, e->NumberOfNames);
}
TEST(apv_exp_dir_dll_name) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const char *n = (const char *)apv_rva(m, e->Name);
    CHECKF(!lstrcmpiA(n, "webauthn.dll"), "export dll name \"%s\"", n);
}
TEST(apv_exp_dir_tables_inside_image) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    const IMAGE_NT_HEADERS64 *nt = apv_nt(m);
    CHECK(e && nt); if (!e || !nt) return;
    DWORD sz = nt->OptionalHeader.SizeOfImage;
    CHECK(e->AddressOfFunctions && e->AddressOfFunctions < sz);
    CHECK(e->AddressOfNames && e->AddressOfNames < sz);
    CHECK(e->AddressOfNameOrdinals && e->AddressOfNameOrdinals < sz);
}
TEST(apv_exp_dir_lives_in_rdata) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_EXPORT);
    const IMAGE_SECTION_HEADER *s = d ? apv_section_of_rva(m, d->VirtualAddress) : NULL;
    CHECK(s && !strncmp((const char *)s->Name, ".rdata", 8));
}
TEST(apv_exp_names_strictly_ascending_ascii) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames);
    int bad = 0;
    for (DWORD i = 1; i < e->NumberOfNames; i++)
        if (strcmp((const char *)apv_rva(m, names[i-1]), (const char *)apv_rva(m, names[i])) >= 0) bad++;
    EXPECT_EQ(bad, 0);
}
TEST(apv_exp_name_ordinal_table_is_identity) {
    /* Name i has ordinal index i, i.e. ordinal i+1: ordinals follow the sorted name order. */
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const WORD *ords = (const WORD *)apv_rva(m, e->AddressOfNameOrdinals);
    int bad = 0;
    for (DWORD i = 0; i < e->NumberOfNames; i++) if (ords[i] != i) bad++;
    EXPECT_EQ(bad, 0);
}
TEST(apv_exp_no_forwarders) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_EXPORT);
    CHECK(e && d); if (!e || !d) return;
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions);
    int fwd = 0;
    for (DWORD i = 0; i < e->NumberOfFunctions; i++)
        if (funcs[i] >= d->VirtualAddress && funcs[i] < d->VirtualAddress + d->Size) fwd++;
    EXPECT_EQ(fwd, 0);
}
TEST(apv_exp_all_function_rvas_nonzero_and_in_text) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions);
    int bad = 0;
    for (DWORD i = 0; i < e->NumberOfFunctions; i++) {
        const IMAGE_SECTION_HEADER *s = funcs[i] ? apv_section_of_rva(m, funcs[i]) : NULL;
        if (!s || strncmp((const char *)s->Name, ".text", 8)) bad++;
    }
    EXPECT_EQ(bad, 0);
}
TEST(apv_exp_function_rvas_may_alias) {
    /* The linker folds identical function bodies (the reference build has 51 distinct addresses for 56
     * exports), so distinct addresses are NOT guaranteed; only record the count. */
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions);
    int distinct = 0;
    for (DWORD i = 0; i < e->NumberOfFunctions; i++) { int dup = 0; for (DWORD j = 0; j < i; j++) if (funcs[j] == funcs[i]) dup = 1; distinct += !dup; }
    t_note("%d distinct export addresses for %lu exports", distinct, (unsigned long)e->NumberOfFunctions);
    CHECK(distinct >= 1);
}
TEST(apv_exp_rvas_vs_reference_build) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    static const DWORD ref[N_EXPORTS] = { APV_EXPORT_RVAS };
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions);
    int diffs = 0;
    for (DWORD i = 0; i < e->NumberOfFunctions && i < N_EXPORTS; i++) if (funcs[i] != ref[i]) diffs++;
    t_note("%d export RVAs differ from reference build 10.0.19041.2913 (expected for other servicing levels)", diffs);
}
TEST(apv_exp_table_matches_reference_list) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    static const char *const want[] = {
#define X(o, n) #n,
        APV_EXPORTS(X)
#undef X
    };
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames);
    int bad = 0;
    for (DWORD i = 0; i < e->NumberOfNames && i < N_EXPORTS; i++)
        if (strcmp((const char *)apv_rva(m, names[i]), want[i])) { bad++; t_note("export %lu is %s want %s", i + 1, (const char *)apv_rva(m, names[i]), want[i]); }
    EXPECT_EQ(bad, 0);
}
TEST(apv_exp_loader_enumeration_names_are_all_resolvable) {
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames);
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions);
    const WORD *ords = (const WORD *)apv_rva(m, e->AddressOfNameOrdinals);
    int bad = 0;
    for (DWORD i = 0; i < e->NumberOfNames; i++) {
        FARPROC p = GetProcAddress(m, (const char *)apv_rva(m, names[i]));
        if ((const BYTE *)p != (const BYTE *)m + funcs[ords[i]]) bad++;
    }
    EXPECT_EQ(bad, 0);
}

/* ---- per-export tests ------------------------------------------------------ */
#define EXPORT_TESTS(ord, nm) \
TEST(apv_exp_by_name_##nm) { \
    APV_REQUIRE_MOD(m); \
    SET_ERR(0); \
    FARPROC p = GetProcAddress(m, #nm); \
    CHECK(p != NULL); \
    if (!p) return; \
    const IMAGE_NT_HEADERS64 *nt = apv_nt(m); \
    CHECK((BYTE *)p >= (BYTE *)m && (BYTE *)p < (BYTE *)m + nt->OptionalHeader.SizeOfImage); \
    MEMORY_BASIC_INFORMATION mbi; \
    CHECK(VirtualQuery(p, &mbi, sizeof mbi) != 0); \
    EXPECT_EQ(mbi.Type, MEM_IMAGE); \
    EXPECT_EQ(mbi.AllocationBase, m); \
    DWORD pr = mbi.Protect & 0xFF; \
    CHECK(pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_WRITECOPY || pr == PAGE_EXECUTE_READWRITE); \
} \
TEST(apv_exp_by_ordinal_##nm) { \
    APV_REQUIRE_MOD(m); \
    FARPROC byname = GetProcAddress(m, #nm); \
    FARPROC byord = GetProcAddress(m, MAKEINTRESOURCEA(ord)); \
    CHECK(byname != NULL); \
    EXPECT_EQ(byord, byname); \
} \
TEST(apv_exp_table_entry_##nm) { \
    APV_REQUIRE_MOD(m); \
    const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m); \
    CHECK(e != NULL); if (!e) return; \
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames); \
    const DWORD *funcs = (const DWORD *)apv_rva(m, e->AddressOfFunctions); \
    const WORD *ords = (const WORD *)apv_rva(m, e->AddressOfNameOrdinals); \
    DWORD i = (ord) - 1; \
    CHECK(i < e->NumberOfNames); if (i >= e->NumberOfNames) return; \
    EXPECT_STR((const char *)apv_rva(m, names[i]), #nm); \
    EXPECT_EQ(ords[i] + e->Base, (ord)); \
    EXPECT_EQ((BYTE *)m + funcs[ords[i]], (BYTE *)GetProcAddress(m, #nm)); \
} \
TEST(apv_exp_case_and_suffix_sensitive_##nm) { \
    APV_REQUIRE_MOD(m); \
    char lo[128], up[128], ext[128]; \
    size_t n = strlen(#nm); \
    for (size_t i = 0; i <= n; i++) { lo[i] = (char)((#nm)[i] >= 'A' && (#nm)[i] <= 'Z' ? (#nm)[i] + 32 : (#nm)[i]); up[i] = (char)((#nm)[i] >= 'a' && (#nm)[i] <= 'z' ? (#nm)[i] - 32 : (#nm)[i]); } \
    snprintf(ext, sizeof ext, "%sX", #nm); \
    SET_ERR(0); CHECK(GetProcAddress(m, lo) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); \
    SET_ERR(0); CHECK(GetProcAddress(m, up) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); \
    SET_ERR(0); CHECK(GetProcAddress(m, ext) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); \
    SET_ERR(0); CHECK(GetProcAddress(m, #nm + 1) == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND); \
}
APV_EXPORTS(EXPORT_TESTS)

/* ---- getmodulehandleex from every export address -------------------------- */
TEST(apv_exp_addresses_map_back_to_module) {
    APV_REQUIRE_MOD(m);
    int bad = 0;
#define X(o, n) { FARPROC p = GetProcAddress(m, #n); HMODULE h = NULL; \
        if (!p || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p, &h) || h != m) bad++; }
    APV_EXPORTS(X)
#undef X
    EXPECT_EQ(bad, 0);
}

/* ---- names/ordinals that must NOT resolve -------------------------------- */
TEST(apv_exp_ordinal_out_of_range) {
    APV_REQUIRE_MOD(m);
    static const WORD ords[] = { 57, 58, 64, 100, 255, 256, 1000, 0x7FFF, 0xFFFE, 0xFFFF };
    for (unsigned i = 0; i < sizeof ords / sizeof *ords; i++) {
        SET_ERR(0);
        FARPROC p = GetProcAddress(m, MAKEINTRESOURCEA(ords[i]));
        CHECKF(p == NULL, "ordinal %u resolved", ords[i]);
        EXPECT_ERR(ERROR_INVALID_ORDINAL);  /* 182 on Windows 10 22H2 (not 127) */
    }
}
TEST(apv_exp_ordinal_zero_does_not_resolve) {
    /* MAKEINTRESOURCE(0) is a NULL name pointer. */
    APV_REQUIRE_MOD(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, MAKEINTRESOURCEA(0)) == NULL);
    t_note("GetProcAddress(webauthn, NULL) last error %lu", GetLastError());
}
TEST(apv_exp_empty_name) {
    APV_REQUIRE_MOD(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(apv_exp_absent_standard_com_and_inf_exports) {
    /* webauthn.dll is neither a COM server nor a self-registering DLL, and has no DllMain export. */
    APV_REQUIRE_MOD(m);
    static const char *const absent[] = { "DllMain", "DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer", "DllUnregisterServer",
        "DllInstall", "DllEntryPoint", "_DllMainCRTStartup", "entry", "DllGetActivationFactory" };
    for (unsigned i = 0; i < sizeof absent / sizeof *absent; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(m, absent[i]) == NULL, "%s resolved", absent[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(apv_exp_absent_later_api_levels) {
    /* Entry points introduced by later WebAuthN API versions are not in this build. */
    APV_REQUIRE_MOD(m);
    static const char *const absent[] = { "WebAuthNGetPlatformCredentialList", "WebAuthNFreePlatformCredentialList",
        "WebAuthNGetAuthenticatorList", "WebAuthNFreeAuthenticatorList", "WebAuthNGetClientCapabilities",
        "WebAuthNFreeClientCapabilities", "WebAuthNGetUserVerifyingPlatformAuthenticatorAvailable",
        "WebAuthNDeletePlatformCredentialByRpId", "WebAuthNAuthenticatorMakeCredentialEx", "WebAuthNAuthenticatorGetAssertionEx" };
    for (unsigned i = 0; i < sizeof absent / sizeof *absent; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(m, absent[i]) == NULL, "%s resolved", absent[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(apv_exp_absent_kernel_names_not_forwarded) {
    APV_REQUIRE_MOD(m);
    static const char *const absent[] = { "CreateFileW", "LoadLibraryA", "GetProcAddress", "NtClose", "BCryptOpenAlgorithmProvider", "NCryptOpenStorageProvider" };
    for (unsigned i = 0; i < sizeof absent / sizeof *absent; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(m, absent[i]) == NULL, "%s resolved", absent[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}
TEST(apv_exp_getprocaddress_null_module_null_name) {
    SET_ERR(0);
    CHECK(GetProcAddress(NULL, NULL) == NULL);
}
TEST(apv_exp_getprocaddress_via_second_loadlibrary_handle_equal) {
    APV_REQUIRE_MOD(m);
    HMODULE m2 = LoadLibraryW(L"webauthn.dll");
    CHECK(m2 == m);
    if (m2) { CHECK(GetProcAddress(m2, "WebAuthNGetApiVersionNumber") == GetProcAddress(m, "WebAuthNGetApiVersionNumber")); FreeLibrary(m2); }
}
TEST(apv_exp_internal_names_have_prefix_convention) {
    /* Documented public entry points are WebAuthN*; the I_* ones are internal RPC encode/decode helpers
     * and CryptsvcDllCtrl / VirtualChannelGetInstance are service/terminal-services hooks. */
    APV_REQUIRE_MOD(m); const IMAGE_EXPORT_DIRECTORY *e = apv_expdir(m);
    CHECK(e != NULL); if (!e) return;
    const DWORD *names = (const DWORD *)apv_rva(m, e->AddressOfNames);
    int webauthn = 0, internal = 0, other = 0;
    for (DWORD i = 0; i < e->NumberOfNames; i++) {
        const char *n = (const char *)apv_rva(m, names[i]);
        if (!strncmp(n, "WebAuthN", 8)) webauthn++; else if (!strncmp(n, "I_WebAuthN", 10)) internal++; else other++;
    }
    EXPECT_EQ(webauthn, 50);
    EXPECT_EQ(internal, 4);
    EXPECT_EQ(other, 2);
}
