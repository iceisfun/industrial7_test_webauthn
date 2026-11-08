/* Loading, identity and lifetime of webauthn.dll: version resource (10.0.19041.x), file location
 * (System32), module-handle lookup rules, and DllMain attach/detach through load/unload cycles
 * (done in child processes where the module starts unloaded). */
#include "apv.h"

/* ---- version resource ------------------------------------------------------- */
static const BYTE *ver_data(HMODULE m, DWORD *size) {
    HRSRC r = FindResourceW(m, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    if (!r) return NULL;
    HGLOBAL g = LoadResource(m, r);
    if (!g) return NULL;
    *size = SizeofResource(m, r);
    return LockResource(g);
}
static const VS_FIXEDFILEINFO *ver_fixed(const BYTE *d, DWORD sz) {
    for (DWORD i = 0; i + sizeof(VS_FIXEDFILEINFO) <= sz && i < 128; i += 4)
        if (*(const DWORD *)(d + i) == 0xFEEF04BD) return (const VS_FIXEDFILEINFO *)(d + i);
    return NULL;
}
/* Value of a StringFileInfo string (UTF-16), or NULL. */
static const WCHAR *ver_string(const BYTE *d, DWORD sz, const WCHAR *key) {
    size_t kl = lstrlenW(key);
    for (DWORD i = 0; i + (kl + 1) * 2 < sz; i += 2) {
        if (memcmp(d + i, key, (kl + 1) * 2)) continue;
        DWORD v = (DWORD)(i + (kl + 1) * 2);
        v = (v + 3) & ~3u;
        return v < sz ? (const WCHAR *)(d + v) : NULL;
    }
    return NULL;
}
#define VER_REQUIRE(m, d, sz, f) \
    APV_REQUIRE_MOD(m); DWORD sz = 0; const BYTE *d = ver_data(m, &sz); \
    if (!d) { CHECK(d != NULL); return; } const VS_FIXEDFILEINFO *f = ver_fixed(d, sz); if (!f) { CHECK(f != NULL); return; }

TEST(apv_res_version_resource_exists) { APV_REQUIRE_MOD(m); DWORD sz = 0; CHECK(ver_data(m, &sz) != NULL && sz > 0x40); }
TEST(apv_res_fixed_signature) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(f->dwSignature, 0xFEEF04BD); EXPECT_EQ(f->dwStrucVersion, 0x00010000); }
TEST(apv_res_file_version_major_minor_10_0) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(f->dwFileVersionMS, 0x000A0000); }
TEST(apv_res_file_version_build_19041) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(HIWORD(f->dwFileVersionLS), 19041); }
TEST(apv_res_file_version_revision_note) { VER_REQUIRE(m, d, sz, f); t_note("file version 10.0.%u.%u", HIWORD(f->dwFileVersionLS), LOWORD(f->dwFileVersionLS)); CHECK(LOWORD(f->dwFileVersionLS) >= 1); }
TEST(apv_res_product_version_matches_file_version) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(f->dwProductVersionMS, f->dwFileVersionMS); EXPECT_EQ(HIWORD(f->dwProductVersionLS), HIWORD(f->dwFileVersionLS)); }
TEST(apv_res_file_os_nt_windows32) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(f->dwFileOS, VOS_NT_WINDOWS32); }
TEST(apv_res_file_type_dll) { VER_REQUIRE(m, d, sz, f); EXPECT_EQ(f->dwFileType, VFT_DLL); EXPECT_EQ(f->dwFileSubtype, 0); }
TEST(apv_res_file_flags_not_debug_or_prerelease) {
    VER_REQUIRE(m, d, sz, f);
    EXPECT_EQ(f->dwFileFlags & f->dwFileFlagsMask & (VS_FF_DEBUG | VS_FF_PRERELEASE), 0);
}
TEST(apv_res_os_build_not_older_than_dll_build) {
    VER_REQUIRE(m, d, sz, f);
    typedef LONG (WINAPI *rtlgetver_t)(OSVERSIONINFOW *);
    rtlgetver_t rv = (rtlgetver_t)t_proc_in("ntdll.dll", "RtlGetVersion");
    if (!rv) { t_skip("no RtlGetVersion"); return; }
    OSVERSIONINFOW vi = { sizeof vi };
    rv(&vi);
    t_note("OS %lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    if (t_is_wine()) { t_skip("emulator reports its own OS version"); return; }
    EXPECT_EQ(vi.dwMajorVersion, 10);
    CHECK(vi.dwBuildNumber >= HIWORD(f->dwFileVersionLS));
}
TEST(apv_res_string_original_filename) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"OriginalFilename");
    CHECK(s != NULL); if (s) CHECKF(!lstrcmpiW(s, L"WebAuthn.dll"), "OriginalFilename \"%ls\"", s);
}
TEST(apv_res_string_internal_name) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"InternalName");
    CHECK(s != NULL); if (s) CHECKF(!lstrcmpiW(s, L"WebAuthn.dll") || !lstrcmpiW(s, L"WebAuthn"), "InternalName \"%ls\"", s);
}
TEST(apv_res_string_company_microsoft) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"CompanyName");
    CHECK(s != NULL); if (s) CHECKF(!lstrcmpW(s, L"Microsoft Corporation"), "CompanyName \"%ls\"", s);
}
TEST(apv_res_string_file_version_prefix) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"FileVersion");
    CHECK(s != NULL); if (s) CHECKF(!wcsncmp(s, L"10.0.19041.", 11), "FileVersion \"%ls\"", s);
}
TEST(apv_res_string_product_version_prefix) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"ProductVersion");
    CHECK(s != NULL); if (s) CHECKF(!wcsncmp(s, L"10.0.19041.", 11), "ProductVersion \"%ls\"", s);
}
TEST(apv_res_string_file_version_matches_fixed_info) {
    VER_REQUIRE(m, d, sz, f);
    const WCHAR *s = ver_string(d, sz, L"FileVersion");
    CHECK(s != NULL); if (!s) return;
    WCHAR want[64];
    wsprintfW(want, L"%u.%u.%u.%u", HIWORD(f->dwFileVersionMS), LOWORD(f->dwFileVersionMS), HIWORD(f->dwFileVersionLS), LOWORD(f->dwFileVersionLS));
    CHECK(!wcsncmp(s, want, lstrlenW(want)));
}
TEST(apv_res_string_descriptive_fields_note) {
    VER_REQUIRE(m, d, sz, f);
    static const WCHAR *const keys[] = { L"FileDescription", L"ProductName", L"LegalCopyright", L"FileVersion" };
    for (int i = 0; i < 4; i++) { const WCHAR *s = ver_string(d, sz, keys[i]); t_note("%ls = %ls", keys[i], s ? s : L"(none)"); }
}
TEST(apv_res_datafile_load_gives_same_version) {
    VER_REQUIRE(m, d, sz, f);
    WCHAR path[MAX_PATH];
    if (!GetModuleFileNameW(m, path, MAX_PATH)) { t_skip("no path"); return; }
    HMODULE df = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    CHECK(df != NULL); if (!df) return;
    DWORD sz2 = 0; const BYTE *d2 = ver_data(df, &sz2);
    CHECK(d2 != NULL);
    if (d2) { const VS_FIXEDFILEINFO *f2 = ver_fixed(d2, sz2); CHECK(f2 && f2->dwFileVersionMS == f->dwFileVersionMS && f2->dwFileVersionLS == f->dwFileVersionLS); }
    FreeLibrary(df);
}
TEST(apv_res_datafile_load_is_not_the_image_handle) {
    APV_REQUIRE_MOD(m);
    WCHAR path[MAX_PATH];
    if (!GetModuleFileNameW(m, path, MAX_PATH)) { t_skip("no path"); return; }
    HMODULE df = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    CHECK(df != NULL);
    /* An already-loaded image is returned as is (same handle); otherwise a data mapping has low tag bits set. */
    if (df) t_note("datafile handle %s the image handle", df == m ? "equals" : "differs from");
    if (df) {
        SET_ERR(0);
        CHECK(GetModuleHandleW(L"webauthn.dll") == m);
        FreeLibrary(df);
    }
}
TEST(apv_res_string_table_resources_note) {
    APV_REQUIRE_MOD(m);
    WCHAR buf[256]; int found = 0;
    for (UINT id = 1; id < 2000 && found < 3; id++) if (LoadStringW(m, id, buf, 256) > 0) { found++; }
    t_note("webauthn.dll has string resources among ids 1..1999: at least %d found", found);
}
TEST(apv_res_version_resource_language_note) {
    APV_REQUIRE_MOD(m);
    HRSRC r = FindResourceW(m, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));
    CHECK(r != NULL);
    HRSRC r0 = FindResourceExW(m, MAKEINTRESOURCEW(16), MAKEINTRESOURCEW(1), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
    HRSRC r9 = FindResourceExW(m, MAKEINTRESOURCEW(16), MAKEINTRESOURCEW(1), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    t_note("version resource neutral:%d en-US:%d", r0 != NULL, r9 != NULL);
}

/* ---- file name and location ------------------------------------------------- */
static void sysdir_path(WCHAR *out) { GetSystemDirectoryW(out, MAX_PATH); lstrcatW(out, L"\\webauthn.dll"); }
TEST(apv_file_module_file_name_w_is_system32) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH], want[MAX_PATH];
    DWORD n = GetModuleFileNameW(m, p, MAX_PATH);
    CHECK(n > 0 && n < MAX_PATH);
    sysdir_path(want);
    if (t_is_wine()) { t_note("emulator path %ls", p); return; }
    CHECKF(!lstrcmpiW(p, want), "path \"%ls\" want \"%ls\"", p, want);
}
TEST(apv_file_module_file_name_a_matches_w) {
    APV_REQUIRE_MOD(m);
    WCHAR w[MAX_PATH]; char a[MAX_PATH], a2[MAX_PATH];
    DWORD nw = GetModuleFileNameW(m, w, MAX_PATH), na = GetModuleFileNameA(m, a, MAX_PATH);
    CHECK(nw && nw == na);
    WideCharToMultiByte(CP_ACP, 0, w, -1, a2, MAX_PATH, NULL, NULL);
    EXPECT_STR(a, a2);
}
TEST(apv_file_path_is_in_windows_directory_tree) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH], win[MAX_PATH];
    GetModuleFileNameW(m, p, MAX_PATH); GetWindowsDirectoryW(win, MAX_PATH);
    if (t_is_wine()) { t_skip("emulator"); return; }
    CHECK(!_wcsnicmp(p, win, lstrlenW(win)));
}
TEST(apv_file_path_has_drive_letter_form) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH]; GetModuleFileNameW(m, p, MAX_PATH);
    CHECK(((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && p[2] == '\\');
}
TEST(apv_file_path_leaf_is_webauthn_dll) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH]; GetModuleFileNameW(m, p, MAX_PATH);
    WCHAR *leaf = wcsrchr(p, L'\\'); CHECK(leaf != NULL);
    if (leaf) CHECK(!lstrcmpiW(leaf + 1, L"webauthn.dll"));
}
TEST(apv_file_path_exists_and_size_matches_image) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH]; GetModuleFileNameW(m, p, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA fa;
    CHECK(GetFileAttributesExW(p, GetFileExInfoStandard, &fa));
    const IMAGE_SECTION_HEADER *last = apv_section_named(m, ".reloc");
    CHECK(last != NULL);
    if (last) {
        CHECK(fa.nFileSizeLow >= last->PointerToRawData + last->SizeOfRawData);
        t_note("file size %lu, end of last section %lu (difference is an embedded signature, if any)", fa.nFileSizeLow, last->PointerToRawData + last->SizeOfRawData);
    }
}
TEST(apv_file_module_file_name_w_small_buffer_protocol) {
    APV_REQUIRE_MOD(m);
    WCHAR full[MAX_PATH]; DWORD n = GetModuleFileNameW(m, full, MAX_PATH);
    for (DWORD size = 1; size < 8 && size < n; size++) {
        WCHAR b[16]; memset(b, 0xAA, sizeof b);
        SET_ERR(0);
        DWORD r = GetModuleFileNameW(m, b, size);
        CHECKF(r == size, "size %lu returned %lu", size, r);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        CHECK(b[size - 1] == 0);
        CHECK(b[size] == 0xAAAA);
    }
}
TEST(apv_file_module_file_name_w_exact_and_exact_plus_one) {
    APV_REQUIRE_MOD(m);
    WCHAR full[MAX_PATH]; DWORD n = GetModuleFileNameW(m, full, MAX_PATH);
    WCHAR b[MAX_PATH];
    SET_ERR(0);
    DWORD r = GetModuleFileNameW(m, b, n + 1);
    EXPECT_EQ(r, n);
    EXPECT_ERR(0);
    CHECK(!lstrcmpW(b, full));
    SET_ERR(0);
    r = GetModuleFileNameW(m, b, n);
    EXPECT_EQ(r, n);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    CHECK(b[n - 1] == 0);
}
TEST(apv_file_module_file_name_a_small_buffer_returns_size) {
    APV_REQUIRE_MOD(m);
    char b[16];
    SET_ERR(0);
    DWORD r = GetModuleFileNameA(m, b, 5);
    EXPECT_EQ(r, 5);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
}
TEST(apv_file_module_file_name_zero_size) {
    APV_REQUIRE_MOD(m);
    WCHAR b[4] = { 1, 1, 1, 1 };
    SET_ERR(0);
    DWORD r = GetModuleFileNameW(m, b, 0);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(b[0], 1);
}

/* ---- module handle lookup --------------------------------------------------- */
TEST(apv_hnd_by_name_dll) { APV_REQUIRE_MOD(m); EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m); }
TEST(apv_hnd_by_name_uppercase) { APV_REQUIRE_MOD(m); EXPECT_EQ(GetModuleHandleW(L"WEBAUTHN.DLL"), m); }
TEST(apv_hnd_by_name_mixed_case) { APV_REQUIRE_MOD(m); EXPECT_EQ(GetModuleHandleW(L"WebAuthn.Dll"), m); }
TEST(apv_hnd_by_name_without_extension) { APV_REQUIRE_MOD(m); EXPECT_EQ(GetModuleHandleW(L"webauthn"), m); }
TEST(apv_hnd_by_name_ansi) { APV_REQUIRE_MOD(m); EXPECT_EQ(GetModuleHandleA("webauthn.dll"), m); }
TEST(apv_hnd_by_full_path) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH]; GetModuleFileNameW(m, p, MAX_PATH);
    EXPECT_EQ(GetModuleHandleW(p), m);
}
TEST(apv_hnd_by_name_with_trailing_dot_is_not_found) {
    /* A trailing dot means "no extension": the name is taken literally and does not match webauthn.dll. */
    APV_REQUIRE_MOD(m);
    SET_ERR(0);
    CHECK(GetModuleHandleW(L"webauthn.") == NULL);
    EXPECT_ERR(ERROR_MOD_NOT_FOUND);
}
TEST(apv_hnd_unknown_name_not_found) {
    SET_ERR(0);
    CHECK(GetModuleHandleW(L"webauthn_no_such_module.dll") == NULL);
    EXPECT_ERR(ERROR_MOD_NOT_FOUND);
}
TEST(apv_hnd_loadlibrary_returns_same_handle) {
    APV_REQUIRE_MOD(m);
    HMODULE a = LoadLibraryW(L"webauthn.dll"), b = LoadLibraryA("WebAuthn.dll");
    EXPECT_EQ(a, m); EXPECT_EQ(b, m);
    if (a) FreeLibrary(a);
    if (b) FreeLibrary(b);
}
TEST(apv_hnd_loadlibrary_without_extension) {
    APV_REQUIRE_MOD(m);
    HMODULE a = LoadLibraryW(L"webauthn");
    EXPECT_EQ(a, m);
    if (a) FreeLibrary(a);
}
TEST(apv_hnd_loadlibrary_full_path) {
    APV_REQUIRE_MOD(m);
    WCHAR p[MAX_PATH]; GetModuleFileNameW(m, p, MAX_PATH);
    HMODULE a = LoadLibraryW(p);
    EXPECT_EQ(a, m);
    if (a) FreeLibrary(a);
}
TEST(apv_hnd_loadlibraryex_search_system32) {
    APV_REQUIRE_MOD(m);
    HMODULE a = LoadLibraryExW(L"webauthn.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    EXPECT_EQ(a, m);
    if (a) FreeLibrary(a);
}
TEST(apv_hnd_getmodulehandleex_from_address) {
    APV_REQUIRE_MOD(m);
    HMODULE h = NULL;
    FARPROC p = GetProcAddress(m, "WebAuthNGetApiVersionNumber");
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)p, &h));
    EXPECT_EQ(h, m);
}
TEST(apv_hnd_getmodulehandleex_by_name_unchanged_refcount) {
    APV_REQUIRE_MOD(m);
    HMODULE h = NULL;
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"webauthn.dll", &h));
    EXPECT_EQ(h, m);
}
TEST(apv_hnd_getmodulehandleex_adds_reference_balanced_by_freelibrary) {
    APV_REQUIRE_MOD(m);
    HMODULE h = NULL;
    CHECK(GetModuleHandleExW(0, L"webauthn.dll", &h));
    EXPECT_EQ(h, m);
    if (h) CHECK(FreeLibrary(h));
    EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m);
}
TEST(apv_hnd_pointer_inside_image_resolves_to_module_even_for_data) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".rdata");
    CHECK(s != NULL); if (!s) return;
    HMODULE h = NULL;
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)((BYTE *)m + s->VirtualAddress + 16), &h));
    EXPECT_EQ(h, m);
}
TEST(apv_hnd_freelibrary_balanced_extra_refs) {
    APV_REQUIRE_MOD(m);
    for (int i = 0; i < 50; i++) CHECK(LoadLibraryW(L"webauthn.dll") == m);
    for (int i = 0; i < 50; i++) CHECK(FreeLibrary(m));
    EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m);
    CHECK(GetProcAddress(m, "WebAuthNGetApiVersionNumber") != NULL);
}
TEST(apv_hnd_dependencies_loaded_in_process) {
    /* Static imports (bcrypt.dll, ntdll.dll, msvcp_win.dll) are mapped before webauthn.dll's DllMain runs. */
    APV_REQUIRE_MOD(m);
    CHECK(GetModuleHandleW(L"bcrypt.dll") != NULL);
    CHECK(GetModuleHandleW(L"ntdll.dll") != NULL);
    if (!t_is_wine()) CHECK(GetModuleHandleW(L"msvcp_win.dll") != NULL);
}

/* ---- load/unload cycles in a fresh process ---------------------------------- */
/* Child exit codes: 0 ok, 1 initial state, 2 load, 3 resolve, 4 version mismatch, 5 free, 6 nesting, 7 missing deps, 9 thread */
CHILD(apv_cycle) {
    int rounds = argc > 1 ? atoi(argv[1]) : 50;
    if (GetModuleHandleW(L"webauthn.dll")) { printf("NOTE module already loaded at child start\n"); }
    DWORD expect = 0xFFFFFFFF; int unloaded = 0;
    for (int i = 0; i < rounds; i++) {
        HMODULE m = LoadLibraryW(L"webauthn.dll");
        if (!m) return 2;
        apv_getver_fn f = (apv_getver_fn)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
        if (!f) return 3;
        DWORD v = f();
        if (expect == 0xFFFFFFFF) expect = v; else if (v != expect) return 4;
        if (v > 2) return 4;
        if (!FreeLibrary(m)) return 5;
        if (!GetModuleHandleW(L"webauthn.dll")) unloaded++;
    }
    printf("NOTE apv_cycle: module unloaded after %d of %d FreeLibrary calls\n", unloaded, rounds);
    return 0;
}
TEST(apv_life_load_free_50_cycles) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_cycle", "50", 60000), 0); }
TEST(apv_life_load_free_1_cycle) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_cycle", "1", 30000), 0); }
TEST(apv_life_load_free_200_cycles) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_cycle", "200", 120000), 0); }

CHILD(apv_nest) {
    int depth = argc > 1 ? atoi(argv[1]) : 50;
    HMODULE first = NULL;
    for (int i = 0; i < depth; i++) {
        HMODULE m = LoadLibraryW(L"webauthn.dll");
        if (!m) return 2;
        if (!first) first = m; else if (m != first) return 6;
    }
    for (int i = 0; i < depth - 1; i++) {
        if (!FreeLibrary(first)) return 5;
        if (GetModuleHandleW(L"webauthn.dll") != first) return 6;      /* still referenced */
    }
    apv_getver_fn f = (apv_getver_fn)GetProcAddress(first, "WebAuthNGetApiVersionNumber");
    if (!f) return 3;
    f();
    if (!FreeLibrary(first)) return 5;
    printf("NOTE apv_nest: module %s after last FreeLibrary\n", GetModuleHandleW(L"webauthn.dll") ? "still mapped" : "unloaded");
    return 0;
}
TEST(apv_life_nested_refcount_50) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_nest", "50", 60000), 0); }
TEST(apv_life_nested_refcount_2) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_nest", "2", 30000), 0); }

CHILD(apv_reload_after_unload) {
    HMODULE a = LoadLibraryW(L"webauthn.dll");
    if (!a) return 2;
    apv_getver_fn f = (apv_getver_fn)GetProcAddress(a, "WebAuthNGetApiVersionNumber");
    DWORD v1 = f ? f() : 0xFFFF;
    if (!FreeLibrary(a)) return 5;
    HMODULE b = LoadLibraryW(L"webauthn.dll");
    if (!b) return 2;
    f = (apv_getver_fn)GetProcAddress(b, "WebAuthNGetApiVersionNumber");
    if (!f) return 3;
    if (f() != v1) return 4;
    /* The security cookie is re-initialised by every attach; the dll must be fully usable. */
    apv_iuvpaa_fn g = (apv_iuvpaa_fn)GetProcAddress(b, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
    BOOL x = 5;
    if (!g || g(&x) != S_OK || (unsigned)x > 1) return 8;
    return FreeLibrary(b) ? 0 : 5;
}
TEST(apv_life_reload_after_unload_fully_usable) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_reload_after_unload", "", 60000), 0); }

CHILD(apv_deps) {
    if (!LoadLibraryW(L"webauthn.dll")) return 2;
    if (!GetModuleHandleW(L"bcrypt.dll")) return 7;
    if (!GetModuleHandleW(L"ntdll.dll")) return 7;
    if (!GetModuleHandleW(L"msvcp_win.dll")) return 7;
    return 0;
}
TEST(apv_life_static_dependencies_loaded_with_dll) { APV_REQUIRE_MOD(m); if (t_is_wine()) { t_skip("emulator"); return; } EXPECT_EQ(t_run_child("apv_deps", "", 30000), 0); }

CHILD(apv_dep_not_loaded_before) {
    /* webauthn.dll must not be pulled in by anything else at process start. */
    return GetModuleHandleW(L"webauthn.dll") == NULL ? 0 : 1;
}
TEST(apv_life_not_loaded_in_fresh_process) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_dep_not_loaded_before", "", 30000), 0); }

static volatile LONG g_thr_fail;
static DWORD WINAPI cycle_thread(LPVOID p) {
    for (int i = 0; i < 25; i++) {
        HMODULE m = LoadLibraryW(L"webauthn.dll");
        if (!m) { InterlockedIncrement(&g_thr_fail); continue; }
        apv_getver_fn f = (apv_getver_fn)GetProcAddress(m, "WebAuthNGetApiVersionNumber");
        if (!f || f() > 2) InterlockedIncrement(&g_thr_fail);
        if (!FreeLibrary(m)) InterlockedIncrement(&g_thr_fail);
    }
    return 0;
}
CHILD(apv_threaded_cycles) {
    HANDLE h[4];
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, cycle_thread, NULL, 0, NULL);
    for (int i = 0; i < 4; i++) { if (!h[i]) return 9; }
    if (WaitForMultipleObjects(4, h, TRUE, 40000) != WAIT_OBJECT_0) return 9;
    return g_thr_fail ? 4 : 0;
}
TEST(apv_life_concurrent_load_free_threads) { APV_REQUIRE_MOD(m); EXPECT_EQ(t_run_child("apv_threaded_cycles", "", 60000), 0); }

/* The in-process version of the same, with the harness reference keeping the module resident. */
TEST(apv_life_in_process_cycles_keep_module_resident) {
    APV_REQUIRE_MOD(m);
    for (int i = 0; i < 50; i++) {
        HMODULE h = LoadLibraryW(L"webauthn.dll");
        CHECK(h == m);
        CHECK(h && FreeLibrary(h));
    }
    EXPECT_EQ(GetModuleHandleW(L"webauthn.dll"), m);
    CHECK(GetProcAddress(m, "WebAuthNGetApiVersionNumber") != NULL);
}
TEST(apv_life_thread_attach_detach_stress) {
    /* 100 short-lived threads each run DLL_THREAD_ATTACH/DETACH through the loaded module. */
    APV_REQUIRE_MOD(m);
    int bad = 0;
    for (int i = 0; i < 100; i++) {
        HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetCurrentThreadId, NULL, 0, NULL);
        if (!h || !apv_join(h, 5000)) bad++;
    }
    EXPECT_EQ(bad, 0);
}
