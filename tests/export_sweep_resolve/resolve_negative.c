/* Whole-DLL export sweep, part 2: GetProcAddress failure modes against the webauthn.dll export table,
 * and the one export that is safe to call without arguments (WebAuthNGetApiVersionNumber). */
#include "sweep.h"

#define ERR_PNF ERROR_PROC_NOT_FOUND   /* 127: STATUS_PROCEDURE_NOT_FOUND mapped by the loader */

/* ---- ordinals outside 1..56 -------------------------------------------- */
static void ord_fails(unsigned ord) {
    SW_NEED_MODULE();
    SET_ERR(0);
    FARPROC p = GetProcAddress(h, (LPCSTR)(ULONG_PTR)ord);
    CHECKF(p == NULL, "ordinal %u resolved", ord);
    EXPECT_ERR(ERR_PNF);
}
#define ORD_TEST(n) TEST(export_sweep_resolve_ordinal_##n##_not_found) { ord_fails(n); }
ORD_TEST(57) ORD_TEST(58) ORD_TEST(60) ORD_TEST(64) ORD_TEST(100) ORD_TEST(255) ORD_TEST(256)
ORD_TEST(1000) ORD_TEST(4096) ORD_TEST(32767) ORD_TEST(32768) ORD_TEST(65534) ORD_TEST(65535)

TEST(export_sweep_resolve_ordinal_0_fails) {
    SW_NEED_MODULE();
    SET_ERR(0);
    FARPROC p = GetProcAddress(h, (LPCSTR)(ULONG_PTR)0);
    CHECK(p == NULL);
    DWORD e = GetLastError();
    CHECKF(e == ERROR_PROC_NOT_FOUND || e == ERROR_INVALID_PARAMETER, "ordinal 0 error %lu", (unsigned long)e);
    t_note("GetProcAddress(webauthn, ordinal 0) -> NULL, GetLastError=%lu", (unsigned long)e);
}
TEST(export_sweep_resolve_name_null_fails) {
    SW_NEED_MODULE();
    SET_ERR(0);
    FARPROC p = GetProcAddress(h, NULL);
    CHECK(p == NULL);
    DWORD e = GetLastError();
    CHECKF(e == ERROR_PROC_NOT_FOUND || e == ERROR_INVALID_PARAMETER, "NULL name error %lu", (unsigned long)e);
    t_note("GetProcAddress(webauthn, NULL) GetLastError=%lu", (unsigned long)e);
}
TEST(export_sweep_resolve_ordinal_0_same_as_null_name) {
    SW_NEED_MODULE();
    SET_ERR(0); GetProcAddress(h, NULL); DWORD a = GetLastError();
    SET_ERR(0); GetProcAddress(h, (LPCSTR)(ULONG_PTR)0); DWORD b = GetLastError();
    EXPECT_EQ(a, b);      /* a NULL name pointer is ordinal 0 */
}
TEST(export_sweep_resolve_null_module_null_name_fails) {
    SET_ERR(0);
    FARPROC p = GetProcAddress(NULL, NULL);
    CHECK(p == NULL);
    t_note("GetProcAddress(NULL,NULL) GetLastError=%lu", (unsigned long)GetLastError());
}
TEST(export_sweep_resolve_null_module_valid_name_fails) {
    SW_NEED_MODULE();
    SET_ERR(0);
    FARPROC p = GetProcAddress(NULL, "WebAuthNGetApiVersionNumber");
    CHECK(p == NULL);
    DWORD e = GetLastError();
    CHECK(e != 0);
    t_note("GetProcAddress(NULL, valid name) GetLastError=%lu", (unsigned long)e);
}
TEST(export_sweep_resolve_null_module_valid_ordinal_fails) {
    SW_NEED_MODULE();
    SET_ERR(0);
    CHECK(GetProcAddress(NULL, (LPCSTR)(ULONG_PTR)49) == NULL);
}

/* ---- names that are not exports ------------------------------------------ */
static void name_fails(const char *name) {
    SW_NEED_MODULE();
    SET_ERR(0);
    FARPROC p = GetProcAddress(h, name);
    CHECKF(p == NULL, "\"%s\" resolved", name);
    EXPECT_ERR(ERR_PNF);
}
#define NAME_TEST(id, s) TEST(export_sweep_resolve_unexported_##id) { name_fails(s); }
NAME_TEST(empty, "")
NAME_TEST(dllmain, "DllMain")
NAME_TEST(dllgetclassobject, "DllGetClassObject")
NAME_TEST(dllcanunloadnow, "DllCanUnloadNow")
NAME_TEST(dllregisterserver, "DllRegisterServer")
NAME_TEST(dllunregisterserver, "DllUnregisterServer")
NAME_TEST(dllinstall, "DllInstall")
NAME_TEST(star, "*")
NAME_TEST(prefix_wildcard, "WebAuthN*")
NAME_TEST(webauthn_only, "WebAuthN")
NAME_TEST(webauthn_make_credential_short, "WebAuthNMakeCredential")
NAME_TEST(webauthn_get_assertion_short, "WebAuthNGetAssertion")
NAME_TEST(public_header_make_credential_a, "WebAuthNAuthenticatorMakeCredentialA")
NAME_TEST(public_header_get_credential_list, "WebAuthNGetPlatformCredentialList")
NAME_TEST(public_header_free_credential_list, "WebAuthNFreePlatformCredentialList")
NAME_TEST(public_header_get_api_v2, "WebAuthNGetApiVersionNumber2")
NAME_TEST(ordinal_style_hash, "#49")
NAME_TEST(ordinal_style_at, "@49")
NAME_TEST(ncrypt_name, "NCryptOpenStorageProvider")
NAME_TEST(bcrypt_name, "BCryptGenRandom")
NAME_TEST(kernel32_name, "CreateFileW")
NAME_TEST(ntdll_name, "NtClose")
NAME_TEST(module_prefix, "webauthn.WebAuthNGetApiVersionNumber")
NAME_TEST(module_prefix_dll, "webauthn.dll.WebAuthNGetApiVersionNumber")
NAME_TEST(module_prefix_slash, "webauthn.dll\\WebAuthNGetApiVersionNumber")
NAME_TEST(leading_tab, "\tWebAuthNGetApiVersionNumber")
NAME_TEST(trailing_newline, "WebAuthNGetApiVersionNumber\n")
NAME_TEST(high_ascii_suffix, "WebAuthNGetApiVersionNumber\xE9")
NAME_TEST(high_ascii_only, "\xFF\xFE")

TEST(export_sweep_resolve_unexported_long_name) {
    SW_NEED_MODULE();
    char buf[1025]; memset(buf, 'A', sizeof buf - 1); buf[sizeof buf - 1] = 0;
    SET_ERR(0);
    CHECK(GetProcAddress(h, buf) == NULL);
    t_note("1024-char name GetLastError=%lu", (unsigned long)GetLastError());
}
TEST(export_sweep_resolve_unexported_long_prefix_of_real_name) {
    SW_NEED_MODULE();
    char buf[1100]; memset(buf, 0, sizeof buf);
    strcpy(buf, "WebAuthNGetApiVersionNumber"); memset(buf + strlen(buf), 'x', 1000);
    SET_ERR(0);
    CHECK(GetProcAddress(h, buf) == NULL);
}
TEST(export_sweep_resolve_failed_lookup_does_not_poison_later_lookup) {
    SW_NEED_MODULE();
    CHECK(GetProcAddress(h, "NoSuchExport_xyz") == NULL);
    CHECK(GetProcAddress(h, (LPCSTR)(ULONG_PTR)9999) == NULL);
    CHECK(GetProcAddress(h, "WebAuthNGetApiVersionNumber") != NULL);
    CHECK(GetProcAddress(h, (LPCSTR)(ULONG_PTR)49) != NULL);
}
TEST(export_sweep_resolve_every_other_module_export_name_absent) {
    SW_NEED_MODULE();
    /* bcrypt / ncrypt / kernel32 exports are never re-exported by webauthn.dll */
    static const char *const names[] = { "BCryptHash", "BCryptOpenAlgorithmProvider", "NCryptCreatePersistedKey",
        "NCryptFreeObject", "LoadLibraryW", "GetProcAddress", "RtlNtStatusToDosError", "HeapAlloc", "CoTaskMemFree", "malloc", "free", "memcpy" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, names[i]) == NULL, "%s", names[i]);
        EXPECT_ERR(ERR_PNF);
    }
}

TEST(export_sweep_resolve_datafile_handle_has_no_exports) {
    SW_NEED_MODULE();
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(h, path, sizeof path);
    CHECK(n > 0 && n < sizeof path); if (!n) return;
    HMODULE d = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!d) { t_skip("cannot map as data file: %lu", (unsigned long)GetLastError()); return; }
    CHECK(((ULONG_PTR)d & 3) != 0);                       /* data-file handles carry tag bits */
    SET_ERR(0);
    FARPROC p = GetProcAddress(d, "WebAuthNGetApiVersionNumber");
    CHECK(p == NULL);
    t_note("GetProcAddress(datafile handle) GetLastError=%lu", (unsigned long)GetLastError());
    FreeLibrary(d);
    CHECK(GetProcAddress(h, "WebAuthNGetApiVersionNumber") != NULL);
}

TEST(export_sweep_resolve_loadlibrary_by_full_path_same_handle) {
    SW_NEED_MODULE();
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(h, path, sizeof path);
    CHECK(n > 0 && n < sizeof path); if (!n) return;
    HMODULE h2 = LoadLibraryA(path);
    EXPECT_EQ(h2, h);
    if (h2) FreeLibrary(h2);
    HMODULE h3 = LoadLibraryExA("webauthn.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    EXPECT_EQ(h3, h);
    if (h3) FreeLibrary(h3);
}

TEST(export_sweep_resolve_getmodulehandleex_pin_and_address) {
    SW_NEED_MODULE();
    HMODULE m = NULL;
    FARPROC p = GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &m));
    EXPECT_EQ(m, h);
    for (int i = 0; i < SW_COUNT; i++) {
        m = NULL;
        CHECK(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)GetProcAddress(h, sw_exports[i].name), &m));
        EXPECT_EQ(m, h);
    }
}

/* ---- WebAuthNGetApiVersionNumber: no arguments, no UI, no device I/O ------ */
/* Decomp: asks the session whether it is a remote session; locally it returns the constant 2,
 * for a remoted session it returns min(remote version, 2) or 0 if the remote query failed. */
typedef DWORD (WINAPI *apiver_fn)(void);

TEST(export_sweep_resolve_apiversion_in_range) {
    SW_NEED_MODULE();
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    REQUIRE(f);
    DWORD v = f();
    CHECKF(v <= 2, "version %lu", (unsigned long)v);
    t_note("WebAuthNGetApiVersionNumber() = %lu", (unsigned long)v);
}
TEST(export_sweep_resolve_apiversion_stable_over_calls) {
    SW_NEED_MODULE();
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    REQUIRE(f);
    DWORD v = f();
    for (int i = 0; i < 1000; i++) if (f() != v) { CHECKF(0, "call %d changed result", i); break; }
}
TEST(export_sweep_resolve_apiversion_by_ordinal_matches) {
    SW_NEED_MODULE();
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    apiver_fn g = (apiver_fn)GetProcAddress(h, (LPCSTR)(ULONG_PTR)49);
    REQUIRE(f); REQUIRE(g);
    { DWORD a_ = f(), b_ = g(); EXPECT_EQ(a_, b_); };
}
TEST(export_sweep_resolve_apiversion_does_not_touch_last_error_contract) {
    SW_NEED_MODULE();
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    REQUIRE(f);
    SET_ERR(0xABCD);
    DWORD v = f();
    CHECK(v <= 2);
    t_note("GetLastError after WebAuthNGetApiVersionNumber = 0x%lx (sentinel was 0xabcd)", (unsigned long)GetLastError());
}
TEST(export_sweep_resolve_apiversion_ignores_stray_register_arguments) {
    SW_NEED_MODULE();
    /* declared as taking nothing; calling through a wider prototype must give the same answer on x64 */
    typedef DWORD (WINAPI *wide_fn)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
    wide_fn w = (wide_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    REQUIRE(w); REQUIRE(f);
    { DWORD a_ = w(0, 0, 0, 0), b_ = f(); EXPECT_EQ(a_, b_); };
}

static DWORD WINAPI apiver_thread(LPVOID p) {
    apiver_fn f = (apiver_fn)p; return f();
}
TEST(export_sweep_resolve_apiversion_same_on_other_thread) {
    SW_NEED_MODULE();
    apiver_fn f = (apiver_fn)GetProcAddress(h, "WebAuthNGetApiVersionNumber");
    REQUIRE(f);
    HANDLE th = CreateThread(NULL, 0, apiver_thread, (LPVOID)f, 0, NULL);
    CHECK(th != NULL); if (!th) return;
    CHECK(WaitForSingleObject(th, 10000) == WAIT_OBJECT_0);
    DWORD code = 0xFFFFFFFF; GetExitCodeThread(th, &code);
    { DWORD b_ = f(); EXPECT_EQ(code, b_); };
    CloseHandle(th);
}
