/* (a) The export set a browser requires before it looks at the API version, and the version gating.
 * (f) Module facts, logged as NOTE rows (build dependent). */
#include "bs.h"
#include <stdlib.h>

static const char *const k_required[] = {   /* resolved by common browser integrations before use */
    "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable", "WebAuthNAuthenticatorMakeCredential",
    "WebAuthNFreeCredentialAttestation", "WebAuthNAuthenticatorGetAssertion", "WebAuthNFreeAssertion",
    "WebAuthNGetCancellationId", "WebAuthNCancelCurrentOperation", "WebAuthNGetErrorName",
    "WebAuthNGetApiVersionNumber", "WebAuthNGetW3CExceptionDOMError",
};
/* resolved only when the reported API version is high enough (platform credential list: version 4 and up) */
static const char *const k_version_gated[] = { "WebAuthNGetPlatformCredentialList", "WebAuthNFreePlatformCredentialList" };

TEST(bs_required_exports_resolve) {
    HMODULE m = bs_dll(); REQUIRE(m);
    for (unsigned i = 0; i < sizeof k_required / sizeof *k_required; i++)
        CHECKF(GetProcAddress(m, k_required[i]) != NULL, "%s", k_required[i]);
}
TEST(bs_required_exports_are_not_forwarders) {
    HMODULE m = bs_dll(); REQUIRE(m);
    const char *base = (const char *)m;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    for (unsigned i = 0; i < sizeof k_required / sizeof *k_required; i++) {
        const char *p = (const char *)GetProcAddress(m, k_required[i]);
        if (!p) continue;
        CHECKF(!(p >= base + dd->VirtualAddress && p < base + dd->VirtualAddress + dd->Size), "%s is a forwarder", k_required[i]);
    }
}
TEST(bs_api_version_decides_optional_exports) {
    HMODULE m = bs_dll(); REQUIRE(m);
    WebAuthNGetApiVersionNumber_pfn f = UN(WebAuthNGetApiVersionNumber); REQUIRE(f);
    DWORD v = f();
    t_note("api version %lu", (unsigned long)v);
    CHECK(v >= 1);   /* the lowest version a browser accepts */
    for (unsigned i = 0; i < sizeof k_version_gated / sizeof *k_version_gated; i++) {
        int present = GetProcAddress(m, k_version_gated[i]) != NULL;
        t_note("version-gated export %s present=%d (api version %lu)", k_version_gated[i], present, (unsigned long)v);
        if (v >= 4) CHECKF(present, "%s must exist at api version %lu", k_version_gated[i], (unsigned long)v);
    }
}
TEST(bs_api_version_is_stable) {
    WebAuthNGetApiVersionNumber_pfn f = UN(WebAuthNGetApiVersionNumber); REQUIRE(f);
    DWORD v = f();
    for (int i = 0; i < 50; i++) if (f() != v) { CHECK(0 && "api version changed between calls"); break; }
}

/* ---- (f) module facts ---- */
TEST(bs_module_export_count) {
    HMODULE m = bs_dll(); REQUIRE(m);
    const char *base = (const char *)m;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    CHECK(dd->VirtualAddress != 0);
    const IMAGE_EXPORT_DIRECTORY *ed = (const IMAGE_EXPORT_DIRECTORY *)(base + dd->VirtualAddress);
    t_note("exports: functions=%lu names=%lu ordinal_base=%lu", (unsigned long)ed->NumberOfFunctions, (unsigned long)ed->NumberOfNames, (unsigned long)ed->Base);
    t_note("image: size=0x%lx timestamp=0x%lx machine=0x%x sections=%u", (unsigned long)nt->OptionalHeader.SizeOfImage,
           (unsigned long)nt->FileHeader.TimeDateStamp, nt->FileHeader.Machine, nt->FileHeader.NumberOfSections);
    CHECK(ed->NumberOfNames <= ed->NumberOfFunctions);
}
TEST(bs_module_import_names) {
    HMODULE m = bs_dll(); REQUIRE(m);
    const char *base = (const char *)m;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    int n = 0;
    if (dd->VirtualAddress) {
        const IMAGE_IMPORT_DESCRIPTOR *d = (const IMAGE_IMPORT_DESCRIPTOR *)(base + dd->VirtualAddress);
        for (; d->Name; d++, n++) t_note("import: %s", base + d->Name);
    }
    const IMAGE_DATA_DIRECTORY *dl = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (dl->VirtualAddress) {
        const IMAGE_DELAYLOAD_DESCRIPTOR *d = (const IMAGE_DELAYLOAD_DESCRIPTOR *)(base + dl->VirtualAddress);
        for (; d->DllNameRVA; d++) t_note("delay-import: %s", base + d->DllNameRVA);
    }
    t_note("import descriptors: %d", n);
    CHECK(n > 0);
}

typedef DWORD (WINAPI *pGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef BOOL (WINAPI *pGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *pVerQueryValueA)(LPCVOID, LPCSTR, LPVOID *, PUINT);
TEST(bs_module_version_resource) {
    HMODULE m = bs_dll(); REQUIRE(m);
    char path[MAX_PATH * 2]; CHECK(GetModuleFileNameA(m, path, sizeof path) != 0);
    HMODULE v = LoadLibraryA("version.dll");
    if (!v) { t_skip("version.dll not loadable"); return; }
    pGetFileVersionInfoSizeA gs = (pGetFileVersionInfoSizeA)GetProcAddress(v, "GetFileVersionInfoSizeA");
    pGetFileVersionInfoA gi = (pGetFileVersionInfoA)GetProcAddress(v, "GetFileVersionInfoA");
    pVerQueryValueA q = (pVerQueryValueA)GetProcAddress(v, "VerQueryValueA");
    if (!gs || !gi || !q) { t_skip("version API missing"); return; }
    DWORD z; DWORD sz = gs(path, &z);
    CHECK(sz != 0);
    if (!sz) return;
    BYTE *buf = malloc(sz);
    if (!gi(path, 0, sz, buf)) { CHECK(0 && "GetFileVersionInfo"); free(buf); return; }
    VS_FIXEDFILEINFO *ff = NULL; UINT len = 0;
    if (q(buf, "\\", (LPVOID *)&ff, &len) && ff)
        t_note("file version %lu.%lu.%lu.%lu product %lu.%lu.%lu.%lu", ff->dwFileVersionMS >> 16, ff->dwFileVersionMS & 0xFFFF, ff->dwFileVersionLS >> 16, ff->dwFileVersionLS & 0xFFFF,
               ff->dwProductVersionMS >> 16, ff->dwProductVersionMS & 0xFFFF, ff->dwProductVersionLS >> 16, ff->dwProductVersionLS & 0xFFFF);
    static const char *const names[] = { "FileDescription", "InternalName", "OriginalFilename", "FileVersion" };
    struct { WORD lang, cp; } *tr = NULL; UINT tl = 0;
    if (q(buf, "\\VarFileInfo\\Translation", (LPVOID *)&tr, &tl) && tr && tl >= 4) {
        for (int i = 0; i < 4; i++) {
            char key[96]; char *val = NULL; UINT vl = 0;
            snprintf(key, sizeof key, "\\StringFileInfo\\%04x%04x\\%s", tr[0].lang, tr[0].cp, names[i]);
            if (q(buf, key, (LPVOID *)&val, &vl) && val) t_note("%s: %s", names[i], val);
        }
    }
    free(buf);
}
