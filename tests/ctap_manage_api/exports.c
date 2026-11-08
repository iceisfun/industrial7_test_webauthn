/* Export surface of the WebAuthNCtapManage* family of webauthn.dll. */
#include "cm_api.h"

static const struct { const char *name; WORD ord; } kMgmt[] = {
    {"WebAuthNCtapManageAuthenticatePin", 18}, {"WebAuthNCtapManageCancelEnrollFingerprint", 19},
    {"WebAuthNCtapManageChangePin", 20},       {"WebAuthNCtapManageClose", 21},
    {"WebAuthNCtapManageDeleteCredential", 22},{"WebAuthNCtapManageEnrollFingerprint", 23},
    {"WebAuthNCtapManageFreeDisplayCredentials", 24}, {"WebAuthNCtapManageGetDisplayCredentials", 25},
    {"WebAuthNCtapManageRemoveFingerprints", 26}, {"WebAuthNCtapManageResetDevice", 27},
    {"WebAuthNCtapManageSelect", 28},           {"WebAuthNCtapManageSetPin", 29},
};
#define NMGMT (sizeof kMgmt / sizeof kMgmt[0])

static HMODULE mod(void) { return t_module("webauthn.dll"); }

static const IMAGE_EXPORT_DIRECTORY *exp_dir(HMODULE m, DWORD *size_out)
{
    const BYTE *base = (const BYTE *)m;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dd;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;
    dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return NULL;
    if (size_out) *size_out = dd->Size;
    return (const IMAGE_EXPORT_DIRECTORY *)(base + dd->VirtualAddress);
}

static int is_mgmt_name(const char *n) { return !strncmp(n, "WebAuthNCtapManage", 18); }

TEST(cmexp_module_is_64bit_pe)
{
    HMODULE m = mod(); if (!m) { t_skip("webauthn.dll not present"); return; }
    CHECK(exp_dir(m, NULL) != NULL);
}

TEST(cmexp_mgmt_family_is_exactly_twelve)
{
    DWORD i, count = 0, seen[NMGMT] = {0}; size_t k;
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed; const BYTE *base = (const BYTE *)m;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, NULL); REQUIRE(ed);
    {
        const DWORD *names = (const DWORD *)(base + ed->AddressOfNames);
        for (i = 0; i < ed->NumberOfNames; i++) {
            const char *n = (const char *)(base + names[i]);
            if (!is_mgmt_name(n)) continue;
            count++;
            for (k = 0; k < NMGMT; k++) if (!strcmp(n, kMgmt[k].name)) seen[k]++;
        }
    }
    EXPECT_EQ(count, NMGMT);
    for (k = 0; k < NMGMT; k++) CHECKF(seen[k] == 1, "%s seen %lu times", kMgmt[k].name, seen[k]);
}

TEST(cmexp_total_export_count)
{
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, NULL); REQUIRE(ed);
    EXPECT_EQ(ed->NumberOfNames, 56);
    EXPECT_EQ(ed->NumberOfFunctions, 56);
    EXPECT_EQ(ed->Base, 1);
}

TEST(cmexp_mgmt_ordinals_match_reference)
{
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed; const BYTE *base = (const BYTE *)m; DWORD i; size_t k;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, NULL); REQUIRE(ed);
    for (i = 0; i < ed->NumberOfNames; i++) {
        const char *n = (const char *)(base + ((const DWORD *)(base + ed->AddressOfNames))[i]);
        WORD ord = ((const WORD *)(base + ed->AddressOfNameOrdinals))[i] + (WORD)ed->Base;
        for (k = 0; k < NMGMT; k++) if (!strcmp(n, kMgmt[k].name)) CHECKF(ord == kMgmt[k].ord, "%s ordinal %u want %u", n, ord, kMgmt[k].ord);
    }
}

TEST(cmexp_mgmt_ordinals_are_contiguous_18_to_29)
{
    WORD seen[64] = {0}; size_t k;
    for (k = 0; k < NMGMT; k++) seen[kMgmt[k].ord]++;
    for (k = 18; k <= 29; k++) CHECK(seen[k] == 1);
}

TEST(cmexp_mgmt_exports_are_not_forwarders)
{
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed; DWORD esz = 0; const BYTE *base = (const BYTE *)m; DWORD i; size_t k;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, &esz); REQUIRE(ed);
    {
        DWORD edrva = (DWORD)((const BYTE *)ed - base);
        const DWORD *funcs = (const DWORD *)(base + ed->AddressOfFunctions);
        for (i = 0; i < ed->NumberOfNames; i++) {
            const char *n = (const char *)(base + ((const DWORD *)(base + ed->AddressOfNames))[i]);
            WORD idx = ((const WORD *)(base + ed->AddressOfNameOrdinals))[i];
            for (k = 0; k < NMGMT; k++) if (!strcmp(n, kMgmt[k].name)) {
                DWORD rva = funcs[idx];
                CHECKF(!(rva >= edrva && rva < edrva + esz), "%s is a forwarder", n);
            }
        }
    }
}

#define RESOLVE_TEST(fn) \
    TEST(cmexp_resolves_##fn) { FARPROC p; REQUIRE(mod()); p = GetProcAddress(mod(), "WebAuthNCtapManage" #fn); CHECK(p != NULL); \
        CHECK(p == t_proc("WebAuthNCtapManage" #fn)); CHECK(p == t_proc_in("webauthn.dll", "WebAuthNCtapManage" #fn)); }
RESOLVE_TEST(Close) RESOLVE_TEST(Select) RESOLVE_TEST(SetPin) RESOLVE_TEST(ChangePin) RESOLVE_TEST(AuthenticatePin)
RESOLVE_TEST(GetDisplayCredentials) RESOLVE_TEST(FreeDisplayCredentials) RESOLVE_TEST(DeleteCredential)
RESOLVE_TEST(EnrollFingerprint) RESOLVE_TEST(CancelEnrollFingerprint) RESOLVE_TEST(RemoveFingerprints) RESOLVE_TEST(ResetDevice)

TEST(cmexp_resolve_by_ordinal_matches_name)
{
    size_t k;
    REQUIRE(mod());
    for (k = 0; k < NMGMT; k++) {
        FARPROC byname = GetProcAddress(mod(), kMgmt[k].name);
        FARPROC byord = GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)kMgmt[k].ord);
        CHECKF(byname != NULL && byname == byord, "%s ord %u", kMgmt[k].name, kMgmt[k].ord);
    }
}

TEST(cmexp_exports_lie_inside_module_image)
{
    size_t k;
    HMODULE m = mod(); const IMAGE_NT_HEADERS64 *nt;
    REQUIRE(m);
    nt = (const IMAGE_NT_HEADERS64 *)((const BYTE *)m + ((const IMAGE_DOS_HEADER *)m)->e_lfanew);
    for (k = 0; k < NMGMT; k++) {
        ULONG_PTR rel = (ULONG_PTR)GetProcAddress(m, kMgmt[k].name) - (ULONG_PTR)m;
        CHECKF(rel > 0 && rel < nt->OptionalHeader.SizeOfImage, "%s", kMgmt[k].name);
    }
}

TEST(cmexp_exports_are_distinct_except_none)
{
    size_t a, b;
    REQUIRE(mod());
    for (a = 0; a < NMGMT; a++) for (b = a + 1; b < NMGMT; b++)
        CHECKF(GetProcAddress(mod(), kMgmt[a].name) != GetProcAddress(mod(), kMgmt[b].name), "%s vs %s", kMgmt[a].name, kMgmt[b].name);
}

TEST(cmexp_free_display_credentials_aliases_free_platform_credentials)
{
    /* Both names are exported for the same code (ordinals 24 and 47). */
    REQUIRE(mod());
    CHECK(GetProcAddress(mod(), "WebAuthNCtapManageFreeDisplayCredentials") == GetProcAddress(mod(), "WebAuthNFreePlatformCredentials"));
    CHECK(GetProcAddress(mod(), "WebAuthNFreePlatformCredentials") == GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)47));
}

TEST(cmexp_names_are_case_sensitive)
{
    size_t k;
    REQUIRE(mod());
    for (k = 0; k < NMGMT; k++) {
        char up[96]; size_t i;
        strcpy(up, kMgmt[k].name);
        for (i = 0; up[i]; i++) if (up[i] >= 'a' && up[i] <= 'z') up[i] -= 32;
        SET_ERR(0);
        CHECK(GetProcAddress(mod(), up) == NULL);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

TEST(cmexp_no_ansi_wide_suffix_variants)
{
    static const char *const suf[] = { "A", "W", "Ex", "2" };
    size_t k, s;
    REQUIRE(mod());
    for (k = 0; k < NMGMT; k++) for (s = 0; s < 4; s++) {
        char n[96]; snprintf(n, sizeof n, "%s%s", kMgmt[k].name, suf[s]);
        SET_ERR(0);
        CHECKF(GetProcAddress(mod(), n) == NULL, "%s", n);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

TEST(cmexp_no_undecorated_or_stdcall_decorations)
{
    size_t k;
    REQUIRE(mod());
    for (k = 0; k < NMGMT; k++) {
        char n[96];
        snprintf(n, sizeof n, "_%s", kMgmt[k].name);
        CHECK(GetProcAddress(mod(), n) == NULL);
        snprintf(n, sizeof n, "_%s@16", kMgmt[k].name);
        CHECK(GetProcAddress(mod(), n) == NULL);
        snprintf(n, sizeof n, "%s@16", kMgmt[k].name);
        CHECK(GetProcAddress(mod(), n) == NULL);
    }
}

TEST(cmexp_ordinal_out_of_range_fails)
{
    REQUIRE(mod());
    SET_ERR(0);
    CHECK(GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)0) == NULL);
    CHECK(GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)57) == NULL);
    CHECK(GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)30) != NULL); /* 30 is another exported ordinal; the family ends at 29 */
}

TEST(cmexp_ordinals_neighbouring_family_are_not_management)
{
    /* Ordinal 17 and 30 belong to other families. */
    size_t k; REQUIRE(mod());
    for (k = 0; k < NMGMT; k++) {
        CHECK(GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)17) != GetProcAddress(mod(), kMgmt[k].name));
        CHECK(GetProcAddress(mod(), (LPCSTR)(ULONG_PTR)30) != GetProcAddress(mod(), kMgmt[k].name));
    }
}

TEST(cmexp_not_exported_by_other_modules)
{
    static const char *const others[] = { "ncrypt.dll", "bcrypt.dll", "kernel32.dll", "ntdll.dll" };
    size_t m, k;
    REQUIRE(mod());
    for (m = 0; m < 4; m++) {
        HMODULE h = t_module(others[m]); if (!h) continue;
        for (k = 0; k < NMGMT; k++) CHECKF(GetProcAddress(h, kMgmt[k].name) == NULL, "%s in %s", kMgmt[k].name, others[m]);
    }
}

TEST(cmexp_mgmt_names_sorted_in_name_table)
{
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed; const BYTE *base = (const BYTE *)m; DWORD i;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, NULL); REQUIRE(ed);
    for (i = 1; i < ed->NumberOfNames; i++) {
        const char *a = (const char *)(base + ((const DWORD *)(base + ed->AddressOfNames))[i - 1]);
        const char *b = (const char *)(base + ((const DWORD *)(base + ed->AddressOfNames))[i]);
        CHECKF(strcmp(a, b) < 0, "%s !< %s", a, b); /* loader binary search requires ordinal-sorted names */
    }
}

TEST(cmexp_export_directory_has_no_gaps_in_ordinals)
{
    HMODULE m = mod(); const IMAGE_EXPORT_DIRECTORY *ed; const BYTE *base = (const BYTE *)m; DWORD i;
    if (!m) { t_skip("webauthn.dll not present"); return; }
    ed = exp_dir(m, NULL); REQUIRE(ed);
    for (i = 0; i < ed->NumberOfFunctions; i++) CHECKF(((const DWORD *)(base + ed->AddressOfFunctions))[i] != 0, "ordinal %lu empty", ed->Base + i);
}

