/* Whole-DLL export sweep, part 1: the export directory of the loaded image and the per-export
 * resolve / image-placement checks.
 *
 * Classification of the 56 exports (documented = has a public documentation page):
 *   documented (12): VirtualChannelGetInstance, WebAuthNAuthenticatorGetAssertion,
 *     WebAuthNAuthenticatorMakeCredential, WebAuthNCancelCurrentOperation,
 *     WebAuthNDeletePlatformCredential, WebAuthNFreeAssertion, WebAuthNFreeCredentialAttestation,
 *     WebAuthNGetApiVersionNumber, WebAuthNGetCancellationId, WebAuthNGetErrorName,
 *     WebAuthNGetW3CExceptionDOMError, WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
 *   undocumented (44): CryptsvcDllCtrl, the four I_WebAuthNCtap{Encode,Decode}*Rpc{Request,Response},
 *     all WebAuthNCtap* (CTAP / device management layer), WebAuthN{Encode,Decode}AccountInformation,
 *     WebAuthNFree{DecodedAccountInformation,EncodedAccountInformation,PlatformCredentials,UserEntityList},
 *     WebAuthNGetCoseAlgorithmIdentifier, WebAuthNGetCredentialIdFromAuthenticatorData,
 *     WebAuthNGetPlatformCredentials.
 * Ordinals are the alphabetical positions 1..56 (export Base = 1); no export is a forwarder.
 */
#include "sweep.h"
#include <ctype.h>

/* ---- export directory structure ---------------------------------------- */
TEST(export_sweep_resolve_module_loads) {
    SW_NEED_MODULE();
    CHECK(h != NULL);
    EXPECT_EQ((ULONG_PTR)h & 0xFFFF, 0);              /* allocation-granularity aligned */
    EXPECT_EQ(GetModuleHandleA(SW_DLL), h);
    EXPECT_EQ(GetModuleHandleA("WEBAUTHN.DLL"), h);   /* case-insensitive */
    EXPECT_EQ(GetModuleHandleA("webauthn"), h);       /* default .dll extension */
}

TEST(export_sweep_resolve_module_filename) {
    SW_NEED_MODULE();
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(h, path, sizeof path);
    CHECK(n > 0 && n < sizeof path);
    size_t l = strlen(path), k = strlen("\\webauthn.dll");
    CHECK(l > k && !lstrcmpiA(path + l - k, "\\webauthn.dll"));
    char sysdir[MAX_PATH]; UINT sl = GetSystemDirectoryA(sysdir, sizeof sysdir);
    CHECK(sl > 0 && !_strnicmp(path, sysdir, sl));    /* lives in the 64-bit system directory */
}

TEST(export_sweep_resolve_loadlibrary_twice_same_handle) {
    SW_NEED_MODULE();
    HMODULE h2 = LoadLibraryA(SW_DLL);
    EXPECT_EQ(h2, h);
    if (h2) FreeLibrary(h2);
    EXPECT_EQ(GetModuleHandleA(SW_DLL), h);           /* still loaded after balanced free */
}

TEST(export_sweep_resolve_pe_headers) {
    SW_NEED_MODULE();
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    CHECK(n != NULL); if (!n) return;
    EXPECT_EQ(n->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64);
    EXPECT_EQ(n->OptionalHeader.Magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    CHECK(n->FileHeader.Characteristics & IMAGE_FILE_DLL);
    CHECK(n->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE);
    CHECK(n->FileHeader.NumberOfSections >= 3);
    t_note("Subsystem=%u", n->OptionalHeader.Subsystem);
    EXPECT_EQ(n->OptionalHeader.ImageBase, 0x180000000ULL);
    t_note("webauthn.dll: TimeDateStamp=0x%08lx SizeOfImage=0x%lx Sections=%u CheckSum=0x%lx OS=%u.%u Link=%u.%u",
           (unsigned long)n->FileHeader.TimeDateStamp, (unsigned long)n->OptionalHeader.SizeOfImage,
           n->FileHeader.NumberOfSections, (unsigned long)n->OptionalHeader.CheckSum,
           n->OptionalHeader.MajorOperatingSystemVersion, n->OptionalHeader.MinorOperatingSystemVersion,
           n->OptionalHeader.MajorLinkerVersion, n->OptionalHeader.MinorLinkerVersion);
}

TEST(export_sweep_resolve_dir_counts) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    EXPECT_EQ(e->NumberOfFunctions, 56);
    EXPECT_EQ(e->NumberOfNames, 56);
    EXPECT_EQ(e->Base, 1);
    EXPECT_EQ(SW_COUNT, 56);
}

TEST(export_sweep_resolve_dir_module_name) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    const char *nm = (const char *)h + e->Name;
    CHECKF(!lstrcmpiA(nm, "webauthn.dll"), "export module name \"%s\"", nm);
}

TEST(export_sweep_resolve_dir_inside_image) {
    SW_NEED_MODULE();
    DWORD rva, size; IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, &rva, &size);
    CHECK(e != NULL); if (!e) return;
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    CHECK(size >= sizeof(IMAGE_EXPORT_DIRECTORY));
    CHECK(rva + size <= n->OptionalHeader.SizeOfImage);
    CHECK(e->AddressOfFunctions && e->AddressOfNames && e->AddressOfNameOrdinals);
    CHECK(sw_section(h, rva) != NULL);
    CHECK(sw_section(h, e->AddressOfFunctions) != NULL);
}

TEST(export_sweep_resolve_name_table_sorted) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *names = (DWORD *)((BYTE *)h + e->AddressOfNames);
    for (DWORD i = 1; i < e->NumberOfNames; i++) {
        const char *a = (const char *)h + names[i - 1], *b = (const char *)h + names[i];
        CHECKF(strcmp(a, b) < 0, "names[%lu]=%s not < names[%lu]=%s", (unsigned long)(i - 1), a, (unsigned long)i, b);
    }
}

TEST(export_sweep_resolve_name_table_matches_reference) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *names = (DWORD *)((BYTE *)h + e->AddressOfNames);
    for (DWORD i = 0; i < e->NumberOfNames && i < (DWORD)SW_COUNT; i++) {
        const char *nm = (const char *)h + names[i];
        CHECKF(!strcmp(nm, sw_exports[i].name), "name[%lu] \"%s\" want \"%s\"", (unsigned long)i, nm, sw_exports[i].name);
    }
}

TEST(export_sweep_resolve_name_ordinal_table_identity) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    WORD *no = (WORD *)((BYTE *)h + e->AddressOfNameOrdinals);
    for (DWORD i = 0; i < e->NumberOfNames; i++)
        CHECKF(no[i] == i, "name-ordinal[%lu]=%u", (unsigned long)i, no[i]);
}

TEST(export_sweep_resolve_function_table_matches_reference) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (int i = 0; i < SW_COUNT && (DWORD)i < e->NumberOfFunctions; i++)
        CHECKF(fn[sw_exports[i].ord - e->Base] == sw_exports[i].rva, "%s rva 0x%lx want 0x%lx", sw_exports[i].name,
               (unsigned long)fn[sw_exports[i].ord - e->Base], (unsigned long)sw_exports[i].rva);
}

TEST(export_sweep_resolve_function_table_no_holes) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfFunctions; i++) CHECKF(fn[i] != 0, "ordinal %lu has a zero RVA", (unsigned long)(i + e->Base));
}

TEST(export_sweep_resolve_function_rvas_distinct) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfFunctions; i++)
        for (DWORD j = i + 1; j < e->NumberOfFunctions; j++)
            CHECKF(fn[i] != fn[j], "ordinals %lu and %lu share rva 0x%lx", (unsigned long)(i + 1), (unsigned long)(j + 1), (unsigned long)fn[i]);
}

TEST(export_sweep_resolve_no_forwarders) {
    SW_NEED_MODULE();
    DWORD rva, size; IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, &rva, &size);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfFunctions; i++)
        CHECKF(!(fn[i] >= rva && fn[i] < rva + size), "ordinal %lu is a forwarder", (unsigned long)(i + 1));
}

TEST(export_sweep_resolve_all_rvas_in_executable_sections) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfFunctions; i++) {
        IMAGE_SECTION_HEADER *s = sw_section(h, fn[i]);
        CHECKF(s && (s->Characteristics & IMAGE_SCN_MEM_EXECUTE), "ordinal %lu not in an executable section", (unsigned long)(i + 1));
    }
}

TEST(export_sweep_resolve_export_section_layout_note) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    IMAGE_SECTION_HEADER *first = sw_section(h, fn[0]);
    CHECK(first != NULL); if (!first) return;
    char nm[9] = {0}; memcpy(nm, first->Name, 8);
    t_note("first export lives in section \"%s\"", nm);
    for (DWORD i = 1; i < e->NumberOfFunctions; i++) if (sw_section(h, fn[i]) != first) t_note("ordinal %lu is in a different section", (unsigned long)(i + 1));
}

TEST(export_sweep_resolve_code_section_not_writable) {
    SW_NEED_MODULE();
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    CHECK(e != NULL); if (!e) return;
    DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfFunctions; i++) {
        IMAGE_SECTION_HEADER *s = sw_section(h, fn[i]);
        CHECKF(s && !(s->Characteristics & IMAGE_SCN_MEM_WRITE), "ordinal %lu in a writable section", (unsigned long)(i + 1));
        CHECKF(s && (s->Characteristics & IMAGE_SCN_CNT_CODE), "ordinal %lu not in a code section", (unsigned long)(i + 1));
    }
}

/* ---- name-prefix families of the real export names ---------------------- */
static int count_prefix(HMODULE h, const char *prefix) {
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL); int c = 0;
    if (!e) return -1;
    DWORD *names = (DWORD *)((BYTE *)h + e->AddressOfNames);
    for (DWORD i = 0; i < e->NumberOfNames; i++) if (!strncmp((const char *)h + names[i], prefix, strlen(prefix))) c++;
    return c;
}
TEST(export_sweep_resolve_family_internal_rpc_codecs) { SW_NEED_MODULE(); EXPECT_EQ(count_prefix(h, "I_WebAuthN"), 4); }
TEST(export_sweep_resolve_family_ctap) { SW_NEED_MODULE(); EXPECT_EQ(count_prefix(h, "WebAuthNCtap"), 30); }
TEST(export_sweep_resolve_family_ctap_manage) { SW_NEED_MODULE(); EXPECT_EQ(count_prefix(h, "WebAuthNCtapManage"), 12); }
TEST(export_sweep_resolve_family_non_webauthn_names) {
    SW_NEED_MODULE();
    EXPECT_EQ(count_prefix(h, "Cryptsvc"), 1);
    EXPECT_EQ(count_prefix(h, "VirtualChannel"), 1);
    EXPECT_EQ(count_prefix(h, "WebAuthN") + count_prefix(h, "I_WebAuthN") + 2, 56);
}
TEST(export_sweep_resolve_family_free_functions) {
    SW_NEED_MODULE();
    EXPECT_EQ(count_prefix(h, "WebAuthNFree"), 6);
}
TEST(export_sweep_resolve_family_reference_counts) {
    int doc = 0; for (int i = 0; i < SW_COUNT; i++) doc += sw_exports[i].documented;
    EXPECT_EQ(doc, 12);
    EXPECT_EQ(SW_COUNT - doc, 44);
}

/* ---- ordinal sweep ------------------------------------------------------ */
TEST(export_sweep_resolve_ordinals_1_to_56_resolve) {
    SW_NEED_MODULE();
    for (unsigned o = 1; o <= 56; o++) CHECKF(GetProcAddress(h, (LPCSTR)(ULONG_PTR)o) != NULL, "ordinal %u", o);
}
TEST(export_sweep_resolve_ordinals_pairwise_distinct) {
    SW_NEED_MODULE();
    FARPROC p[57] = {0};
    for (unsigned o = 1; o <= 56; o++) p[o] = GetProcAddress(h, (LPCSTR)(ULONG_PTR)o);
    for (unsigned a = 1; a <= 56; a++) for (unsigned b = a + 1; b <= 56; b++) CHECKF(p[a] != p[b], "ordinals %u and %u alias", a, b);
}
TEST(export_sweep_resolve_ordinal_equals_name_for_all) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++)
        CHECKF(GetProcAddress(h, sw_exports[i].name) == GetProcAddress(h, (LPCSTR)(ULONG_PTR)sw_exports[i].ord), "%s ordinal %u", sw_exports[i].name, sw_exports[i].ord);
}
TEST(export_sweep_resolve_name_order_equals_ordinal_order) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++) EXPECT_EQ(sw_exports[i].ord, i + 1);
    for (int i = 1; i < SW_COUNT; i++) CHECK(strcmp(sw_exports[i - 1].name, sw_exports[i].name) < 0);
}
TEST(export_sweep_resolve_pinned_module_lookup_matches) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++) EXPECT_EQ(t_proc_in(SW_DLL, sw_exports[i].name), GetProcAddress(h, sw_exports[i].name));
}
TEST(export_sweep_resolve_module_list_lookup_prefers_dll_under_test) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++) EXPECT_EQ(t_proc(sw_exports[i].name), GetProcAddress(h, sw_exports[i].name));
}
TEST(export_sweep_resolve_t_proc_ord_matches) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++) EXPECT_EQ(t_proc_ord(SW_DLL, sw_exports[i].ord), GetProcAddress(h, sw_exports[i].name));
}
TEST(export_sweep_resolve_repeat_lookup_is_stable) {
    SW_NEED_MODULE();
    for (int i = 0; i < SW_COUNT; i++) {
        FARPROC a = GetProcAddress(h, sw_exports[i].name);
        for (int k = 0; k < 20; k++) if (GetProcAddress(h, sw_exports[i].name) != a) { CHECKF(0, "%s unstable", sw_exports[i].name); break; }
    }
}
TEST(export_sweep_resolve_exports_not_in_other_modules_under_same_name) {
    SW_NEED_MODULE();
    /* none of the webauthn-only names exist in kernel32/ntdll, so U() cannot hit a wrong module */
    for (int i = 0; i < SW_COUNT; i++) {
        CHECKF(t_proc_in("kernel32.dll", sw_exports[i].name) == NULL, "%s in kernel32", sw_exports[i].name);
        CHECKF(t_proc_in("ntdll.dll", sw_exports[i].name) == NULL, "%s in ntdll", sw_exports[i].name);
    }
}

/* ---- per-export tests (one TEST per export, generated) ------------------- */
static void sw_resolve(const char *name, unsigned ord, DWORD rva) {
    HMODULE h = sw_mod(); if (!h) { t_skip("not loadable"); return; }
    FARPROC p = GetProcAddress(h, name);
    CHECKF(p != NULL, "%s by name", name);
    FARPROC q = GetProcAddress(h, (LPCSTR)(ULONG_PTR)ord);
    CHECKF(q != NULL, "%s by ordinal %u", name, ord);
    EXPECT_EQ(p, q);
    EXPECT_EQ((BYTE *)p - (BYTE *)h, rva);
    EXPECT_EQ(t_proc_in(SW_DLL, name), p);
    EXPECT_EQ(t_proc(name), p);
    /* the found function is the same one the export directory names */
    IMAGE_EXPORT_DIRECTORY *e = sw_expdir(h, NULL, NULL);
    if (e && ord >= e->Base && ord - e->Base < e->NumberOfFunctions) {
        DWORD *fn = (DWORD *)((BYTE *)h + e->AddressOfFunctions);
        EXPECT_EQ(fn[ord - e->Base], rva);
    }
}

static void sw_image(const char *name, unsigned ord, DWORD rva) {
    HMODULE h = sw_mod(); if (!h) { t_skip("not loadable"); return; }
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    BYTE *p = (BYTE *)GetProcAddress(h, name);
    CHECKF(p != NULL, "%s", name); if (!p || !n) return;
    CHECK(p > (BYTE *)h && p < (BYTE *)h + n->OptionalHeader.SizeOfImage);
    DWORD dr, ds; sw_expdir(h, &dr, &ds);
    CHECKF(!(rva >= dr && rva < dr + ds), "%s lies in the export directory (forwarder)", name);
    IMAGE_SECTION_HEADER *s = sw_section(h, rva);
    CHECKF(s != NULL, "%s not in any section", name); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_EXECUTE);
    CHECK(s->Characteristics & IMAGE_SCN_CNT_CODE);
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_WRITE));
    MEMORY_BASIC_INFORMATION mbi; memset(&mbi, 0, sizeof mbi);
    CHECK(VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi);
    EXPECT_EQ(mbi.AllocationBase, h);
    EXPECT_EQ(mbi.Type, MEM_IMAGE);
    EXPECT_EQ(mbi.State, MEM_COMMIT);
    CHECK(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
    CHECK(!(mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE)));
    /* prologue sanity: not padding / trap / zero fill at the entry point */
    CHECKF(p[0] != 0xCC, "%s starts with int3", name);
    CHECKF(!(p[0] == 0x0F && p[1] == 0x0B), "%s starts with ud2", name);
    CHECKF(!(p[0] == 0 && p[1] == 0), "%s starts with zero fill", name);
    CHECKF(!(p[0] == 0xCC && p[1] == 0xCC && p[2] == 0xCC && p[3] == 0xCC), "%s starts with int3 padding", name);
    CHECKF(rva % 16 == 0, "%s entry not 16-byte aligned", name);
}

static int sw_is_export(const char *s) { return sw_find(s) != NULL; }

static void sw_nearmiss(const char *name) {
    HMODULE h = sw_mod(); if (!h) { t_skip("not loadable"); return; }
    char v[200]; size_t l = strlen(name);
    struct { const char *tag; } dummy; (void)dummy;
    for (int k = 0; k < 16; k++) {
        v[0] = 0;
        switch (k) {
        case 0: for (size_t i = 0; i <= l; i++) v[i] = (char)tolower((unsigned char)name[i]); break;           /* all lower */
        case 1: for (size_t i = 0; i <= l; i++) v[i] = (char)toupper((unsigned char)name[i]); break;           /* all upper */
        case 2: snprintf(v, sizeof v, "%s", name); v[0] = isupper((unsigned char)v[0]) ? (char)tolower((unsigned char)v[0]) : (char)toupper((unsigned char)v[0]); break;
        case 3: snprintf(v, sizeof v, "%sA", name); break;
        case 4: snprintf(v, sizeof v, "%sW", name); break;
        case 5: snprintf(v, sizeof v, "%sX", name); break;
        case 6: snprintf(v, sizeof v, "%s2", name); break;
        case 7: snprintf(v, sizeof v, "%.*s", (int)(l - 1), name); break;                                      /* truncated */
        case 8: snprintf(v, sizeof v, "_%s", name); break;
        case 9: snprintf(v, sizeof v, "_%s@4", name); break;
        case 10: snprintf(v, sizeof v, "_%s@16", name); break;
        case 11: snprintf(v, sizeof v, "_%s@32", name); break;
        case 12: snprintf(v, sizeof v, "%s@16", name); break;
        case 13: snprintf(v, sizeof v, " %s", name); break;
        case 14: snprintf(v, sizeof v, "%s ", name); break;
        case 15: snprintf(v, sizeof v, "?%s@@YAXXZ", name); break;                                             /* C++ mangled style */
        }
        if (sw_is_export(v)) continue;     /* variant happens to be another real export */
        SET_ERR(0);
        FARPROC p = GetProcAddress(h, v);
        CHECKF(p == NULL, "variant %d \"%s\" resolved", k, v);
        if (!p) EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

#define GEN_RESOLVE(N, O, R, D) TEST(export_sweep_resolve_resolve_##N) { sw_resolve(#N, O, R); }
#define GEN_IMAGE(N, O, R, D)   TEST(export_sweep_resolve_image_##N)   { sw_image(#N, O, R); }
#define GEN_NEAR(N, O, R, D)    TEST(export_sweep_resolve_nearmiss_##N) { sw_nearmiss(#N); }
SWEEP_EXPORTS(GEN_RESOLVE)
SWEEP_EXPORTS(GEN_IMAGE)
SWEEP_EXPORTS(GEN_NEAR)
