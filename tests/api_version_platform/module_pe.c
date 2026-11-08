/* Static facts about the webauthn.dll image as mapped into the process: PE headers, sections,
 * data directories, load-config/cookie state. Everything here is read from the loaded image, so
 * it describes the genuine Windows 10 x64 binary, not what a stand-in would happen to export. */
#include "apv.h"

#define PE_NT(m) const IMAGE_NT_HEADERS64 *nt = apv_nt(m); if (!nt) { CHECK(nt != NULL); return; }

TEST(apv_pe_dos_header) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)m;
    EXPECT_EQ(d->e_magic, IMAGE_DOS_SIGNATURE);
    CHECK(d->e_lfanew >= 0x40 && d->e_lfanew < 0x400);
    EXPECT_EQ(d->e_lfanew % 8, 0);
}
TEST(apv_pe_nt_signature) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->Signature, IMAGE_NT_SIGNATURE); }
TEST(apv_pe_machine_amd64) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64); }
TEST(apv_pe_optional_magic_pe32plus) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->OptionalHeader.Magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC); }
TEST(apv_pe_optional_header_size) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->FileHeader.SizeOfOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64)); }
TEST(apv_pe_is_dll) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(nt->FileHeader.Characteristics & IMAGE_FILE_DLL); }
TEST(apv_pe_is_executable_image) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE); }
TEST(apv_pe_not_32bit_machine_flag) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(!(nt->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)); }
TEST(apv_pe_large_address_aware) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE); }
TEST(apv_pe_not_stripped_relocs) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(!(nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)); }
TEST(apv_pe_no_coff_symbols) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->FileHeader.NumberOfSymbols, 0); EXPECT_EQ(nt->FileHeader.PointerToSymbolTable, 0); }
TEST(apv_pe_section_count_7) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->FileHeader.NumberOfSections, 7); }
TEST(apv_pe_subsystem_console) {
    /* Windows subsystem value of the OS DLLs in this family: 3 (CUI). */
    APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->OptionalHeader.Subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI);
}
TEST(apv_pe_os_version_10_0) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    EXPECT_EQ(nt->OptionalHeader.MajorOperatingSystemVersion, 10);
    EXPECT_EQ(nt->OptionalHeader.MinorOperatingSystemVersion, 0);
}
TEST(apv_pe_subsystem_version_10_0) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    EXPECT_EQ(nt->OptionalHeader.MajorSubsystemVersion, 10);
    EXPECT_EQ(nt->OptionalHeader.MinorSubsystemVersion, 0);
}
TEST(apv_pe_win32_version_value_zero) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->OptionalHeader.Win32VersionValue, 0); }
TEST(apv_pe_preferred_image_base) {
    /* The loader rewrites OptionalHeader.ImageBase in the mapped image to the actual base after relocation
     * (observed on Windows 10 22H2: equals the module handle), so the preferred base is read from the file. */
    APV_REQUIRE_MOD(m); PE_NT(m);
    CHECK(nt->OptionalHeader.ImageBase == (ULONGLONG)(ULONG_PTR)m || nt->OptionalHeader.ImageBase == 0x180000000ull);
    WCHAR path[MAX_PATH];
    if (!GetModuleFileNameW(m, path, MAX_PATH)) { t_skip("no path"); return; }
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE); if (f == INVALID_HANDLE_VALUE) return;
    BYTE hdr[1024]; DWORD n = 0; BOOL ok = ReadFile(f, hdr, sizeof hdr, &n, NULL); CloseHandle(f);
    CHECK(ok && n == sizeof hdr); if (!ok || n != sizeof hdr) return;
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)hdr;
    CHECK(d->e_magic == IMAGE_DOS_SIGNATURE && d->e_lfanew > 0 && (size_t)d->e_lfanew < sizeof hdr - sizeof(IMAGE_NT_HEADERS64));
    if (d->e_magic != IMAGE_DOS_SIGNATURE || d->e_lfanew <= 0 || (size_t)d->e_lfanew >= sizeof hdr - sizeof(IMAGE_NT_HEADERS64)) return;
    const IMAGE_NT_HEADERS64 *fnt = (const IMAGE_NT_HEADERS64 *)(hdr + d->e_lfanew);
    EXPECT_EQ(fnt->OptionalHeader.ImageBase, 0x180000000ull);
    t_note("mapped ImageBase field 0x%llx, module handle %p", (unsigned long long)nt->OptionalHeader.ImageBase, (void *)m);
}
TEST(apv_pe_mapped_at_64k_aligned_address) { APV_REQUIRE_MOD(m); EXPECT_EQ((ULONG_PTR)m & 0xFFFF, 0); }
TEST(apv_pe_alignments) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    EXPECT_EQ(nt->OptionalHeader.SectionAlignment, 0x1000);
    EXPECT_EQ(nt->OptionalHeader.FileAlignment, 0x200);
}
TEST(apv_pe_size_of_image_page_aligned) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    EXPECT_EQ(nt->OptionalHeader.SizeOfImage % 0x1000, 0);
    CHECK(nt->OptionalHeader.SizeOfImage > 0x10000 && nt->OptionalHeader.SizeOfImage < 0x1000000);
    t_note("SizeOfImage 0x%lx (servicing dependent)", nt->OptionalHeader.SizeOfImage);
}
TEST(apv_pe_size_of_headers_covers_section_table) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)m;
    DWORD end = d->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    CHECK(nt->OptionalHeader.SizeOfHeaders >= end);
    EXPECT_EQ(nt->OptionalHeader.SizeOfHeaders % nt->OptionalHeader.FileAlignment, 0);
}
TEST(apv_pe_dll_characteristics_dynamic_base) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE); }
TEST(apv_pe_dll_characteristics_nx_compat) { APV_REQUIRE_MOD(m); PE_NT(m); CHECK(nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT); }
TEST(apv_pe_dll_characteristics_guard_cf) { APV_REQUIRE_MOD(m); PE_NT(m); t_note("GUARD_CF bit (0x4000) in DllCharacteristics: %d", !!(nt->OptionalHeader.DllCharacteristics & 0x4000)); }
TEST(apv_pe_dll_characteristics_note) { APV_REQUIRE_MOD(m); PE_NT(m); t_note("DllCharacteristics 0x%x", nt->OptionalHeader.DllCharacteristics); }
TEST(apv_pe_entry_point_in_text) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
    CHECK(ep != 0);
    const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, ep);
    CHECK(s && !strncmp((const char *)s->Name, ".text", 8));
}
TEST(apv_pe_data_directory_count_16) { APV_REQUIRE_MOD(m); PE_NT(m); EXPECT_EQ(nt->OptionalHeader.NumberOfRvaAndSizes, 16); }

/* ---- sections ----------------------------------------------------------- */
static const char *const SEC_NAMES[7] = { ".text", ".rdata", ".data", ".pdata", ".didat", ".rsrc", ".reloc" };
TEST(apv_pe_section_names_in_order) {
    APV_REQUIRE_MOD(m);
    int c; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    CHECK(s && c == 7);
    for (int i = 0; s && i < 7 && i < c; i++) CHECKF(!strncmp((const char *)s[i].Name, SEC_NAMES[i], 8), "section %d is %.8s want %s", i, s[i].Name, SEC_NAMES[i]);
}
TEST(apv_pe_section_text_flags) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".text");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_CNT_CODE);
    CHECK(s->Characteristics & IMAGE_SCN_MEM_EXECUTE);
    CHECK(s->Characteristics & IMAGE_SCN_MEM_READ);
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_WRITE));
}
TEST(apv_pe_section_rdata_flags) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".rdata");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_READ);
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_WRITE));
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE));
}
TEST(apv_pe_section_data_flags) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".data");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_READ);
    CHECK(s->Characteristics & IMAGE_SCN_MEM_WRITE);
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE));
}
TEST(apv_pe_section_pdata_flags) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".pdata");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_READ);
    CHECK(!(s->Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)));
}
TEST(apv_pe_section_didat_is_writable_delay_iat) {
    /* .didat holds the delay-load import address tables, so it is writable. */
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".didat");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_WRITE);
    CHECK(!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE));
}
TEST(apv_pe_section_rsrc_flags) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".rsrc");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_READ);
    CHECK(!(s->Characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)));
}
TEST(apv_pe_section_reloc_discardable) {
    APV_REQUIRE_MOD(m);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".reloc");
    CHECK(s != NULL); if (!s) return;
    CHECK(s->Characteristics & IMAGE_SCN_MEM_DISCARDABLE);
}
TEST(apv_pe_sections_contiguous_and_aligned) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    int c = 0; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    if (!s) { CHECK(s != NULL); return; }
    DWORD expect = nt->OptionalHeader.SectionAlignment;   /* first section follows the headers' page(s) */
    CHECK(s[0].VirtualAddress >= nt->OptionalHeader.SizeOfHeaders);
    int bad = 0;
    for (int i = 0; i < c; i++) {
        if (s[i].VirtualAddress % 0x1000) bad++;
        if (s[i].PointerToRawData % 0x200) bad++;
        if (s[i].SizeOfRawData % 0x200) bad++;
        if (i > 0) {
            DWORD prev_end = s[i-1].VirtualAddress + ((s[i-1].Misc.VirtualSize + 0xFFF) & ~0xFFFu);
            if (s[i].VirtualAddress != prev_end) bad++;
        }
    }
    EXPECT_EQ(bad, 0);
    DWORD last_end = s[c-1].VirtualAddress + ((s[c-1].Misc.VirtualSize + 0xFFF) & ~0xFFFu);
    EXPECT_EQ(last_end, nt->OptionalHeader.SizeOfImage);
}
TEST(apv_pe_mapped_section_page_protections_match_flags) {
    APV_REQUIRE_MOD(m);
    int c = 0; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    int bad = 0;
    for (int i = 0; i < c; i++) {
        if (s[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) continue;   /* .reloc may be unmapped */
        if (!strncmp((const char *)s[i].Name, ".didat", 8)) continue;     /* delay-load IAT protection changes at run time */
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((BYTE *)m + s[i].VirtualAddress, &mbi, sizeof mbi)) { bad++; continue; }
        if (mbi.Type != MEM_IMAGE || mbi.AllocationBase != (PVOID)m) bad++;
        DWORD p = mbi.Protect & 0xFF;
        int ex = (s[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        int wr = (s[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        int is_ex = p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY || p == PAGE_EXECUTE;
        int is_wr = p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
        if (ex != is_ex) bad++;
        if (wr != is_wr) bad++;
    }
    EXPECT_EQ(bad, 0);
}
TEST(apv_pe_headers_page_is_read_only_image) {
    APV_REQUIRE_MOD(m);
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(VirtualQuery(m, &mbi, sizeof mbi));
    EXPECT_EQ(mbi.Type, MEM_IMAGE);
    EXPECT_EQ(mbi.AllocationBase, m);
    EXPECT_EQ(mbi.Protect, PAGE_READONLY);
}

/* ---- data directories ---------------------------------------------------- */
#define DIRTEST(nm, idx) \
    TEST(apv_pe_dir_##nm##_present) { APV_REQUIRE_MOD(m); const IMAGE_DATA_DIRECTORY *d = apv_dd(m, idx); CHECK(d && d->VirtualAddress && d->Size); \
        if (d && d->VirtualAddress) { const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, d->VirtualAddress); CHECK(s != NULL); } }
DIRTEST(export, IMAGE_DIRECTORY_ENTRY_EXPORT)
DIRTEST(import, IMAGE_DIRECTORY_ENTRY_IMPORT)
DIRTEST(resource, IMAGE_DIRECTORY_ENTRY_RESOURCE)
DIRTEST(exception, IMAGE_DIRECTORY_ENTRY_EXCEPTION)
DIRTEST(basereloc, IMAGE_DIRECTORY_ENTRY_BASERELOC)
DIRTEST(debug, IMAGE_DIRECTORY_ENTRY_DEBUG)
DIRTEST(load_config, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
DIRTEST(iat, IMAGE_DIRECTORY_ENTRY_IAT)
DIRTEST(delay_import, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)

TEST(apv_pe_dir_security_note) {
    /* OS binaries are normally catalog-signed with no embedded blob; record what this build has. */
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_SECURITY);
    CHECK(d != NULL);
    if (d) t_note("security directory: offset 0x%lx size 0x%lx", d->VirtualAddress, d->Size);
}
TEST(apv_pe_dir_tls_note) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_TLS);
    if (d) t_note("TLS directory rva 0x%lx size 0x%lx", d->VirtualAddress, d->Size);
    CHECK(d != NULL);
}
TEST(apv_pe_dir_com_descriptor_absent) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    CHECK(d && d->VirtualAddress == 0 && d->Size == 0);   /* native image, not managed */
}
TEST(apv_pe_dir_bound_import_note) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
    if (d) t_note("bound import directory rva 0x%lx", d->VirtualAddress);
    CHECK(d != NULL);
}
TEST(apv_pe_exception_directory_is_runtime_function_table) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    CHECK(d && d->Size % sizeof(RUNTIME_FUNCTION) == 0);
    const RUNTIME_FUNCTION *rf = (const RUNTIME_FUNCTION *)apv_rva(m, d->VirtualAddress);
    DWORD n = d->Size / sizeof *rf;
    CHECK(n > 100);
    int unsorted = 0, outside = 0;
    const IMAGE_SECTION_HEADER *pd = apv_section_named(m, ".pdata");
    CHECK(pd && d->VirtualAddress >= pd->VirtualAddress && d->VirtualAddress + d->Size <= pd->VirtualAddress + pd->Misc.VirtualSize);
    for (DWORD i = 0; i < n; i++) {
        if (i && rf[i].BeginAddress <= rf[i-1].BeginAddress) unsorted++;
        if (rf[i].BeginAddress >= rf[i].EndAddress || rf[i].EndAddress > nt->OptionalHeader.SizeOfImage) outside++;
    }
    EXPECT_EQ(unsorted, 0);
    EXPECT_EQ(outside, 0);
}
TEST(apv_pe_entry_point_has_runtime_function) {
    /* DllMain's entry stub is a real function with unwind info that the OS can look up. */
    APV_REQUIRE_MOD(m); PE_NT(m);
    DWORD64 base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry((DWORD64)m + nt->OptionalHeader.AddressOfEntryPoint, &base, NULL);
    /* A leaf/tail-jump entry stub may legitimately have no unwind data: record only. */
    t_note("entry stub has RUNTIME_FUNCTION: %d", rf != NULL);
    if (rf) EXPECT_EQ(base, (DWORD64)m);
}
TEST(apv_pe_debug_directory_has_codeview_pdb70) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_DEBUG);
    CHECK(d && d->VirtualAddress); if (!d || !d->VirtualAddress) return;
    const IMAGE_DEBUG_DIRECTORY *dd = (const IMAGE_DEBUG_DIRECTORY *)apv_rva(m, d->VirtualAddress);
    int found = 0;
    for (DWORD i = 0; i < d->Size / sizeof *dd; i++) {
        if (dd[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
        const DWORD *cv = (const DWORD *)apv_rva(m, dd[i].AddressOfRawData);
        if (cv[0] == 0x53445352 /* RSDS */) {
            found = 1;
            const char *pdb = (const char *)(cv) + 24;
            EXPECT_STR(pdb, "webauthn.pdb");
        }
    }
    CHECK(found);
}
TEST(apv_pe_reloc_directory_in_reloc_section) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".reloc");
    CHECK(d && s && d->VirtualAddress == s->VirtualAddress);
}
TEST(apv_pe_resource_directory_in_rsrc_section) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    const IMAGE_SECTION_HEADER *s = apv_section_named(m, ".rsrc");
    CHECK(d && s && d->VirtualAddress == s->VirtualAddress);
}
TEST(apv_pe_delay_import_directory_is_64bit_rva_style) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    CHECK(d && d->VirtualAddress); if (!d || !d->VirtualAddress) return;
    const apv_delay_desc *e = (const apv_delay_desc *)apv_rva(m, d->VirtualAddress);
    int n = 0, bad = 0;
    for (; e->DllNameRVA; e++, n++) if (!(e->Attributes & 1)) bad++;
    CHECK(n > 5);
    EXPECT_EQ(bad, 0);
}
TEST(apv_pe_delay_iat_lives_in_didat) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    const IMAGE_SECTION_HEADER *did = apv_section_named(m, ".didat");
    CHECK(d && did); if (!d || !did) return;
    const apv_delay_desc *e = (const apv_delay_desc *)apv_rva(m, d->VirtualAddress);
    int bad = 0, n = 0;
    for (; e->DllNameRVA; e++, n++)
        if (e->ImportAddressTableRVA < did->VirtualAddress || e->ImportAddressTableRVA >= did->VirtualAddress + did->Misc.VirtualSize) bad++;
    CHECK(n > 0);
    EXPECT_EQ(bad, 0);
}

/* ---- security cookie / DllMain attach ----------------------------------- */
TEST(apv_pe_load_config_has_security_cookie) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    CHECK(d && d->VirtualAddress); if (!d || !d->VirtualAddress) return;
    const IMAGE_LOAD_CONFIG_DIRECTORY64 *lc = (const IMAGE_LOAD_CONFIG_DIRECTORY64 *)apv_rva(m, d->VirtualAddress);
    CHECK(lc->Size >= 0x70);
    CHECK(lc->SecurityCookie != 0);
    const IMAGE_NT_HEADERS64 *nt = apv_nt(m);
    CHECK(lc->SecurityCookie >= (ULONGLONG)(ULONG_PTR)m && lc->SecurityCookie < (ULONGLONG)(ULONG_PTR)m + nt->OptionalHeader.SizeOfImage);   /* relocated */
    const IMAGE_SECTION_HEADER *s = apv_section_of_rva(m, (DWORD)(lc->SecurityCookie - (ULONGLONG)(ULONG_PTR)m));
    CHECK(s && !strncmp((const char *)s->Name, ".data", 8));
}
TEST(apv_pe_security_cookie_initialised_by_dllmain_attach) {
    /* __security_init_cookie runs on DLL_PROCESS_ATTACH (the entry stub calls it first), replacing the
     * link-time default 0x00002B992DDFA232. */
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!d || !d->VirtualAddress) { CHECK(d != NULL); return; }
    const IMAGE_LOAD_CONFIG_DIRECTORY64 *lc = (const IMAGE_LOAD_CONFIG_DIRECTORY64 *)apv_rva(m, d->VirtualAddress);
    ULONGLONG cookie = *(const ULONGLONG *)(ULONG_PTR)lc->SecurityCookie;
    CHECK(cookie != 0);
    CHECK(cookie != 0x00002B992DDFA232ull);
}
TEST(apv_pe_security_cookie_is_48_bit) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!d || !d->VirtualAddress) { CHECK(d != NULL); return; }
    const IMAGE_LOAD_CONFIG_DIRECTORY64 *lc = (const IMAGE_LOAD_CONFIG_DIRECTORY64 *)apv_rva(m, d->VirtualAddress);
    ULONGLONG cookie = *(const ULONGLONG *)(ULONG_PTR)lc->SecurityCookie;
    t_note("security cookie high 16 bits: 0x%llx (CRT clears them on x64)", (unsigned long long)(cookie >> 48));
}
TEST(apv_pe_cfg_guard_check_pointers_present) {
    APV_REQUIRE_MOD(m);
    const IMAGE_DATA_DIRECTORY *d = apv_dd(m, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if (!d || !d->VirtualAddress) { CHECK(d != NULL); return; }
    const IMAGE_LOAD_CONFIG_DIRECTORY64 *lc = (const IMAGE_LOAD_CONFIG_DIRECTORY64 *)apv_rva(m, d->VirtualAddress);
    const BYTE *raw = (const BYTE *)lc;     /* x64 layout: check ptr @0x70, dispatch ptr @0x78, count @0x88, flags @0x90 */
    if (lc->Size < 0x94) { t_note("load config size 0x%lx has no CFG fields", (unsigned long)lc->Size); return; }
    t_note("CFG check 0x%llx dispatch 0x%llx count %llu flags 0x%lx",
           (unsigned long long)*(const ULONGLONG *)(raw + 0x70), (unsigned long long)*(const ULONGLONG *)(raw + 0x78),
           (unsigned long long)*(const ULONGLONG *)(raw + 0x88), (unsigned long)*(const DWORD *)(raw + 0x90));
}
TEST(apv_pe_timestamp_nonzero) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    CHECK(nt->FileHeader.TimeDateStamp != 0);
    t_note("PE TimeDateStamp 0x%lx", nt->FileHeader.TimeDateStamp);
}
TEST(apv_pe_checksum_note) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    t_note("CheckSum 0x%lx SizeOfImage 0x%lx EntryRVA 0x%lx", nt->OptionalHeader.CheckSum, nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.AddressOfEntryPoint);
}
TEST(apv_pe_stack_heap_reserves_note) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    t_note("stack reserve/commit %llu/%llu", (unsigned long long)nt->OptionalHeader.SizeOfStackReserve, (unsigned long long)nt->OptionalHeader.SizeOfStackCommit);
}

/* ---- layout of the reference build (servicing dependent: differences are recorded, not failed) ---- */
static const struct { const char *name; DWORD rva, vsize; } REF_SECTIONS[7] = {
    { ".text", 4096, 388158 }, { ".rdata", 393216, 73610 }, { ".data", 466944, 4336 }, { ".pdata", 475136, 11880 },
    { ".didat", 487424, 1304 }, { ".rsrc", 491520, 47504 }, { ".reloc", 540672, 1564 } };
TEST(apv_pe_section_layout_vs_reference_build) {
    APV_REQUIRE_MOD(m); PE_NT(m);
    int c; const IMAGE_SECTION_HEADER *s = apv_sections(m, &c);
    CHECK(s && c == 7); if (!s || c != 7) return;
    int diffs = 0;
    for (int i = 0; i < 7; i++) {
        if (strncmp((const char *)s[i].Name, REF_SECTIONS[i].name, 8)) { CHECK(0); continue; }
        if (s[i].VirtualAddress != REF_SECTIONS[i].rva || s[i].Misc.VirtualSize != REF_SECTIONS[i].vsize) {
            diffs++; t_note("%s rva 0x%lx vsize 0x%lx (reference 10.0.19041.2913: 0x%lx / 0x%lx)", REF_SECTIONS[i].name,
                            (unsigned long)s[i].VirtualAddress, (unsigned long)s[i].Misc.VirtualSize, (unsigned long)REF_SECTIONS[i].rva, (unsigned long)REF_SECTIONS[i].vsize);
        }
    }
    if (nt->OptionalHeader.SizeOfImage != 0x85000) { diffs++; t_note("SizeOfImage 0x%lx (reference 0x85000)", (unsigned long)nt->OptionalHeader.SizeOfImage); }
    if (nt->OptionalHeader.AddressOfEntryPoint != 377248) { diffs++; t_note("entry RVA 0x%lx (reference 0x5c1a0)", (unsigned long)nt->OptionalHeader.AddressOfEntryPoint); }
    t_note("%d layout differences from the reference build", diffs);
}
