/* Shared helpers for the whole-DLL export sweeps: PE image parsing of the loaded webauthn.dll. */
#ifndef SWEEP_H
#define SWEEP_H
#include "t.h"
#include "sweep_table.h"

#ifndef SW_DLL
#define SW_DLL "webauthn.dll"
#endif

struct sw_exp { const char *name; unsigned ord; DWORD rva; int documented; };
static const struct sw_exp sw_exports[] = {
#define SW_ROW(n, o, r, d) { #n, o, r, d },
    SWEEP_EXPORTS(SW_ROW)
#undef SW_ROW
};
#define SW_COUNT ((int)(sizeof(sw_exports) / sizeof(sw_exports[0])))

static HMODULE sw_mod(void) { return t_module(SW_DLL); }

static IMAGE_NT_HEADERS64 *sw_nt(HMODULE h) {
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)h;
    if (!h || d->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64 *n = (IMAGE_NT_HEADERS64 *)((BYTE *)h + d->e_lfanew);
    return n->Signature == IMAGE_NT_SIGNATURE ? n : NULL;
}

static IMAGE_EXPORT_DIRECTORY *sw_expdir(HMODULE h, DWORD *dir_rva, DWORD *dir_size) {
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    if (!n) return NULL;
    IMAGE_DATA_DIRECTORY *dd = &n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dd->VirtualAddress) return NULL;
    if (dir_rva) *dir_rva = dd->VirtualAddress;
    if (dir_size) *dir_size = dd->Size;
    return (IMAGE_EXPORT_DIRECTORY *)((BYTE *)h + dd->VirtualAddress);
}

/* Section containing an RVA, or NULL (headers / outside image). */
static IMAGE_SECTION_HEADER *sw_section(HMODULE h, DWORD rva) {
    IMAGE_NT_HEADERS64 *n = sw_nt(h);
    if (!n) return NULL;
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(n);
    for (int i = 0; i < n->FileHeader.NumberOfSections; i++) {
        DWORD sz = s[i].Misc.VirtualSize > s[i].SizeOfRawData ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
        if (rva >= s[i].VirtualAddress && rva < s[i].VirtualAddress + sz) return &s[i];
    }
    return NULL;
}

static const struct sw_exp *sw_find(const char *name) {
    for (int i = 0; i < SW_COUNT; i++) if (!strcmp(sw_exports[i].name, name)) return &sw_exports[i];
    return NULL;
}

#define SW_NEED_MODULE() HMODULE h = sw_mod(); do { if (!h) { t_skip(SW_DLL " not loadable"); return; } } while (0)
#endif
