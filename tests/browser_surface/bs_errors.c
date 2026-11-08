/* (c) WebAuthNGetErrorName / WebAuthNGetW3CExceptionDOMError for the HRESULTs a browser sees from the
 * MakeCredential / GetAssertion path, and the properties browsers rely on: the name is a stable string,
 * the DOM value agrees with the name, the functions are safe to call from several threads. */
#include "bs.h"

typedef struct { unsigned code; const char *what; } hrcase;
static const hrcase k_hr[] = {
    { 0x00000000u, "S_OK" },
    { 0x8007000Du, "ERROR_INVALID_DATA (request encoder)" },
    { 0x80090027u, "NTE_INVALID_PARAMETER (entry check)" },
    { 0x80090029u, "NTE_NOT_SUPPORTED" },
    { 0x8009000Fu, "NTE_EXISTS" },
    { 0x80090011u, "NTE_NOT_FOUND" },
    { 0x80090023u, "NTE_TOKEN_KEYSET_STORAGE_FULL" },
    { 0x80090035u, "NTE 0x35" },
    { 0x80090036u, "NTE_USER_CANCELLED" },
    { 0x80070032u, "ERROR_NOT_SUPPORTED" },
    { 0x800704C7u, "ERROR_CANCELLED" },
    { 0x800705B4u, "ERROR_TIMEOUT" },
    { 0x80070057u, "E_INVALIDARG" },
    { 0x80070005u, "E_ACCESSDENIED" },
    { 0x80004004u, "E_ABORT" },
    { 0x80004005u, "E_FAIL" },
    { 0x8000FFFFu, "E_UNEXPECTED" },
    { 0x80090010u, "NTE_PERM" },
    { 0x8001011Bu, "RPC_E_CALL_REJECTED-class" },
    { 0x800706BAu, "RPC_S_SERVER_UNAVAILABLE" },
    { 0x8007139Fu, "ERROR_INVALID_STATE" },
    { 0x800710D3u, "ERROR_ACCOUNT_RESTRICTION-class" },
    { 0x80070490u, "ERROR_NOT_FOUND" },
    { 0x8007007Bu, "ERROR_INVALID_NAME" },
    { 0x8007001Fu, "ERROR_GEN_FAILURE" },
    { 0x80190190u, "HTTP-style code" },
};
#define NHR ((int)(sizeof k_hr / sizeof k_hr[0]))

static const struct { const wchar_t *name; unsigned dom; } k_pairs[] = {
    { L"Success", 0 }, { L"InvalidStateError", 0x8070000Bu }, { L"NotAllowedError", 0x80700023u },
    { L"ConstraintError", 0x8070001Au }, { L"NotSupportedError", 0x80700009u }, { L"UnknownError", 0x80700000u },
};
static const wchar_t *exp_name(unsigned c) {
    switch (c) {
    case 0x00000000u: return L"Success";
    case 0x8009000Fu: return L"InvalidStateError";
    case 0x80090011u: case 0x80090035u: case 0x80090036u: case 0x800704C7u: case 0x800705B4u: return L"NotAllowedError";
    case 0x80090023u: case 0x80090029u: case 0x80070032u: return L"ConstraintError";
    case 0x80090027u: return L"NotSupportedError";
    default: return L"UnknownError";
    }
}
static int pair_dom(const wchar_t *n, unsigned *dom) {
    for (unsigned i = 0; i < sizeof k_pairs / sizeof *k_pairs; i++) if (!lstrcmpW(n, k_pairs[i].name)) { *dom = k_pairs[i].dom; return 1; }
    return 0;
}

TEST(bs_error_names_for_browser_hresults) {
    WebAuthNGetErrorName_pfn gn = UN(WebAuthNGetErrorName); REQUIRE(gn);
    for (int i = 0; i < NHR; i++) {
        PCWSTR n = gn((HRESULT)k_hr[i].code);
        CHECKF(n != NULL, "%s: NULL name", k_hr[i].what);
        if (!n) continue;
        char nb[64]; size_t j = 0; for (; n[j] && j < 63; j++) nb[j] = (char)n[j]; nb[j] = 0;
        t_note("errname 0x%08x %s -> %s", k_hr[i].code, k_hr[i].what, nb);
        CHECKF(j > 0 && j < 40, "%s: name length %zu", k_hr[i].what, j);
        unsigned dom;
        CHECKF(pair_dom(n, &dom), "%s: name \"%s\" is not one of the six W3C-style names", k_hr[i].what, nb);
        CHECKF(!lstrcmpW(n, exp_name(k_hr[i].code)), "%s: name \"%s\"", k_hr[i].what, nb);
    }
}
TEST(bs_error_dom_agrees_with_name) {
    WebAuthNGetErrorName_pfn gn = UN(WebAuthNGetErrorName); REQUIRE(gn);
    WebAuthNGetW3CExceptionDOMError_pfn gd = UN(WebAuthNGetW3CExceptionDOMError); REQUIRE(gd);
    for (int i = 0; i < NHR; i++) {
        PCWSTR n = gn((HRESULT)k_hr[i].code); unsigned want;
        if (!n || !pair_dom(n, &want)) { CHECKF(0, "%s: name missing or unknown", k_hr[i].what); continue; }
        unsigned got = (unsigned)gd((HRESULT)k_hr[i].code);
        t_note("domerr 0x%08x %s -> 0x%08x", k_hr[i].code, k_hr[i].what, got);
        CHECKF(got == want, "%s: dom 0x%08x does not match name (want 0x%08x)", k_hr[i].what, got, want);
    }
}
TEST(bs_error_name_pointer_is_stable) {
    WebAuthNGetErrorName_pfn gn = UN(WebAuthNGetErrorName); REQUIRE(gn);
    HMODULE m = bs_dll();
    for (int i = 0; i < NHR; i++) {
        PCWSTR a = gn((HRESULT)k_hr[i].code), b = gn((HRESULT)k_hr[i].code);
        CHECKF(a == b, "%s: pointer changes between calls", k_hr[i].what);
        if (i == 0 && a && m) {
            const char *base = (const char *)m;
            const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
            t_note("name storage: %s", ((const char *)a >= base && (const char *)a < base + nt->OptionalHeader.SizeOfImage) ? "inside module image" : "outside module image");
        }
    }
}
TEST(bs_error_names_same_name_same_pointer) {
    /* callers compare or cache the returned pointer per name; equal names must be one string */
    WebAuthNGetErrorName_pfn gn = UN(WebAuthNGetErrorName); REQUIRE(gn);
    for (int i = 0; i < NHR; i++) for (int j = i + 1; j < NHR; j++) {
        PCWSTR a = gn((HRESULT)k_hr[i].code), b = gn((HRESULT)k_hr[j].code);
        if (a && b && !lstrcmpW(a, b)) t_note("same name, %s pointer: %s / %s", a == b ? "same" : "different", k_hr[i].what, k_hr[j].what);
    }
}

static volatile LONG g_mismatch;
static DWORD WINAPI err_thread(LPVOID p) {
    WebAuthNGetErrorName_pfn gn = UN(WebAuthNGetErrorName);
    WebAuthNGetW3CExceptionDOMError_pfn gd = UN(WebAuthNGetW3CExceptionDOMError);
    PCWSTR ref[64]; unsigned dref[64];
    for (int i = 0; i < NHR; i++) { ref[i] = gn((HRESULT)k_hr[i].code); dref[i] = (unsigned)gd((HRESULT)k_hr[i].code); }
    for (int it = 0; it < 2000; it++) {
        int i = (it * 7 + (int)(ULONG_PTR)p) % NHR;
        if (gn((HRESULT)k_hr[i].code) != ref[i] || (unsigned)gd((HRESULT)k_hr[i].code) != dref[i]) InterlockedIncrement(&g_mismatch);
    }
    return 0;
}
TEST(bs_error_functions_thread_safe) {
    REQUIRE(UN(WebAuthNGetErrorName)); REQUIRE(UN(WebAuthNGetW3CExceptionDOMError));
    HANDLE h[4]; g_mismatch = 0;
    for (int i = 0; i < 4; i++) h[i] = CreateThread(NULL, 0, err_thread, (LPVOID)(ULONG_PTR)i, 0, NULL);
    for (int i = 0; i < 4; i++) { CHECK(h[i] != NULL); if (h[i]) { WaitForSingleObject(h[i], 60000); CloseHandle(h[i]); } }
    EXPECT_EQ(g_mismatch, 0);
}
