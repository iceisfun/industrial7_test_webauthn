#ifndef EN_COMMON_H
#define EN_COMMON_H
#include "t.h"

/* webauthn.h exports, declared locally. Both are plain WINAPI leaf-style wrappers
 * over one shared internal switch: name string and DOM-error HRESULT. */
UDECL(PCWSTR,  WebAuthNGetErrorName,            (HRESULT hr));
UDECL(HRESULT, WebAuthNGetW3CExceptionDOMError, (HRESULT hr));

#define EN_UNKNOWN_DOM  ((HRESULT)0x80700000)
#define EN_DOM_NOTSUPPORTED ((HRESULT)0x80700009)
#define EN_DOM_INVALIDSTATE ((HRESULT)0x8070000B)
#define EN_DOM_CONSTRAINT   ((HRESULT)0x8070001A)
#define EN_DOM_NOTALLOWED   ((HRESULT)0x80700023)

typedef struct {
    unsigned code;        /* input HRESULT */
    const wchar_t *name;  /* expected GetErrorName string */
    unsigned dom;         /* expected GetW3CExceptionDOMError result */
    const char *sym;
} en_entry;

/* Every input the switch handles specially (verified against the disassembly:
 * signed compares, 11 handled values + zero). */
static const en_entry en_table[] = {
    { 0x00000000u, L"Success",           0x00000000u, "S_OK" },
    { 0x8009000Fu, L"InvalidStateError", 0x8070000Bu, "NTE_EXISTS" },
    { 0x80090011u, L"NotAllowedError",   0x80700023u, "NTE_NOT_FOUND" },
    { 0x80090023u, L"ConstraintError",   0x8070001Au, "NTE_TOKEN_KEYSET_STORAGE_FULL" },
    { 0x80090027u, L"NotSupportedError", 0x80700009u, "NTE_INVALID_PARAMETER" },
    { 0x80090029u, L"ConstraintError",   0x8070001Au, "NTE_NOT_SUPPORTED" },
    { 0x80090035u, L"NotAllowedError",   0x80700023u, "0x80090035" },
    { 0x80090036u, L"NotAllowedError",   0x80700023u, "NTE_USER_CANCELLED" },
    { 0x80070032u, L"ConstraintError",   0x8070001Au, "HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)" },
    { 0x800704C7u, L"NotAllowedError",   0x80700023u, "HRESULT_FROM_WIN32(ERROR_CANCELLED)" },
    { 0x800705B4u, L"NotAllowedError",   0x80700023u, "HRESULT_FROM_WIN32(ERROR_TIMEOUT)" },
};
#define EN_N (sizeof(en_table)/sizeof(en_table[0]))

static int en_is_handled(unsigned c) {
    for (size_t i = 0; i < EN_N; i++) if (en_table[i].code == c) return 1;
    return 0;
}

/* expected values for any input per the table */
static const wchar_t *en_expect_name(unsigned c) {
    for (size_t i = 0; i < EN_N; i++) if (en_table[i].code == c) return en_table[i].name;
    return L"UnknownError";
}
static unsigned en_expect_dom(unsigned c) {
    for (size_t i = 0; i < EN_N; i++) if (en_table[i].code == c) return en_table[i].dom;
    return 0x80700000u;
}
#endif
