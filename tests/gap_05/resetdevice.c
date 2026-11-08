/* WebAuthNCtapResetDevice: undocumented export, resolve/placement only.
 *
 * The reference decompilation shows: void return; (hWnd, ulong, GUID*) arguments; a NULL GUID is
 * replaced by a freshly generated one (UuidCreate); then the device-selection helper is invoked with
 * a fixed operation code. There is no early argument rejection before device selection, so the
 * function is never called here (it would enumerate authenticators and could show UI or reset one). */
#include "t.h"

UDECL(void, WebAuthNCtapResetDevice, (HWND hWnd, DWORD dwTimeoutMs, GUID *pCancellationId));

static IMAGE_NT_HEADERS64 *nt_of(HMODULE m) {
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)m;
    if (!m || d->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return (IMAGE_NT_HEADERS64 *)((BYTE *)m + d->e_lfanew);
}

TEST(gap5_resetdevice_resolves) {
    WebAuthNCtapResetDevice_pfn p = UN(WebAuthNCtapResetDevice);
    REQUIRE(p);
    CHECK(p != NULL);
}
TEST(gap5_resetdevice_pinned_to_webauthn) {
    FARPROC p = t_proc_in("webauthn.dll", "WebAuthNCtapResetDevice");
    REQUIRE(p);
    CHECK(p == t_proc("WebAuthNCtapResetDevice"));
}
TEST(gap5_resetdevice_inside_image_not_forwarder) {
    FARPROC p = t_proc_in("webauthn.dll", "WebAuthNCtapResetDevice");
    REQUIRE(p);
    HMODULE m = t_module("webauthn.dll");
    IMAGE_NT_HEADERS64 *n = nt_of(m);
    REQUIRE(n);
    CHECK((BYTE *)p > (BYTE *)m && (BYTE *)p < (BYTE *)m + n->OptionalHeader.SizeOfImage);
}
TEST(gap5_resetdevice_ordinal_matches_name) {
    /* alphabetical export table, Base 1: this export is listed at ordinal 31 in the reference */
    FARPROC p = t_proc_in("webauthn.dll", "WebAuthNCtapResetDevice");
    REQUIRE(p);
    FARPROC o = t_proc_ord("webauthn.dll", 31);
    CHECK(o == p);
}
TEST(gap5_resetdevice_distinct_from_manage_reset) {
    FARPROC a = t_proc_in("webauthn.dll", "WebAuthNCtapResetDevice");
    FARPROC b = t_proc_in("webauthn.dll", "WebAuthNCtapManageResetDevice");
    REQUIRE(a); REQUIRE(b);
    CHECK(a != b);
}
TEST(gap5_resetdevice_not_in_other_modules) {
    if (!t_module("webauthn.dll")) { t_skip("webauthn.dll absent"); return; }
    CHECK(t_proc_in("ncrypt.dll", "WebAuthNCtapResetDevice") == NULL);
    CHECK(t_proc_in("bcrypt.dll", "WebAuthNCtapResetDevice") == NULL);
}
TEST(gap5_resetdevice_not_called_note) {
    REQUIRE(UN(WebAuthNCtapResetDevice));
    t_note("WebAuthNCtapResetDevice not invoked: no early validation before device selection");
}
