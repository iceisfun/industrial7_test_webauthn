#include "ctap_misc.h"
/* WebAuthNCtapFreeSelectedDeviceInformation, CryptsvcDllCtrl, VirtualChannelGetInstance. */

/* ---- WebAuthNCtapFreeSelectedDeviceInformation ------------------------
 * Decomp: if (p != NULL) LocalFree(p). The export shares its body (same RVA) with WebAuthNFreeAssertion,
 * WebAuthNFreeDecodedAccountInformation, WebAuthNFreeEncodedAccountInformation and WebAuthNFreeUserEntityList. */
TEST(ctapmisc_free_null_is_noop)
{
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    SET_ERR(0x4242);
    f(NULL);
    EXPECT_EQ(GetLastError(), 0x4242);   /* NULL path performs no API call */
}
TEST(ctapmisc_free_null_repeated)
{
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    for (int i = 0; i < 1000; i++) f(NULL);
    CHECK(1);
}
TEST(ctapmisc_free_localalloc_block)
{
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    HLOCAL m = LocalAlloc(LPTR, 128);
    REQUIRE(m);
    f(m);
    CHECK(1);
}
TEST(ctapmisc_free_zeroed_struct_on_local_heap)
{
    /* A hand-built all-zero "selected device information" block that was LocalAlloc'd is released as one block. */
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    for (int i = 0; i < 100; i++) {
        void *p = LocalAlloc(LPTR, 256);
        REQUIRE(p);
        f(p);
    }
    CHECK(1);
}
TEST(ctapmisc_free_many_sizes)
{
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    static const SIZE_T sz[] = { 1, 2, 7, 8, 15, 16, 17, 255, 256, 4096, 65536, 1u << 20 };
    for (unsigned i = 0; i < sizeof sz / sizeof *sz; i++) {
        void *p = LocalAlloc(LMEM_FIXED, sz[i]);
        REQUIRE(p);
        memset(p, 0xA5, sz[i]);
        f(p);
    }
    CHECK(1);
}
TEST(ctapmisc_free_same_entry_as_sibling_free_exports)
{
    FARPROC a = t_proc("WebAuthNCtapFreeSelectedDeviceInformation"); REQUIRE(a);
    static const char *sib[] = { "WebAuthNFreeAssertion", "WebAuthNFreeDecodedAccountInformation",
                                 "WebAuthNFreeEncodedAccountInformation", "WebAuthNFreeUserEntityList" };
    for (unsigned i = 0; i < 4; i++) {
        FARPROC b = t_proc(sib[i]);
        if (!b) { t_note("%s not exported", sib[i]); continue; }
        EXPECT_EQ(a, b);                  /* identical code folding: one body at the same RVA */
    }
}
TEST(ctapmisc_free_alloc_from_wnf_string_via_this_free)
{
    WebAuthNCtapFreeSelectedDeviceInformation_pfn f = UN(WebAuthNCtapFreeSelectedDeviceInformation); REQUIRE(f);
    WebAuthNCtapGetWnfLocalizedString_pfn g = UN(WebAuthNCtapGetWnfLocalizedString); REQUIRE(g);
    LPWSTR s = NULL; DWORD fb;
    if (g(0, 9, (int)0x800705B4, 0, &s, &fb) == 0 && s) f(s);   /* both sides use the LocalAlloc heap */
    CHECK(1);
}

/* ---- CryptsvcDllCtrl ----------------------------------------------------
 * ULONG CryptsvcDllCtrl(ULONG op, ULONG a, ULONG b, void *p)
 *   op 1: starts the CTAP RPC service     -- NEVER called here (service side effect)
 *   op 2: stops it                        -- NEVER called here
 *   op 3: cancels RPCs only when b is 6 or 7, otherwise returns 0 with no effect
 *   op 4: signals device-change waiters only when b is 0x8000/0x8003/0x8004 and p->[1]==5 (p dereferenced
 *         only then); returns 0 otherwise
 *   any other op: returns 0x8000FFFF (E_UNEXPECTED) */
TEST(ctapmisc_cryptsvc_op0_unexpected)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    EXPECT_EQ(f(0, 0, 0, NULL), 0x8000FFFFu);
}
TEST(ctapmisc_cryptsvc_unknown_ops_table)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    static const ULONG ops[] = { 0, 5, 6, 7, 8, 9, 10, 15, 16, 31, 32, 100, 255, 256, 0x1000, 0x10000,
                                 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
    for (unsigned i = 0; i < sizeof ops / sizeof *ops; i++) {
        ULONG r = f(ops[i], 0, 0, NULL);
        CHECKF(r == 0x8000FFFFu, "op=0x%lx r=0x%lx", ops[i], r);
    }
}
TEST(ctapmisc_cryptsvc_unknown_op_ignores_other_args)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    BYTE buf[64] = { 0 };
    EXPECT_EQ(f(9, 6, 6, buf), 0x8000FFFFu);
    EXPECT_EQ(f(0, 0xFFFFFFFFu, 0x8000, buf), 0x8000FFFFu);
    EXPECT_EQ(f(5, 1, 7, NULL), 0x8000FFFFu);
}
TEST(ctapmisc_cryptsvc_op_range_all_unexpected_except_1_to_4)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    for (ULONG op = 5; op < 2000; op++) {
        ULONG r = f(op, 0, 0, NULL);
        if (r != 0x8000FFFFu) { CHECKF(0, "op=%lu r=0x%lx", op, r); break; }
    }
}
TEST(ctapmisc_cryptsvc_op3_non_cancel_codes_return_zero)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    static const ULONG b[] = { 0, 1, 2, 3, 4, 5, 8, 9, 0x8000, 0xFFFFFFFFu };   /* excludes 6 and 7 */
    for (unsigned i = 0; i < sizeof b / sizeof *b; i++) {
        ULONG r = f(3, 0, b[i], NULL);
        CHECKF(r == 0, "b=0x%lx r=0x%lx", b[i], r);
    }
}
TEST(ctapmisc_cryptsvc_op3_a_param_ignored)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    EXPECT_EQ(f(3, 0xFFFFFFFFu, 0, NULL), 0);
    EXPECT_EQ(f(3, 1, 1, NULL), 0);
}
TEST(ctapmisc_cryptsvc_op4_non_device_event_codes_do_not_touch_pointer)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    static const ULONG b[] = { 0, 1, 0x7FFF, 0x8001, 0x8002, 0x8005, 0x8100, 0xFFFFFFFFu };  /* not 0x8000/0x8003/0x8004 */
    for (unsigned i = 0; i < sizeof b / sizeof *b; i++) {
        ULONG r = f(4, 0, b[i], NULL);                 /* p is never dereferenced for these codes */
        CHECKF(r == 0, "b=0x%lx r=0x%lx", b[i], r);
    }
}
TEST(ctapmisc_cryptsvc_op4_device_arrival_with_wrong_type_is_noop)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    DWORD hdr[8];
    static const ULONG codes[] = { 0x8000, 0x8003, 0x8004 };
    for (unsigned i = 0; i < 3; i++) {
        memset(hdr, 0, sizeof hdr);          /* dword[1] (device type) != 5: nothing is signalled */
        EXPECT_EQ(f(4, 0, codes[i], hdr), 0);
        hdr[1] = 4;
        EXPECT_EQ(f(4, 0, codes[i], hdr), 0);
        hdr[1] = 6;
        EXPECT_EQ(f(4, 0, codes[i], hdr), 0);
    }
}
TEST(ctapmisc_cryptsvc_ctrl_ops_resolved_but_start_stop_not_invoked)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    /* ops 1 (start service) and 2 (stop service) are deliberately not exercised by the corpus */
    t_note("CryptsvcDllCtrl ops 1/2 start/stop the CTAP RPC service and are not called");
    CHECK(t_proc_ord("webauthn.dll", 1) == (FARPROC)f);
}
TEST(ctapmisc_cryptsvc_ordinal_1_matches_name)
{
    FARPROC a = t_proc_in("webauthn.dll", "CryptsvcDllCtrl"); REQUIRE(a);
    EXPECT_EQ(t_proc_ord("webauthn.dll", 1), a);
}
TEST(ctapmisc_cryptsvc_does_not_set_lasterror_for_unknown_op)
{
    CryptsvcDllCtrl_pfn f = UN(CryptsvcDllCtrl); REQUIRE(f);
    SET_ERR(0x3131);
    ULONG r = f(77, 0, 0, NULL);
    EXPECT_EQ(r, 0x8000FFFFu);
    EXPECT_EQ(GetLastError(), 0x3131);
}

/* ---- VirtualChannelGetInstance --------------------------------------------
 * LONG VirtualChannelGetInstance(REFGUID iid, ULONG *pcount, void **ppv)
 *   iid == {A1230201-1439-4E62-A414-190D0AC3D40E} (the WebAuthN DVC plugin id):
 *       ppv == NULL  -> *pcount = 1, returns S_OK
 *       ppv != NULL  -> creates the DVC plugin object; on success *pcount = 1, *ppv = IWTSPlugin*, S_OK
 *   any other iid  -> returns 0x80004002 (E_NOINTERFACE); outputs are not touched and may be NULL. */
static const GUID IID_DVC = { 0xa1230201, 0x1439, 0x4e62, { 0xa4, 0x14, 0x19, 0x0d, 0x0a, 0xc3, 0xd4, 0x0e } };
typedef struct { HRESULT (WINAPI *QI)(void *, const GUID *, void **); ULONG (WINAPI *AddRef)(void *); ULONG (WINAPI *Release)(void *); } unk_vtbl;
static void rel(void *p) { if (p) (*(unk_vtbl **)p)->Release(p); }

TEST(ctapmisc_vc_count_query_with_null_ppv)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n = 0xFFFF;
    LONG hr = f(&IID_DVC, &n, NULL);
    EXPECT_EQ(hr, 0);
    EXPECT_EQ(n, 1);
}
TEST(ctapmisc_vc_count_query_repeatable)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    for (int i = 0; i < 20; i++) {
        ULONG n = 0;
        EXPECT_EQ(f(&IID_DVC, &n, NULL), 0);
        EXPECT_EQ(n, 1);
    }
}
TEST(ctapmisc_vc_wrong_guid_e_nointerface_null_outputs)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    static const GUID bad = { 0xa1230201, 0x1439, 0x4e62, { 0xa4, 0x14, 0x19, 0x0d, 0x0a, 0xc3, 0xd4, 0x0f } };
    LONG hr = f(&bad, NULL, NULL);          /* outputs are not dereferenced on the mismatch path */
    EXPECT_EQ(hr, (LONG)0x80004002);
}
TEST(ctapmisc_vc_wrong_guid_leaves_outputs_untouched)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    static const GUID bad = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
    ULONG n = 0x1234; void *p = (void *)(ULONG_PTR)0x5678;
    LONG hr = f(&bad, &n, &p);
    EXPECT_EQ(hr, (LONG)0x80004002);
    EXPECT_EQ(n, 0x1234);
    EXPECT_EQ(p, 0x5678);
}
TEST(ctapmisc_vc_wrong_guid_differing_in_each_field)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    GUID g[5];
    for (int i = 0; i < 5; i++) g[i] = IID_DVC;
    g[0].Data1 ^= 1; g[1].Data2 ^= 1; g[2].Data3 ^= 1; g[3].Data4[0] ^= 1; g[4].Data4[7] ^= 0x80;
    for (int i = 0; i < 5; i++) {
        ULONG n = 99; void *p = NULL;
        EXPECT_EQ(f(&g[i], &n, &p), (LONG)0x80004002);
        EXPECT_EQ(n, 99);
        EXPECT_EQ(p, NULL);
    }
}
TEST(ctapmisc_vc_well_known_iids_rejected)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    static const GUID iunk = { 0, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    static const GUID iwts = { 0xA1230201, 0x1439, 0x4E62, { 0xA4, 0x14, 0x19, 0x0D, 0x0A, 0xC3, 0xD4, 0x0E } };
    ULONG n = 0;
    EXPECT_EQ(f(&iunk, &n, NULL), (LONG)0x80004002);
    EXPECT_EQ(n, 0);
    EXPECT_EQ(f(&iwts, &n, NULL), 0);     /* sanity: the matching one succeeds */
    EXPECT_EQ(n, 1);
}
TEST(ctapmisc_vc_create_instance)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n = 0; void *p = NULL;
    LONG hr = f(&IID_DVC, &n, &p);
    if (hr < 0) { t_note("VirtualChannelGetInstance create failed 0x%08lx", (unsigned long)hr); CHECK(p == NULL); return; }
    EXPECT_EQ(hr, 0);
    EXPECT_EQ(n, 1);
    CHECK(p != NULL);
    rel(p);
}
TEST(ctapmisc_vc_create_failure_leaves_outputs_untouched)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n = 0x77; void *p = (void *)(ULONG_PTR)0x88;
    LONG hr = f(&IID_DVC, &n, &p);
    if (hr < 0) { EXPECT_EQ(n, 0x77); EXPECT_EQ(p, 0x88); }
    else { EXPECT_EQ(n, 1); CHECK(p != (void *)0x88); rel(p); }
}
TEST(ctapmisc_vc_two_calls_instances)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n1 = 0, n2 = 0; void *p1 = NULL, *p2 = NULL;
    LONG h1 = f(&IID_DVC, &n1, &p1);
    LONG h2 = f(&IID_DVC, &n2, &p2);
    if (h1 < 0 || h2 < 0) { t_note("create failed 0x%08lx/0x%08lx", (unsigned long)h1, (unsigned long)h2); rel(p1); rel(p2); return; }
    EXPECT_EQ(n1, 1); EXPECT_EQ(n2, 1);
    t_note("two calls return %s object (%p / %p)", p1 == p2 ? "the same" : "different", p1, p2);
    if (p1 != p2) { rel(p1); rel(p2); } else { rel(p1); rel(p2); }
}
TEST(ctapmisc_vc_instance_is_iunknown)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n = 0; void *p = NULL;
    if (f(&IID_DVC, &n, &p) < 0 || !p) { t_skip("could not create plugin"); return; }
    unk_vtbl *vt = *(unk_vtbl **)p;
    ULONG r1 = vt->AddRef(p);
    ULONG r2 = vt->Release(p);
    CHECK(r1 >= 2);
    CHECK(r2 >= 1);
    CHECK(r1 == r2 + 1);
    void *q = NULL;
    static const GUID iid_unknown = { 0, 0, 0, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    HRESULT hr = vt->QI(p, &iid_unknown, &q);
    CHECK(hr == 0 && q == p);
    if (q) rel(q);
    rel(p);
}
TEST(ctapmisc_vc_instance_rejects_unknown_iid_in_qi)
{
    VirtualChannelGetInstance_pfn f = UN(VirtualChannelGetInstance); REQUIRE(f);
    ULONG n = 0; void *p = NULL;
    if (f(&IID_DVC, &n, &p) < 0 || !p) { t_skip("could not create plugin"); return; }
    static const GUID bogus = { 0xdeadbeef, 1, 2, { 3, 4, 5, 6, 7, 8, 9, 10 } };
    void *q = (void *)1;
    HRESULT hr = (*(unk_vtbl **)p)->QI(p, &bogus, &q);
    CHECK(hr == (HRESULT)0x80004002);
    CHECK(q == NULL);
    rel(p);
}
TEST(ctapmisc_vc_ordinal_6_matches_name)
{
    FARPROC a = t_proc_in("webauthn.dll", "VirtualChannelGetInstance"); REQUIRE(a);
    EXPECT_EQ(t_proc_ord("webauthn.dll", 6), a);
}
