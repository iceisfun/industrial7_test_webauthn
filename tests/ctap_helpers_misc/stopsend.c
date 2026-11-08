#include "ctap_misc.h"
/* WebAuthNCtapIsStopSendCommandError. Decomp-derived semantics:
 *   FALSE for 0x80090035 and 0x800705B4 (checked first);
 *   TRUE  for 0x8001011B 0x8001011F 0x80010006 0x8010002E;
 *   otherwise TRUE unless WebAuthNGetW3CExceptionDOMError(hr) == 0x80700000 (UnknownError / unmapped).
 * The DOM mapping is reproduced below from the decomp of the internal error-name table. */

#define H(x) ((HRESULT)(x))

static unsigned dom(int h)
{
    if (h < -0x7ff6ffdc) {
        if (h == -0x7ff6ffdd || h == -0x7ff8ffce) return 0x8070001a;          /* ConstraintError  */
        if (h == -0x7ff8fb39 || h == -0x7ff8fa4c || h == -0x7ff6ffef) return 0x80700023; /* NotAllowedError */
        if (h == -0x7ff6fff1) return 0x8070000b;                                /* InvalidStateError */
        return 0x80700000;
    }
    if (h == -0x7ff6ffd9) return 0x80700009;                                    /* NotSupportedError */
    if (h == -0x7ff6ffd7) return 0x8070001a;                                    /* ConstraintError   */
    if (h > -0x7ff6ffcc) {
        if (h < -0x7ff6ffc9) return 0x80700023;                                 /* NotAllowedError   */
        if (h == 0) return 0;
    }
    return 0x80700000;
}
static int model(int h)
{
    if (h == -0x7ff6ffcb || h == -0x7ff8fa4c) return 0;
    if (h == -0x7ffefee5 || h == -0x7ffefee1 || h == -0x7ffefffa || h == -0x7fefffd2) return 1;
    return dom(h) != 0x80700000u;
}

/* Explicit literal cases: STOP_CASE(name, hresult, expected) */
#define STOP_CASE(n, hr, exp) \
    TEST(ctapmisc_stop_##n) { \
        WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f); \
        BOOL r = f(H(hr)); \
        EXPECT_EQ(r, exp); \
    }

/* explicit FALSE (checked before anything else) */
STOP_CASE(nte_bad_data_0x80090035,   0x80090035u, 0)
STOP_CASE(win32_1460_timeout,        0x800705B4u, 0)   /* HRESULT_FROM_WIN32(ERROR_TIMEOUT) */
/* explicit TRUE */

STOP_CASE(rpc_0x8001011B,            0x8001011Bu, 1)
STOP_CASE(rpc_0x8001011F,            0x8001011Fu, 1)
STOP_CASE(rpc_e_cantcallout_0x80010006, 0x80010006u, 1)
STOP_CASE(scard_0x8010002E,          0x8010002Eu, 1)
/* DOM-mapped values (mapped => not UnknownError => TRUE) */
STOP_CASE(dom_constraint_0x80090023, 0x80090023u, 1)
STOP_CASE(dom_constraint_0x80070032, 0x80070032u, 1)
STOP_CASE(dom_notallowed_0x800704C7, 0x800704C7u, 1)   /* ERROR_CANCELLED */
STOP_CASE(dom_invalidstate_0x8009000F, 0x8009000Fu, 1)
STOP_CASE(dom_notallowed_0x80090011, 0x80090011u, 1)
STOP_CASE(dom_notsupported_0x80090027, 0x80090027u, 1)
STOP_CASE(dom_constraint_0x80090029, 0x80090029u, 1)
STOP_CASE(dom_notallowed_0x80090036, 0x80090036u, 1)
STOP_CASE(dom_success_s_ok,          0x00000000u, 1)   /* "Success" maps to DOM 0, which is not 0x80700000 */
/* unmapped => UnknownError => FALSE */
STOP_CASE(unk_e_fail,                0x80004005u, 0)
STOP_CASE(unk_e_invalidarg,          0x80070057u, 0)
STOP_CASE(unk_e_outofmemory,         0x8007000Eu, 0)
STOP_CASE(unk_e_accessdenied,        0x80070005u, 0)
STOP_CASE(unk_e_notimpl,             0x80004001u, 0)
STOP_CASE(unk_e_pointer,             0x80004003u, 0)
STOP_CASE(unk_e_unexpected,          0x8000FFFFu, 0)
STOP_CASE(unk_0x80090034,            0x80090034u, 0)   /* just below the NotAllowed pair */
STOP_CASE(unk_0x80090037,            0x80090037u, 0)   /* just above it */
STOP_CASE(unk_0x80090024,            0x80090024u, 0)
STOP_CASE(unk_0x80090038,            0x80090038u, 0)
STOP_CASE(unk_s_false,               0x00000001u, 0)   /* S_FALSE is not "Success" (only 0 is) */
STOP_CASE(unk_minus_one,             0xFFFFFFFFu, 0)
STOP_CASE(unk_int_min,               0x80000000u, 0)
STOP_CASE(unk_int_max,               0x7FFFFFFFu, 0)
STOP_CASE(unk_ntstatus_style,        0xC0000005u, 0)

TEST(ctapmisc_stop_return_is_exactly_0_or_1)
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    static const unsigned v[] = { 0, 1, 0x80004005u, 0x80090035u, 0x800705B4u, 0x8001011Bu, 0x80090011u, 0xFFFFFFFFu };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        ULONG_PTR r = (ULONG_PTR)f(H(v[i]));
        CHECKF(r == 0 || r == 1, "hr=0x%08x r=0x%llx", v[i], (unsigned long long)r);
    }
}

TEST(ctapmisc_stop_deterministic)
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    static const unsigned v[] = { 0, 0x80004005u, 0x80090035u, 0x8001011Bu, 0x80090011u };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        BOOL first = f(H(v[i]));
        for (int k = 0; k < 50; k++) EXPECT_EQ(f(H(v[i])), first);
    }
}

TEST(ctapmisc_stop_no_lasterror_needed)
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    SET_ERR(0x1234);
    BOOL r = f(H(0x80090011u));
    EXPECT_EQ(r, 1);
    t_note("GetLastError after IsStopSendCommandError = %lu (not asserted)", GetLastError());
}

/* Sweep the neighbourhood of every boundary against the decomp-derived model. */
static const unsigned boundary[] = {
    0x80090035u, 0x800705B4u, 0x8001011Bu, 0x8001011Fu, 0x80010006u, 0x8010002Eu,
    0x80090023u, 0x80070032u, 0x800704C7u, 0x8009000Fu, 0x80090011u, 0x80090027u, 0x80090029u,
    0x80090036u, 0x80090024u, 0x80090034u, 0x80090037u, 0x80090038u, 0x00000000u,
};
TEST(ctapmisc_stop_neighbour_sweep)
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned i = 0; i < sizeof boundary / sizeof *boundary; i++)
        for (int d = -8; d <= 8; d++) {
            int h = (int)(boundary[i] + (unsigned)d);
            BOOL r = f(h);
            if (r != model(h)) { bad++; CHECKF(0, "hr=0x%08x got %d want %d", (unsigned)h, (int)r, model(h)); }
        }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_nte_range)       /* 0x80090000..0x80090FFF */
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0x80090000u; h < 0x80091000u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x got %d want %d", h, (int)f((int)h), model((int)h)); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_win32_range)     /* HRESULT_FROM_WIN32(0..0x1000) */
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0x80070000u; h < 0x80071000u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x got %d want %d", h, (int)f((int)h), model((int)h)); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_rpc_range)       /* 0x80010000..0x800101FF */
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0x80010000u; h < 0x80010200u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x got %d want %d", h, (int)f((int)h), model((int)h)); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_scard_range)     /* 0x80100000..0x801000FF */
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0x80100000u; h < 0x80100100u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x got %d want %d", h, (int)f((int)h), model((int)h)); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_low_range)       /* 0x80000000..0x8000FFFF generic COM errors, and small positives */
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0x80000000u; h < 0x80010000u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x got %d want %d", h, (int)f((int)h), model((int)h)); }
    for (unsigned h = 0; h < 0x100; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x", h); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_sweep_ntstatus_style)
{
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    int bad = 0;
    for (unsigned h = 0xC0000000u; h < 0xC0000400u; h++)
        if (f((int)h) != model((int)h)) { if (bad++ < 10) CHECKF(0, "hr=0x%08x", h); }
    CHECK(bad == 0);
}
TEST(ctapmisc_stop_true_set_is_closed_under_dom_mapping)
{
    /* Every DOM-mapped value (other than the two explicit FALSE entries) must be TRUE. */
    WebAuthNCtapIsStopSendCommandError_pfn f = UN(WebAuthNCtapIsStopSendCommandError); REQUIRE(f);
    static const unsigned mapped[] = { 0x80090023u, 0x80070032u, 0x800704C7u, 0x8009000Fu, 0x80090011u,
                                       0x80090027u, 0x80090029u, 0x80090036u, 0 };
    for (unsigned i = 0; i < sizeof mapped / sizeof *mapped; i++) EXPECT_EQ(f(H(mapped[i])), 1);
    /* the two explicit exceptions are DOM-mapped (NotAllowed) yet FALSE */
    EXPECT_EQ(f(H(0x80090035u)), 0);
    EXPECT_EQ(f(H(0x800705B4u)), 0);
}
