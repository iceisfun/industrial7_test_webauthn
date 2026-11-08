/* dx_gap_00: CNG context configuration writers. These modify the machine-wide CNG configuration
 * (HKLM) and need an elevated token; every test uses a context name private to this process, removes it
 * before and after, and skips when the caller lacks the rights. Run only with the destructive switch. */
#include "gap0.h"

static wchar_t g_ctx[64];
static const wchar_t *dxg_name(void) {
    if (!g_ctx[0]) wsprintfW(g_ctx, L"Gap0DxCtx_%lu", (unsigned long)GetCurrentProcessId());
    return g_ctx;
}
static void dxg_cleanup(void) {
    if (U(BCryptRemoveContextFunction)) U(BCryptRemoveContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN");
    if (U(BCryptDeleteContext)) U(BCryptDeleteContext)(CRYPT_LOCAL, dxg_name());
}
static int dxg_have(void) {
    if (t_is_wine()) return 0;   /* the context configuration exports abort under Wine */
    return U(BCryptCreateContext) && U(BCryptDeleteContext) && U(BCryptQueryContextConfiguration) && U(BCryptEnumContexts)
        && U(BCryptAddContextFunction) && U(BCryptRemoveContextFunction) && U(BCryptEnumContextFunctions) && U(BCryptFreeBuffer);
}
static int dxg_contains_ctx(void) {
    CRYPT_CONTEXTS *c = NULL; ULONG cb = 0; int found = 0;
    if (U(BCryptEnumContexts)(CRYPT_LOCAL, &cb, &c) < 0 || !c) return 0;
    for (ULONG i = 0; i < c->cContexts; i++) if (!lstrcmpiW(c->rgpszContexts[i], dxg_name())) found = 1;
    U(BCryptFreeBuffer)(c); return found;
}
/* create or skip; returns 1 when the context exists and the test may proceed */
static int dxg_create(void) {
    dxg_cleanup();
    CRYPT_CONTEXT_CONFIG cfg = { 0, 0 };
    NTSTATUS st = U(BCryptCreateContext)(CRYPT_LOCAL, dxg_name(), &cfg);
    if ((ULONG)st == G0_ACCESS_DENIED) { t_skip("CNG configuration is not writable (needs elevation)"); return 0; }
    G0_OKST(st);
    return st >= 0;
}

TEST(dx_gap0_context_lifecycle) {
    if (!dxg_have()) { t_skip("missing export"); return; }
    if (!dxg_create()) return;
    CHECK(dxg_contains_ctx());
    CRYPT_CONTEXT_CONFIG *q = NULL; ULONG cb = 0;
    G0_OKST(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, dxg_name(), &cb, &q));
    if (q) { EXPECT_EQ(q->dwFlags, 0); CHECK(cb >= sizeof *q); U(BCryptFreeBuffer)(q); }
    G0_OKST(U(BCryptDeleteContext)(CRYPT_LOCAL, dxg_name()));
    CHECK(!dxg_contains_ctx());
    q = NULL;
    NTSTATUS st = U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, dxg_name(), &cb, &q);
    t_note("Query after delete -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0 && q == NULL);
    st = U(BCryptDeleteContext)(CRYPT_LOCAL, dxg_name());
    t_note("second DeleteContext -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0);
    dxg_cleanup();
}
TEST(dx_gap0_context_duplicate_create_note) {
    if (!dxg_have()) { t_skip("missing export"); return; }
    if (!dxg_create()) return;
    CRYPT_CONTEXT_CONFIG cfg = { 0, 0 };
    NTSTATUS st = U(BCryptCreateContext)(CRYPT_LOCAL, dxg_name(), &cfg);
    t_note("CreateContext of an existing name -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0);
    dxg_cleanup();
}
TEST(dx_gap0_context_configure_and_requery) {
    if (!dxg_have() || !U(BCryptConfigureContext)) { t_skip("missing export"); return; }
    if (!dxg_create()) return;
    CRYPT_CONTEXT_CONFIG cfg = { 0x1, 0 }, *q = NULL; ULONG cb = 0;
    NTSTATUS st = U(BCryptConfigureContext)(CRYPT_LOCAL, dxg_name(), &cfg);
    t_note("ConfigureContext(0x1) -> 0x%08lx", (unsigned long)st);
    if (st >= 0) {
        G0_OKST(U(BCryptQueryContextConfiguration)(CRYPT_LOCAL, dxg_name(), &cb, &q));
        if (q) { EXPECT_EQ(q->dwFlags, 0x1); U(BCryptFreeBuffer)(q); }
    }
    cfg.dwFlags = 0;
    G0_OKST(U(BCryptConfigureContext)(CRYPT_LOCAL, dxg_name(), &cfg));
    dxg_cleanup();
}
TEST(dx_gap0_context_configure_missing_context) {
    if (!dxg_have() || !U(BCryptConfigureContext)) { t_skip("missing export"); return; }
    dxg_cleanup();
    CRYPT_CONTEXT_CONFIG cfg = { 0, 0 };
    NTSTATUS st = U(BCryptConfigureContext)(CRYPT_LOCAL, dxg_name(), &cfg);
    if ((ULONG)st == G0_ACCESS_DENIED) { t_skip("needs elevation"); return; }
    t_note("ConfigureContext(missing) -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0);
}
TEST(dx_gap0_context_function_lifecycle) {
    if (!dxg_have() || !U(BCryptConfigureContextFunction) || !U(BCryptQueryContextFunctionConfiguration)) { t_skip("missing export"); return; }
    if (!dxg_create()) return;
    NTSTATUS st = U(BCryptAddContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", CRYPT_PRIORITY_BOTTOM);
    t_note("AddContextFunction -> 0x%08lx", (unsigned long)st);
    G0_OKST(st);
    if (st >= 0) {
        CRYPT_CONTEXT_FUNCTIONS *f = NULL; ULONG cb = 0; int found = 0;
        G0_OKST(U(BCryptEnumContextFunctions)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, &cb, &f));
        if (f) { for (ULONG i = 0; i < f->cFunctions; i++) if (!lstrcmpiW(f->rgpszFunctions[i], L"GAP0DXFN")) found = 1; U(BCryptFreeBuffer)(f); }
        CHECK(found);
        CRYPT_CONTEXT_FUNCTION_CONFIG fc = { 0, 0 }, *q = NULL;
        /* Windows 10 22H2: a freshly added function has no configuration entry (STATUS_NOT_FOUND 0xc0000225) until it is configured. */
        NTSTATUS qs = U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", &cb, &q);
        t_note("Query function configuration before configure -> 0x%08lx", (unsigned long)qs);
        if (qs >= 0 && q) U(BCryptFreeBuffer)(q);
        q = NULL;
        G0_OKST(U(BCryptConfigureContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", &fc));
        G0_OKST(U(BCryptQueryContextFunctionConfiguration)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", &cb, &q));
        if (q) { EXPECT_EQ(q->dwFlags, 0); U(BCryptFreeBuffer)(q); }
        G0_OKST(U(BCryptRemoveContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN"));
        f = NULL; found = 0;
        st = U(BCryptEnumContextFunctions)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, &cb, &f);
        if (st >= 0 && f) { for (ULONG i = 0; i < f->cFunctions; i++) if (!lstrcmpiW(f->rgpszFunctions[i], L"GAP0DXFN")) found = 1; U(BCryptFreeBuffer)(f); }
        CHECK(!found);
    }
    dxg_cleanup();
}
TEST(dx_gap0_context_function_priority_order) {
    if (!dxg_have()) { t_skip("missing export"); return; }
    if (!dxg_create()) return;
    NTSTATUS a = U(BCryptAddContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", CRYPT_PRIORITY_BOTTOM);
    NTSTATUS b = U(BCryptAddContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN2", CRYPT_PRIORITY_TOP);
    G0_OKST(a); G0_OKST(b);
    if (a >= 0 && b >= 0) {
        CRYPT_CONTEXT_FUNCTIONS *f = NULL; ULONG cb = 0;
        G0_OKST(U(BCryptEnumContextFunctions)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, &cb, &f));
        if (f && f->cFunctions >= 2) {
            CHECK(!lstrcmpiW(f->rgpszFunctions[0], L"GAP0DXFN2"));                   /* TOP inserts first */
            CHECK(!lstrcmpiW(f->rgpszFunctions[f->cFunctions - 1], L"GAP0DXFN"));  /* BOTTOM appends */
        } else CHECK(0);
        if (f) U(BCryptFreeBuffer)(f);
    }
    U(BCryptRemoveContextFunction)(CRYPT_LOCAL, dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN2");
    dxg_cleanup();
}
TEST(dx_gap0_context_writers_invalid_table) {
    if (!dxg_have() || !U(BCryptConfigureContext) || !U(BCryptConfigureContextFunction)) { t_skip("missing export"); return; }
    CRYPT_CONTEXT_CONFIG cfg = { 0, 0 }; CRYPT_CONTEXT_FUNCTION_CONFIG fc = { 0, 0 };
    static const ULONG bad[] = { 0, 3, 0x10, 0xFFFFFFFFu };
    for (size_t i = 0; i < 4; i++) {
        ST(U(BCryptCreateContext)(bad[i], dxg_name(), &cfg), G0_INVALID_PARAMETER);
        ST(U(BCryptConfigureContext)(bad[i], dxg_name(), &cfg), G0_INVALID_PARAMETER);
        ST(U(BCryptDeleteContext)(bad[i], dxg_name()), G0_INVALID_PARAMETER);
        ST(U(BCryptAddContextFunction)(bad[i], dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", CRYPT_PRIORITY_BOTTOM), G0_INVALID_PARAMETER);
        ST(U(BCryptConfigureContextFunction)(bad[i], dxg_name(), BCRYPT_CIPHER_INTERFACE, L"GAP0DXFN", &fc), G0_INVALID_PARAMETER);
    }
    CHECK(!dxg_contains_ctx());
}
