/* DPAPI-NG exports: NCryptRegisterProtectionDescriptorName (validation only), NCryptStreamOpenToProtect,
 * NCryptStreamOpenToUnprotect(Ex), NCryptStreamUpdate, NCryptStreamClose, NCryptUnprotectSecret.
 * Every call here either fails argument validation (visible in the Windows 10 reference decompilation)
 * or uses the "LOCAL=user" descriptor with NCRYPT_SILENT_FLAG, which never shows UI.
 * The state-changing success path of NCryptRegisterProtectionDescriptorName lives in dx_gap_02. */
#include "g2.h"

/* Wine's ncrypt.dll exports these as aborting stubs: skip them there. */
#undef REQUIRE
#define REQUIRE(ptr) do { if (t_is_wine()) { t_skip("Wine ncrypt stubs abort"); return; } if (!(ptr)) { t_skip("missing export: " #ptr); return; } } while (0)

#define F_SILENT 0x40u
#define F_NO_DECRYPT 0x1u

static LONG WINAPI cb_collect(void *ctx, const BYTE *d, SIZE_T cb, BOOL fin) {
    struct { BYTE *p; SIZE_T n, cap; int fin; } *c = ctx;
    if (c->n + cb > c->cap) return (LONG)0x8009000EL;
    if (cb) memcpy(c->p + c->n, d, cb);
    c->n += cb; if (fin) c->fin = 1;
    return 0;
}
static LONG WINAPI cb_nop(void *ctx, const BYTE *d, SIZE_T cb, BOOL fin) { return 0; }

/* A readable region whose first qword is not the stream magic 0xC0. */
typedef struct { ULONGLONG magic; ULONGLONG pad[63]; } __attribute__((aligned(16))) g2_sobj;

/* ---------------- NCryptRegisterProtectionDescriptorName (argument validation only) ---------------- */
TEST(gap2_regname_null_or_empty_name) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    LONG (WINAPI *f)(LPCWSTR, LPCWSTR, DWORD) = (void *)UN(NCryptRegisterProtectionDescriptorName);
    G2_EQ(f(NULL, L"LOCAL=user", 0), G2_NTE_INVALID_PARAM);
    G2_EQ(f(L"", L"LOCAL=user", 0), G2_NTE_INVALID_PARAM);
    G2_EQ(f(NULL, NULL, 0), G2_NTE_INVALID_PARAM);
    G2_EQ(f(L"", NULL, 0), G2_NTE_INVALID_PARAM);
    /* the name is validated before the flags */
    G2_EQ(f(NULL, L"LOCAL=user", 0x1), G2_NTE_INVALID_PARAM);
    G2_EQ(f(L"", L"LOCAL=user", 0xFFFFFFFF), G2_NTE_INVALID_PARAM);
}
TEST(gap2_regname_bad_flags) {
    REQUIRE(UN(NCryptRegisterProtectionDescriptorName));
    LONG (WINAPI *f)(LPCWSTR, LPCWSTR, DWORD) = (void *)UN(NCryptRegisterProtectionDescriptorName);
    /* only NCRYPT_MACHINE_KEY_FLAG (0x20) is accepted; any other bit is NTE_BAD_FLAGS before the registry is touched */
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x1000, 0x10000, 0x80000000u, 0xFFFFFFFFu, 0x21, 0x60, 0xFFFFFFDFu };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LONG r = f(L"gap2_never_registered", L"LOCAL=user", bad[i]);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
        r = f(L"gap2_never_registered", NULL, bad[i]);
        CHECKF(r == G2_NTE_BAD_FLAGS, "unregister flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
    }
}

/* ---------------- NCryptStreamClose ---------------- */
TEST(gap2_stream_close_null) {
    REQUIRE(UN(NCryptStreamClose));
    G2_EQ(UN(NCryptStreamClose)(NULL), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_stream_close_wrong_magic) {
    REQUIRE(UN(NCryptStreamClose));
    static const ULONGLONG m[] = { 0, 1, 0xBF, 0xC1, 0x28, 0x4444444400000000ull, 0xFFFFFFFFFFFFFFFFull };
    for (unsigned i = 0; i < sizeof m / sizeof m[0]; i++) {
        g2_sobj o; memset(&o, 0, sizeof o); o.magic = m[i];
        LONG r = UN(NCryptStreamClose)(&o);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "magic 0x%llx -> 0x%08lx", (unsigned long long)m[i], (unsigned long)r);
    }
}

/* ---------------- NCryptStreamUpdate ---------------- */
TEST(gap2_stream_update_invalid_handle) {
    REQUIRE(UN(NCryptStreamUpdate));
    BYTE d[16] = {0};
    G2_EQ(UN(NCryptStreamUpdate)(NULL, d, sizeof d, FALSE), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(NCryptStreamUpdate)(NULL, d, sizeof d, TRUE), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(NCryptStreamUpdate)(NULL, NULL, 0, TRUE), G2_NTE_INVALID_HANDLE);
    g2_sobj o; memset(&o, 0, sizeof o); o.magic = 0xBF;
    G2_EQ(UN(NCryptStreamUpdate)(&o, d, sizeof d, FALSE), G2_NTE_INVALID_HANDLE);
    o.magic = 0x28;
    G2_EQ(UN(NCryptStreamUpdate)(&o, d, sizeof d, TRUE), G2_NTE_INVALID_HANDLE);
}

/* ---------------- NCryptStreamOpenToProtect: parameter order of validation ---------------- */
static void *mkdesc(void) {
    void *d = NULL;
    if (!UN(NCryptCreateProtectionDescriptor)) return NULL;
    if (UN(NCryptCreateProtectionDescriptor)(L"LOCAL=user", 0, &d) != 0) return NULL;
    return d;
}
TEST(gap2_stream_protect_null_outputs) {
    REQUIRE(UN(NCryptStreamOpenToProtect));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = (void *)0x77; g2_sobj fake; memset(&fake, 0, sizeof fake);
    /* parameter checks (info, callback, output) come before the descriptor handle check */
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, &si, NULL), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, NULL, NULL), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToProtect)(&fake, 0, NULL, &si, NULL), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(h, 0x77);
    G2_STREAM_INFO nocb = { NULL, NULL };
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, &nocb, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToProtect)(&fake, 0, NULL, &nocb, &h), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(h, 0x77);
}
TEST(gap2_stream_protect_invalid_descriptor) {
    REQUIRE(UN(NCryptStreamOpenToProtect));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = (void *)0x77;
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0, NULL, &si, &h), G2_NTE_INVALID_HANDLE);
    static const DWORD m[] = { 0, 1, 0x27, 0x29, 0xC0, 0x44440001, 0xFFFFFFFF };
    for (unsigned i = 0; i < sizeof m / sizeof m[0]; i++) {
        g2_sobj o; memset(&o, 0, sizeof o); *(DWORD *)&o = m[i];
        LONG r = UN(NCryptStreamOpenToProtect)(&o, 0, NULL, &si, &h);
        CHECKF(r == G2_NTE_INVALID_HANDLE, "descriptor magic 0x%lx -> 0x%08lx", (unsigned long)m[i], (unsigned long)r);
    }
    EXPECT_EQ(h, 0x77);
    /* a descriptor is checked before the flags */
    G2_EQ(UN(NCryptStreamOpenToProtect)(NULL, 0xFFFFFFFF, NULL, &si, &h), G2_NTE_INVALID_HANDLE);
}
TEST(gap2_stream_protect_bad_flags) {
    REQUIRE(UN(NCryptStreamOpenToProtect)); REQUIRE(UN(NCryptCreateProtectionDescriptor)); REQUIRE(UN(NCryptCloseProtectionDescriptor));
    void *d = mkdesc(); if (!d) { t_skip("LOCAL=user descriptor unavailable"); return; }
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = (void *)0x77;
    /* accepted flag bits: 0x40 (silent) and 0x80; everything in 0x3F and above 0xFF is NTE_BAD_FLAGS */
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x3F, 0x100, 0x200, 0x1000, 0x10000, 0x40000000u, 0x80000000u, 0xFFFFFF3Fu };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LONG r = UN(NCryptStreamOpenToProtect)(d, bad[i], NULL, &si, &h);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
    }
    EXPECT_EQ(h, 0x77);
    UN(NCryptCloseProtectionDescriptor)(d);
}

/* ---------------- NCryptStreamOpenToUnprotect / Ex ---------------- */
TEST(gap2_stream_unprotect_null_args) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect));
    G2_STREAM_INFO si = { cb_nop, NULL }, nocb = { NULL, NULL }; void *h = (void *)0x77;
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(NULL, 0, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, NULL), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(&nocb, 0, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(NULL, 0, NULL, NULL), G2_NTE_INVALID_PARAM);
    /* argument checks precede flag checks */
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(NULL, 0xFFFFFFFF, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotect)(&nocb, 0x1, NULL, &h), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(h, 0x77);
}
TEST(gap2_stream_unprotect_ex_null_args) {
    REQUIRE(UN(NCryptStreamOpenToUnprotectEx));
    G2_STREAM_INFO si = { cb_nop, NULL }, nocb = { NULL, NULL }; void *h = (void *)0x77;
    G2_EQ(UN(NCryptStreamOpenToUnprotectEx)(NULL, 0, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotectEx)(&si, 0, NULL, NULL), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotectEx)(&nocb, 0, NULL, &h), G2_NTE_INVALID_PARAM);
    G2_EQ(UN(NCryptStreamOpenToUnprotectEx)(NULL, 0xFFFFFFFF, NULL, &h), G2_NTE_INVALID_PARAM);
    EXPECT_EQ(h, 0x77);
}
TEST(gap2_stream_unprotect_bad_flags) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = (void *)0x77;
    /* NCryptStreamOpenToUnprotect accepts only 0x40/0x80 (and 0 ); bit 0 is rejected */
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x3F, 0x41, 0x100, 0x1000, 0x80000000u, 0xFFFFFF3Fu };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LONG r = UN(NCryptStreamOpenToUnprotect)(&si, bad[i], NULL, &h);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
    }
    EXPECT_EQ(h, 0x77);
}
TEST(gap2_stream_unprotect_ex_bad_flags) {
    REQUIRE(UN(NCryptStreamOpenToUnprotectEx));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = (void *)0x77;
    /* the Ex variant additionally accepts bit 0 (no-decrypt) */
    static const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x20, 0x3E, 0x100, 0x1000, 0x80000000u, 0xFFFFFF3Eu };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        LONG r = UN(NCryptStreamOpenToUnprotectEx)(&si, bad[i], NULL, &h);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
    }
    EXPECT_EQ(h, 0x77);
}
TEST(gap2_stream_unprotect_open_close) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect)); REQUIRE(UN(NCryptStreamClose));
    G2_STREAM_INFO si = { cb_nop, NULL };
    static const DWORD ok[] = { 0, F_SILENT, 0x80, 0xC0 };
    for (unsigned i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        void *h = NULL;
        LONG r = UN(NCryptStreamOpenToUnprotect)(&si, ok[i], NULL, &h);
        CHECKF(r == 0, "flags 0x%lx -> 0x%08lx", (unsigned long)ok[i], (unsigned long)r);
        if (r == 0) { CHECK(h != NULL); G2_EQ(UN(NCryptStreamClose)(h), 0); }
    }
    if (UN(NCryptStreamOpenToUnprotectEx)) {
        for (unsigned i = 0; i < 2; i++) {
            void *h = NULL;
            LONG r = UN(NCryptStreamOpenToUnprotectEx)(&si, i ? F_NO_DECRYPT : 0, NULL, &h);
            CHECKF(r == 0, "Ex flags %u -> 0x%08lx", i, (unsigned long)r);
            if (r == 0) G2_EQ(UN(NCryptStreamClose)(h), 0);
        }
    }
}
TEST(gap2_stream_update_protocol) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect)); REQUIRE(UN(NCryptStreamUpdate)); REQUIRE(UN(NCryptStreamClose));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = NULL;
    if (UN(NCryptStreamOpenToUnprotect)(&si, F_SILENT, NULL, &h) != 0) { t_skip("cannot open stream"); return; }
    BYTE one = 0x01;
    /* a single byte is buffered without parsing */
    G2_EQ(UN(NCryptStreamUpdate)(h, &one, 1, FALSE), 0);
    /* an empty non-final update is accepted */
    G2_EQ(UN(NCryptStreamUpdate)(h, NULL, 0, FALSE), 0);
    /* garbage cannot be a protected message: the final update reports an error */
    BYTE junk[16]; memset(junk, 0, sizeof junk);
    LONG r = UN(NCryptStreamUpdate)(h, junk, sizeof junk, TRUE);
    CHECK(r != 0); t_note("final update with garbage -> 0x%08lx", (unsigned long)r);
    /* after the final update the stream is finished: further updates are an invalid handle */
    G2_EQ(UN(NCryptStreamUpdate)(h, &one, 1, FALSE), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(NCryptStreamUpdate)(h, NULL, 0, TRUE), G2_NTE_INVALID_HANDLE);
    G2_EQ(UN(NCryptStreamClose)(h), 0);
}
TEST(gap2_stream_update_small_nonfinal_garbage) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect)); REQUIRE(UN(NCryptStreamUpdate)); REQUIRE(UN(NCryptStreamClose));
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = NULL;
    if (UN(NCryptStreamOpenToUnprotect)(&si, F_SILENT, NULL, &h) != 0) { t_skip("cannot open stream"); return; }
    /* fewer than 7 bytes of undecodable data that are not yet final are held back, not rejected */
    BYTE junk[3] = { 0x30, 0x84, 0x01 };   /* DER header whose length field is incomplete */
    G2_EQ(UN(NCryptStreamUpdate)(h, junk, 3, FALSE), 0);
    G2_EQ(UN(NCryptStreamClose)(h), 0);
}
TEST(gap2_stream_close_twice_is_not_tested) {
    REQUIRE(UN(NCryptStreamOpenToUnprotect)); REQUIRE(UN(NCryptStreamClose));
    /* A closed stream's memory is freed, so reuse is undefined; only the first close is asserted. */
    G2_STREAM_INFO si = { cb_nop, NULL }; void *h = NULL;
    if (UN(NCryptStreamOpenToUnprotect)(&si, 0, NULL, &h) != 0) { t_skip("cannot open stream"); return; }
    G2_EQ(UN(NCryptStreamClose)(h), 0);
}

/* ---------------- protect / unprotect stream round trip (LOCAL=user, silent) ---------------- */
TEST(gap2_stream_roundtrip_local_user) {
    REQUIRE(UN(NCryptStreamOpenToProtect)); REQUIRE(UN(NCryptStreamOpenToUnprotect)); REQUIRE(UN(NCryptStreamUpdate));
    REQUIRE(UN(NCryptStreamClose)); REQUIRE(UN(NCryptCreateProtectionDescriptor));
    if (t_is_wine()) { t_skip("DPAPI-NG not available"); return; }
    void *d = mkdesc(); if (!d) { t_skip("LOCAL=user descriptor unavailable"); return; }
    BYTE plain[3000]; for (unsigned i = 0; i < sizeof plain; i++) plain[i] = (BYTE)(i * 31 + 5);
    static BYTE ct[8192], out[8192];
    struct { BYTE *p; SIZE_T n, cap; int fin; } c = { ct, 0, sizeof ct, 0 }, o = { out, 0, sizeof out, 0 };
    G2_STREAM_INFO sp = { cb_collect, &c }, su = { cb_collect, &o };
    void *ps = NULL, *us = NULL;
    LONG r = UN(NCryptStreamOpenToProtect)(d, F_SILENT, NULL, &sp, &ps);
    if (r != 0) { t_note("OpenToProtect(LOCAL=user, silent) -> 0x%08lx", (unsigned long)r); UN(NCryptCloseProtectionDescriptor)(d); t_skip("protect stream unavailable"); return; }
    G2_EQ(UN(NCryptStreamUpdate)(ps, plain, 1000, FALSE), 0);
    G2_EQ(UN(NCryptStreamUpdate)(ps, plain + 1000, 2000, FALSE), 0);
    G2_EQ(UN(NCryptStreamUpdate)(ps, NULL, 0, TRUE), 0);
    G2_EQ(UN(NCryptStreamClose)(ps), 0);
    CHECK(c.n > sizeof plain);       /* envelope plus ciphertext */
    CHECK(c.fin);                    /* the callback is told when the output is complete */
    CHECK(c.n < sizeof plain + 4096);
    CHECK(c.n < 4 || memcmp(ct, plain, 16) != 0);   /* not stored in the clear */
    if (UN(NCryptStreamOpenToUnprotect)(&su, F_SILENT, NULL, &us) != 0) { t_skip("cannot open unprotect stream"); UN(NCryptCloseProtectionDescriptor)(d); return; }
    SIZE_T off = 0; LONG ur = 0;
    while (off < c.n && ur == 0) { SIZE_T n = c.n - off < 97 ? c.n - off : 97; off += n; ur = UN(NCryptStreamUpdate)(us, ct + off - n, n, off == c.n); }
    CHECKF(ur == 0, "unprotect update -> 0x%08lx", (unsigned long)ur);
    EXPECT_EQ(o.n, sizeof plain);
    CHECK(o.n == sizeof plain && !memcmp(out, plain, sizeof plain));
    G2_EQ(UN(NCryptStreamClose)(us), 0);
    /* a flipped ciphertext byte must not decrypt to the original */
    struct { BYTE *p; SIZE_T n, cap; int fin; } o2 = { out, 0, sizeof out, 0 };
    G2_STREAM_INFO su2 = { cb_collect, &o2 }; void *us2 = NULL;
    memset(out, 0, sizeof out);
    ct[c.n - 5] ^= 0x01;
    if (UN(NCryptStreamOpenToUnprotect)(&su2, F_SILENT, NULL, &us2) == 0) {
        LONG r2 = UN(NCryptStreamUpdate)(us2, ct, c.n, TRUE);
        CHECK(r2 != 0 || o2.n != sizeof plain || memcmp(out, plain, sizeof plain) != 0);
        t_note("tampered ciphertext -> 0x%08lx, produced %zu bytes", (unsigned long)r2, (size_t)o2.n);
        UN(NCryptStreamClose)(us2);
    }
    UN(NCryptCloseProtectionDescriptor)(d);
}

/* ---------------- NCryptUnprotectSecret ---------------- */
static const BYTE blob16[16] = { 0x30, 0x0e, 0x02, 0x01, 0x00, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
typedef LONG (WINAPI *unprot_t)(void **, DWORD, const BYTE *, ULONG, const void *, HWND, BYTE **, ULONG *);

TEST(gap2_unprotect_null_arguments) {
    REQUIRE(UN(NCryptUnprotectSecret));
    unprot_t f = (unprot_t)UN(NCryptUnprotectSecret);
    BYTE *pb = (BYTE *)0x11; ULONG cb = 0x22; void *desc = (void *)0x33;
    G2_EQ(f(&desc, 0, NULL, sizeof blob16, NULL, NULL, &pb, &cb), G2_NTE_INVALID_PARAM);       /* no blob */
    G2_EQ(f(&desc, 0, blob16, 0, NULL, NULL, &pb, &cb), G2_NTE_INVALID_PARAM);                 /* zero length */
    G2_EQ(f(&desc, 0, blob16, sizeof blob16, NULL, NULL, NULL, &cb), G2_NTE_INVALID_PARAM);    /* no data pointer */
    G2_EQ(f(&desc, 0, blob16, sizeof blob16, NULL, NULL, &pb, NULL), G2_NTE_INVALID_PARAM);    /* no size pointer */
    G2_EQ(f(NULL, 0, NULL, 0, NULL, NULL, NULL, NULL), G2_NTE_INVALID_PARAM);
    /* all of those fail before any output is cleared */
    EXPECT_EQ(pb, 0x11); EXPECT_EQ(cb, 0x22); EXPECT_EQ(desc, 0x33);
    /* the argument checks win over flag checks */
    G2_EQ(f(&desc, 0xFFFFFFFF, NULL, 0, NULL, NULL, &pb, &cb), G2_NTE_INVALID_PARAM);
}
TEST(gap2_unprotect_bad_flags_clear_outputs) {
    REQUIRE(UN(NCryptUnprotectSecret));
    unprot_t f = (unprot_t)UN(NCryptUnprotectSecret);
    /* accepted bits: 0x1 (no decrypt) and 0x40 (silent); anything else is NTE_BAD_FLAGS */
    static const DWORD bad[] = { 0x2, 0x4, 0x8, 0x10, 0x20, 0x3E, 0x80, 0x100, 0x1000, 0x80000000u, 0xFFFFFFBEu, 0xFFFFFFFFu };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        BYTE *pb = (BYTE *)0x11; ULONG cb = 0x22; void *desc = (void *)0x33;
        LONG r = f(&desc, bad[i], blob16, sizeof blob16, NULL, NULL, &pb, &cb);
        CHECKF(r == G2_NTE_BAD_FLAGS, "flags 0x%08lx -> 0x%08lx", (unsigned long)bad[i], (unsigned long)r);
        /* by the time the flags are examined, descriptor and output slots have been zeroed */
        CHECKF(pb == NULL && cb == 0 && desc == NULL, "outputs pb=%p cb=%lu desc=%p", (void *)pb, (unsigned long)cb, desc);
    }
}
TEST(gap2_unprotect_bad_flags_null_descriptor_slot) {
    REQUIRE(UN(NCryptUnprotectSecret));
    unprot_t f = (unprot_t)UN(NCryptUnprotectSecret);
    BYTE *pb = (BYTE *)0x11; ULONG cb = 0x22;
    /* phDescriptor is optional */
    G2_EQ(f(NULL, 0x2, blob16, sizeof blob16, NULL, NULL, &pb, &cb), G2_NTE_BAD_FLAGS);
    EXPECT_EQ(pb, NULL); EXPECT_EQ(cb, 0);
}
TEST(gap2_unprotect_garbage_blob) {
    REQUIRE(UN(NCryptUnprotectSecret));
    if (t_is_wine()) { t_skip("DPAPI-NG not available"); return; }
    unprot_t f = (unprot_t)UN(NCryptUnprotectSecret);
    static const DWORD ok[] = { 0, F_SILENT, F_NO_DECRYPT, F_NO_DECRYPT | F_SILENT };
    BYTE zeros[64]; memset(zeros, 0, sizeof zeros);
    for (unsigned i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        BYTE *pb = (BYTE *)0x11; ULONG cb = 0x22; void *desc = (void *)0x33;
        LONG r = f(&desc, ok[i], zeros, sizeof zeros, NULL, NULL, &pb, &cb);
        CHECKF(r != 0, "flags 0x%lx accepted an all-zero blob", (unsigned long)ok[i]);
        CHECKF(r != G2_NTE_BAD_FLAGS, "flags 0x%lx rejected as bad flags", (unsigned long)ok[i]);
        t_note("UnprotectSecret(all-zero 64B, flags 0x%lx) -> 0x%08lx", (unsigned long)ok[i], (unsigned long)r);
        EXPECT_EQ(pb, NULL); EXPECT_EQ(cb, 0); EXPECT_EQ(desc, NULL);
    }
    BYTE *pb = NULL; ULONG cb = 0;
    LONG r = f(NULL, F_SILENT, blob16, sizeof blob16, NULL, NULL, &pb, &cb);
    CHECK(r != 0 && r != G2_NTE_BAD_FLAGS); t_note("UnprotectSecret(truncated DER) -> 0x%08lx", (unsigned long)r);
}
TEST(gap2_protect_unprotect_secret_roundtrip) {
    REQUIRE(UN(NCryptUnprotectSecret)); REQUIRE(UN(NCryptProtectSecret)); REQUIRE(UN(NCryptCreateProtectionDescriptor));
    if (t_is_wine()) { t_skip("DPAPI-NG not available"); return; }
    void *d = mkdesc(); if (!d) { t_skip("LOCAL=user descriptor unavailable"); return; }
    BYTE secret[40]; for (unsigned i = 0; i < sizeof secret; i++) secret[i] = (BYTE)(0xA0 + i);
    BYTE *prot = NULL; ULONG cprot = 0;
    LONG r = UN(NCryptProtectSecret)(d, F_SILENT, secret, sizeof secret, NULL, NULL, &prot, &cprot);
    if (r != 0) { t_note("ProtectSecret -> 0x%08lx", (unsigned long)r); UN(NCryptCloseProtectionDescriptor)(d); t_skip("protect unavailable"); return; }
    CHECK(prot != NULL && cprot > sizeof secret);
    BYTE *pt = NULL; ULONG cpt = 0; void *desc = NULL;
    r = ((unprot_t)UN(NCryptUnprotectSecret))(&desc, F_SILENT, prot, cprot, NULL, NULL, &pt, &cpt);
    G2_EQ(r, 0);
    if (r == 0) {
        EXPECT_EQ(cpt, sizeof secret);
        CHECK(pt && cpt == sizeof secret && !memcmp(pt, secret, sizeof secret));
        CHECK(desc != NULL);       /* descriptor of the message is returned when requested */
        if (desc) UN(NCryptCloseProtectionDescriptor)(desc);
        LocalFree(pt);
    }
    /* NO_DECRYPT: only the descriptor is returned, no data */
    desc = NULL; pt = (BYTE *)0x11; cpt = 0x22;
    r = ((unprot_t)UN(NCryptUnprotectSecret))(&desc, F_SILENT | F_NO_DECRYPT, prot, cprot, NULL, NULL, &pt, &cpt);
    t_note("UnprotectSecret(NO_DECRYPT) -> 0x%08lx", (unsigned long)r);
    if (r == 0) { CHECK(desc != NULL); EXPECT_EQ(pt, NULL); EXPECT_EQ(cpt, 0); if (desc) UN(NCryptCloseProtectionDescriptor)(desc); }
    /* truncated message does not decrypt */
    pt = NULL; cpt = 0;
    r = ((unprot_t)UN(NCryptUnprotectSecret))(NULL, F_SILENT, prot, cprot - 8, NULL, NULL, &pt, &cpt);
    CHECK(r != 0); EXPECT_EQ(pt, NULL); EXPECT_EQ(cpt, 0);
    t_note("UnprotectSecret(truncated by 8) -> 0x%08lx", (unsigned long)r);
    LocalFree(prot);
    UN(NCryptCloseProtectionDescriptor)(d);
}
