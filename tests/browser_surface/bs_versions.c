/* Struct-version handling and read extents for the structures a browser fills in.
 *
 * For every structure and version value the child places the structure on a guard page (see bs.h) and the
 * smallest readable size for which the call returns normally is printed as a table row:
 *   NOTE table <api> <kind> v<version> mode<m> read=0x.. declared_end=0x.. hr=0x........
 * Hard checks: a version the header documents is never read beyond its documented size (rounded to 8),
 * the version field itself is always read, and every call ends with the expected local rejection. */
#include "bs.h"

typedef struct { const char *kind; unsigned end; } kindinfo;

static void row(char api, const char *kind, DWORD ver, int mode, int ext, unsigned end, DWORD hr) {
    if (ext >= 0) t_note("table %c %s v%lu mode%d read=0x%x declared_end=0x%x hr=0x%08lx", api, kind, (unsigned long)ver, mode, ext, end, (unsigned long)hr);
    else t_note("table %c %s v%lu mode%d read=%s declared_end=0x%x hr=0x%08lx", api, kind, (unsigned long)ver, mode,
                ext == BS_X_FAULT_AT_MAX ? "beyond-max" : "no-result", end, (unsigned long)hr);
}

/* One probe with checks. `local_hr` is the HRESULT the call must return when everything is readable. */
static int probe_one(char api, const char *kind, DWORD ver, int mode, int maxS, unsigned end, unsigned local_hr, int check_end) {
    DWORD hr = 0;
    int ext = bs_extent(api, kind, ver, mode, maxS, &hr);
    row(api, kind, ver, mode, ext, end, hr);
    CHECKF(ext != BS_X_NO_EXPORT, "export missing");
    CHECKF(ext != BS_X_NO_RESULT, "%c %s v%lu: child timed out or crashed (rc 0x%08lx)", api, kind, (unsigned long)ver, (unsigned long)hr);
    if (ext < 0) return ext;
    CHECKF(hr == local_hr, "%c %s v%lu mode%d: full-size result 0x%08lx want 0x%08x", api, kind, (unsigned long)ver, mode, (unsigned long)hr, local_hr);
    CHECKF(ext >= 4, "%c %s v%lu: version field not read (read=%d)", api, kind, (unsigned long)ver, ext);
    if (check_end) CHECKF((unsigned)ext <= BS_ROUND8(end), "%c %s v%lu read 0x%x beyond documented size 0x%x", api, kind, (unsigned long)ver, ext, BS_ROUND8(end));
    return ext;
}

#define NEED_MC REQUIRE(UN(WebAuthNAuthenticatorMakeCredential))
#define NEED_GA REQUIRE(UN(WebAuthNAuthenticatorGetAssertion))

/* ---- small structures, version 1 and unknown future versions ---- */
#define SMALL(nm, api, kind, endv, local_hr) \
TEST(bs_##nm##_v1) { if (api == 'm') { NEED_MC; } else { NEED_GA; } probe_one(api, kind, 1, 0, 0x40, endv, local_hr, 1); } \
TEST(bs_##nm##_future_versions) { if (api == 'm') { NEED_MC; } else { NEED_GA; } \
    int e1 = probe_one(api, kind, 1, 0, 0x40, endv, local_hr, 1); \
    static const DWORD fv[] = { 2, 3, 100, 0x7fffffffu, 0xffffffffu }; \
    for (int i = 0; i < 5; i++) { int e = probe_one(api, kind, fv[i], 0, 0x40, endv, local_hr, 1); \
        if (e >= 0 && e1 >= 0 && e != e1) t_note("%s: version %lu reads 0x%x, version 1 reads 0x%x", kind, (unsigned long)fv[i], e, e1); } }

SMALL(mc_rp, 'm', "rp", 0x20, BS_ENC_FAIL)
SMALL(mc_user, 'm', "user", 0x28, BS_ENC_FAIL)
SMALL(mc_client_data, 'm', "cd", 0x18, BS_ENC_FAIL)
SMALL(mc_cose_param, 'm', "cosep", 0x14, BS_ENC_FAIL)
SMALL(mc_exclude_entry_ex, 'm', "credex", 0x1c, BS_ENC_FAIL)
SMALL(ga_client_data, 'g', "cd", 0x18, BS_ENC_FAIL)
SMALL(ga_allow_entry_ex, 'g', "credex", 0x1c, BS_ENC_FAIL)
SMALL(ga_allow_entry_legacy, 'g', "cred", 0x14, BS_ENC_FAIL)

/* ---- options structures, versions 1..9 and beyond ---- */
TEST(bs_mc_options_each_version) {
    NEED_MC;
    int prev = 0;
    for (DWORD v = 1; v <= 9; v++) {
        int e = probe_one('m', "opts", v, 0, 0x100, bs_mc_end[v], BS_ENC_FAIL, 1);
        if (e >= 0) { CHECKF(e >= prev, "v%lu reads less (0x%x) than v%lu (0x%x)", (unsigned long)v, e, (unsigned long)v - 1, prev); prev = e; }
    }
}
TEST(bs_mc_options_future_versions) {
    NEED_MC;
    static const DWORD fv[] = { 10, 11, 100, 0x100, 0x7fffffffu, 0xffffffffu };
    int e9 = probe_one('m', "opts", 9, 0, 0x100, bs_mc_end[9], BS_ENC_FAIL, 1);
    for (int i = 0; i < 6; i++) {
        int e = probe_one('m', "opts", fv[i], 0, 0x100, 0, BS_ENC_FAIL, 0);
        if (e >= 0 && e9 >= 0) t_note("mc options v%lu reads 0x%x (v9 reads 0x%x)", (unsigned long)fv[i], e, e9);
    }
}
TEST(bs_mc_options_version_zero_is_rejected_at_entry) {
    NEED_MC;
    DWORD hr = 0; int e = bs_extent('m', "opts", 0, 0, 0x100, &hr);
    row('m', "opts", 0, 0, e, 0, hr);
    CHECKF(hr == BS_NTE_INVALID_PARAMETER, "got 0x%08lx", (unsigned long)hr);
    CHECKF(e >= 0 && e <= 8, "version 0 reads 0x%x", e);
}
/* mode 1: the local fault is a bad list entry (cbId 0), valid COSE parameters. Only versions where the
 * version-matching list form is known to be rejected locally (1,2 legacy list; 3..6 exclude list). */
TEST(bs_mc_options_each_version_list_fault) {
    NEED_MC;
    for (DWORD v = 1; v <= 6; v++) probe_one('m', "opts", v, 1, 0x100, bs_mc_end[v], BS_ENC_FAIL, 1);
}
TEST(bs_ga_options_each_version) {
    NEED_GA;
    int prev = 0;
    for (DWORD v = 1; v <= 9; v++) {
        int e = probe_one('g', "opts", v, 0, 0x100, bs_ga_end[v], BS_ENC_FAIL, 1);
        if (e >= 0) { CHECKF(e >= prev, "v%lu reads less (0x%x) than v%lu (0x%x)", (unsigned long)v, e, (unsigned long)v - 1, prev); prev = e; }
    }
}
TEST(bs_ga_options_each_version_list_fault) {
    NEED_GA;
    for (DWORD v = 1; v <= 9; v++) probe_one('g', "opts", v, 1, 0x100, bs_ga_end[v], BS_ENC_FAIL, 1);
}
TEST(bs_ga_options_future_versions) {
    NEED_GA;
    static const DWORD fv[] = { 10, 11, 100, 0x100, 0x7fffffffu, 0xffffffffu };
    int e9 = probe_one('g', "opts", 9, 0, 0x100, bs_ga_end[9], BS_ENC_FAIL, 1);
    for (int i = 0; i < 6; i++) {
        int e = probe_one('g', "opts", fv[i], 0, 0x100, 0, BS_ENC_FAIL, 0);
        if (e >= 0 && e9 >= 0) t_note("ga options v%lu reads 0x%x (v9 reads 0x%x)", (unsigned long)fv[i], e, e9);
    }
}
TEST(bs_ga_options_version_zero_is_rejected_at_entry) {
    NEED_GA;
    DWORD hr = 0; int e = bs_extent('g', "opts", 0, 0, 0x100, &hr);
    row('g', "opts", 0, 0, e, 0, hr);
    CHECKF(hr == BS_NTE_INVALID_PARAMETER, "got 0x%08lx", (unsigned long)hr);
}

/* ---- documented sizes (table, no call) ---- */
TEST(bs_documented_version_sizes) {
    for (unsigned v = 1; v <= 9; v++) t_note("size mc_options v%u end=0x%x padded=0x%x", v, bs_mc_end[v], BS_ROUND8(bs_mc_end[v]));
    for (unsigned v = 1; v <= 9; v++) t_note("size ga_options v%u end=0x%x padded=0x%x", v, bs_ga_end[v], BS_ROUND8(bs_ga_end[v]));
    CHECK(sizeof(BS_MC_OPTIONS) == 0xc8);
    CHECK(sizeof(BS_GA_OPTIONS) == 0xc8);
}

/* ---- a fully populated browser-style call, every options version ---- */
TEST(bs_mc_browser_shape_every_options_version) {
    NEED_MC;
    for (DWORD v = 1; v <= 9; v++) {
        DWORD rc = bs_probe('m', "browser", v, 0, 0x100);
        CHECKF(rc == BS_ENC_FAIL, "options v%lu: got 0x%08lx want 0x%08x", (unsigned long)v, (unsigned long)rc, BS_ENC_FAIL);
    }
}
TEST(bs_ga_browser_shape_every_options_version) {
    NEED_GA;
    for (DWORD v = 1; v <= 9; v++) {
        DWORD rc = bs_probe('g', "browser", v, 0, 0x100);
        CHECKF(rc == BS_ENC_FAIL, "options v%lu: got 0x%08lx want 0x%08x", (unsigned long)v, (unsigned long)rc, BS_ENC_FAIL);
    }
}
