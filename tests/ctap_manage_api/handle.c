/* Handle validation of DeleteCredential, EnrollFingerprint, CancelEnrollFingerprint,
 * RemoveFingerprints, ResetDevice and GetDisplayCredentials.
 *
 * Verified from the reference decompilation:
 *  - Every management call that reaches the request dispatcher fails with NTE_INVALID_PARAMETER
 *    (0x80090027) before any device I/O when: the handle is NULL, handle+8 (context) is NULL,
 *    *context (device session) is NULL, or the context's request length / buffer are 0 / NULL.
 *  - DeleteCredential rejects handle == NULL, cbCredentialId == 0 or pbCredentialId == NULL
 *    without touching the handle at all.
 *  - EnrollFingerprint stores 0xFFFFFFFF / 0 into its two outputs on entry, before validation.
 *  - CancelEnrollFingerprint returns S_OK without any device traffic when no enrolment is pending
 *    (ctx+0x2c == 0 or ctx+0x30 == NULL), and clears/frees the pending template either way.
 *  - GetDisplayCredentials stores NULL into *ppList on entry.
 * ResetDevice is only called with shapes whose device session is NULL: any other shape would
 * try to re-open the device, so those are not exercised.
 */
#include "cm_api.h"

#define SENT_DW 0xA5A5A5A5u

/* ---------------- DeleteCredential ---------------- */
static const BYTE kCred[32] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };

TEST(cmdelete_all_null)
{
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 0, NULL), 0x80090027);
}

TEST(cmdelete_null_handle_valid_id)
{
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 32, kCred), 0x80090027);
}

TEST(cmdelete_zero_length_id_every_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s);
        CHECKF((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, h, 0, kCred) == 0x80090027, "%s", cm_shape_name[s]);
    }
}

TEST(cmdelete_null_id_every_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s);
        CHECKF((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, h, 32, NULL) == 0x80090027, "%s", cm_shape_name[s]);
    }
}

TEST(cmdelete_valid_args_invalid_handle_shapes)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s);
        HRESULT hr = UN(WebAuthNCtapManageDeleteCredential)(NULL, h, 32, kCred);
        CHECKF((DWORD)hr == 0x80090027, "%s: got 0x%lx", cm_shape_name[s], (DWORD)hr);
    }
}

TEST(cmdelete_credential_id_lengths_invalid_handle)
{
    static const int lens[] = { 1, 2, 16, 31, 32, 33, 64, 128, 255, 256, 1023 };
    BYTE *id = calloc(2048, 1); size_t i;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential)); REQUIRE(id);
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++)
        CHECKF((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, lens[i], id) == 0x80090027, "len %d", lens[i]);
    free(id);
}

TEST(cmdelete_does_not_modify_credential_id)
{
    BYTE id[32]; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    memcpy(id, kCred, 32);
    hr = UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 32, id);
    EXPECT_EQ((DWORD)hr, 0x80090027);
    CHECK(!memcmp(id, kCred, 32));
}

TEST(cmdelete_hwnd_ignored_before_validation)
{
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(GetDesktopWindow(), NULL, 32, kCred), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(GetDesktopWindow(), NULL, 0, NULL), 0x80090027);
}

TEST(cmdelete_argument_checks_are_order_independent)
{
    /* Any of the three missing is enough: all eight combinations of {handle, len, id} present/absent
     * with a handle that has no session give the same code. */
    int m;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    for (m = 0; m < 8; m++) {
        CM_SHAPE sh; void *h = (m & 1) ? cm_shape(&sh, SH_ZERO_CTX) : NULL;
        HRESULT hr = UN(WebAuthNCtapManageDeleteCredential)(NULL, h, (m & 2) ? 32 : 0, (m & 4) ? kCred : NULL);
        CHECKF((DWORD)hr == 0x80090027, "mask %d: 0x%lx", m, (DWORD)hr);
    }
}

TEST(cmdelete_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    for (i = 0; i < 100; i++) CHECK((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 32, kCred) == 0x80090027);
}

/* ---------------- GetDisplayCredentials ---------------- */
TEST(cmgetdisp_null_handle_clears_output)
{
    void *list = (void *)(ULONG_PTR)0x1; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials));
    hr = UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, NULL, &list);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(list, NULL);
}

TEST(cmgetdisp_every_invalid_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s); void *list = (void *)(ULONG_PTR)0x1;
        HRESULT hr = UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, h, &list);
        CHECKF((DWORD)hr == 0x80090027, "%s: 0x%lx", cm_shape_name[s], (DWORD)hr);
        CHECKF(list == NULL, "%s: output not cleared", cm_shape_name[s]);
    }
}

TEST(cmgetdisp_hwnd_ignored)
{
    void *list = (void *)(ULONG_PTR)0x1;
    REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageGetDisplayCredentials)(GetDesktopWindow(), NULL, &list), 0x80090027);
    EXPECT_EQ(list, NULL);
}

TEST(cmgetdisp_failed_output_is_safe_to_free)
{
    void *list = (void *)(ULONG_PTR)0x1;
    REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials)); REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, NULL, &list);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(list);
    CHECK(1);
}

TEST(cmgetdisp_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials));
    for (i = 0; i < 100; i++) {
        void *list = (void *)(ULONG_PTR)0x1;
        CHECK((DWORD)UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, NULL, &list) == 0x80090027 && list == NULL);
    }
}

/* ---------------- RemoveFingerprints ---------------- */
TEST(cmremovefp_null_handle)
{
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(NULL, NULL), 0x80090027);
}

TEST(cmremovefp_every_invalid_shape)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    for (s = 0; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s);
        HRESULT hr = UN(WebAuthNCtapManageRemoveFingerprints)(NULL, h);
        CHECKF((DWORD)hr == 0x80090027, "%s: 0x%lx", cm_shape_name[s], (DWORD)hr);
    }
}

TEST(cmremovefp_hwnd_ignored)
{
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(GetDesktopWindow(), NULL), 0x80090027);
}

TEST(cmremovefp_does_not_touch_handle_state_on_failure)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    UN(WebAuthNCtapManageRemoveFingerprints)(NULL, h);
    CHECK(sh.h.tag == 0 && sh.h.pad == 0 && sh.h.ctx == &sh.c);
    { size_t i; int zero = 1; for (i = 0; i < sizeof sh.c.b; i++) if (sh.c.b[i]) zero = 0; CHECK(zero); }
}

TEST(cmremovefp_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    for (i = 0; i < 100; i++) CHECK((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(NULL, NULL) == 0x80090027);
}

/* ---------------- ResetDevice ---------------- */
TEST(cmreset_null_handle)
{
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, NULL), 0x80090027);
}

TEST(cmreset_handle_without_context)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_NO_CTX);
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, h), 0x80090027);
}

TEST(cmreset_context_without_device_session)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, h), 0x80090027);
}

TEST(cmreset_hwnd_ignored)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(GetDesktopWindow(), h), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(GetDesktopWindow(), NULL), 0x80090027);
}

TEST(cmreset_leaves_handle_unchanged_on_failure)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    UN(WebAuthNCtapManageResetDevice)(NULL, h);
    CHECK(sh.h.ctx == &sh.c);
}

TEST(cmreset_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    for (i = 0; i < 100; i++) CHECK((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, NULL) == 0x80090027);
}

/* ---------------- EnrollFingerprint ---------------- */
static HRESULT enroll(void *h, int begin, DWORD timeout, DWORD *st, DWORD *rem)
{ return UN(WebAuthNCtapManageEnrollFingerprint)(NULL, h, begin, timeout, st, rem); }

TEST(cmenroll_null_handle_outputs_initialised)
{
    DWORD st = SENT_DW, rem = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    hr = enroll(NULL, 1, 0, &st, &rem);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_null_handle_continue_mode_outputs_initialised)
{
    DWORD st = SENT_DW, rem = SENT_DW; HRESULT hr;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    hr = enroll(NULL, 0, 0, &st, &rem);
    EXPECT_EQ((DWORD)hr, 0x80090027); EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_handle_without_context)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_NO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    EXPECT_EQ((DWORD)enroll(h, 1, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_every_shape_both_modes)
{
    int s, begin;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    for (s = 0; s < SH_COUNT; s++) for (begin = 0; begin < 2; begin++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s); DWORD st = SENT_DW, rem = SENT_DW;
        HRESULT hr = enroll(h, begin, 0, &st, &rem);
        CHECKF((DWORD)hr == 0x80090027, "%s begin=%d: 0x%lx", cm_shape_name[s], begin, (DWORD)hr);
        CHECKF(st == 0xFFFFFFFF && rem == 0, "%s begin=%d: out %lx %lx", cm_shape_name[s], begin, st, rem);
    }
}

TEST(cmenroll_timeout_values_do_not_change_early_failure)
{
    static const DWORD tos[] = { 0, 1, 1000, 20000, 0x7fffffff, 0xffffffff };
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    for (i = 0; i < sizeof tos / sizeof tos[0]; i++) {
        DWORD st = SENT_DW, rem = SENT_DW;
        CHECKF((DWORD)enroll(NULL, 1, tos[i], &st, &rem) == 0x80090027, "timeout %lu", tos[i]);
        CHECK(st == 0xFFFFFFFF && rem == 0);
    }
}

TEST(cmenroll_nonzero_begin_values_are_equivalent)
{
    static const int v[] = { 1, 2, -1, 0x100, 0x7fffffff, (int)0x80000000 };
    size_t i;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    for (i = 0; i < sizeof v / sizeof v[0]; i++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
        CHECKF((DWORD)enroll(h, v[i], 0, &st, &rem) == 0x80090027, "begin %d", v[i]);
    }
}

TEST(cmenroll_continue_without_pending_template_fails)
{
    /* begin == 0 means "continue": it needs ctx+0x2c != 0 and ctx+0x30 != NULL. */
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    EXPECT_EQ((DWORD)enroll(h, 0, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_continue_with_length_but_no_pointer_resets_length)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    CTX_TLEN(&sh.c) = 5;
    EXPECT_EQ((DWORD)enroll(h, 0, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
}

TEST(cmenroll_continue_with_pointer_but_no_length_frees_pending_template)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)enroll(h, 0, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
}

TEST(cmenroll_failed_begin_clears_pending_template_state)
{
    /* Begin with a context that has no device session: dispatcher rejects, pending state released. */
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    CTX_TLEN(&sh.c) = 4; CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)enroll(h, 1, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
}

TEST(cmenroll_failed_continue_with_template_clears_it)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX); DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    CTX_TLEN(&sh.c) = 4; CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)enroll(h, 0, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
    EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_hwnd_ignored)
{
    DWORD st = SENT_DW, rem = SENT_DW;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageEnrollFingerprint)(GetDesktopWindow(), NULL, 1, 0, &st, &rem), 0x80090027);
    EXPECT_EQ(st, 0xFFFFFFFF); EXPECT_EQ(rem, 0);
}

TEST(cmenroll_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint));
    for (i = 0; i < 100; i++) {
        DWORD st = SENT_DW, rem = SENT_DW;
        CHECK((DWORD)enroll(NULL, i & 1, 0, &st, &rem) == 0x80090027 && st == 0xFFFFFFFF && rem == 0);
    }
}

/* ---------------- CancelEnrollFingerprint ---------------- */
TEST(cmcancel_null_handle)
{
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, NULL), 0x80090027);
}

TEST(cmcancel_handle_without_context)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_NO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), 0x80090027);
}

TEST(cmcancel_nothing_pending_succeeds_without_device)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), S_OK);
}

TEST(cmcancel_nothing_pending_every_context_shape_succeeds)
{
    int s;
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    for (s = SH_ZERO_CTX; s < SH_COUNT; s++) {
        CM_SHAPE sh; void *h = cm_shape(&sh, s);
        HRESULT hr = UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h);
        CHECKF(hr == S_OK, "%s: 0x%lx", cm_shape_name[s], (DWORD)hr);
    }
}

TEST(cmcancel_length_without_pointer_returns_ok_and_resets_length)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    CTX_TLEN(&sh.c) = 9;
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), S_OK);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
}

TEST(cmcancel_pointer_without_length_returns_ok_and_frees_pointer)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    CTX_TLEN(&sh.c) = 0; CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), S_OK);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
}

TEST(cmcancel_pending_template_with_dead_session_fails_and_clears)
{
    /* With a template pending the cancel request goes to the dispatcher, which rejects the
     * context (no device session) before any I/O; the pending template is released regardless. */
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    CTX_TLEN(&sh.c) = 4; CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), 0x80090027);
    EXPECT_EQ(CTX_TPTR(&sh.c), NULL);
    EXPECT_EQ(CTX_TLEN(&sh.c), 0);
}

TEST(cmcancel_twice_second_is_ok)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    CTX_TLEN(&sh.c) = 4; CTX_TPTR(&sh.c) = LocalAlloc(LPTR, 16); REQUIRE(CTX_TPTR(&sh.c));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, h), S_OK);
}

TEST(cmcancel_hwnd_ignored)
{
    CM_SHAPE sh; void *h = cm_shape(&sh, SH_ZERO_CTX);
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(GetDesktopWindow(), h), S_OK);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(GetDesktopWindow(), NULL), 0x80090027);
}

TEST(cmcancel_repeatable)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    for (i = 0; i < 100; i++) CHECK((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, NULL) == 0x80090027);
}

/* ---------------- Call-order independence ---------------- */
TEST(cmorder_close_null_between_failing_calls)
{
    void *list = (void *)(ULONG_PTR)1;
    REQUIRE(UN(WebAuthNCtapManageClose)); REQUIRE(UN(WebAuthNCtapManageGetDisplayCredentials)); REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    UN(WebAuthNCtapManageClose)(NULL);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, NULL, &list), 0x80090027);
    UN(WebAuthNCtapManageClose)(NULL);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(NULL, NULL), 0x80090027);
    UN(WebAuthNCtapManageClose)(NULL);
}

TEST(cmorder_reverse_order_of_calls_same_results)
{
    DWORD st, rem; int r; DWORD u; void *list;
    REQUIRE(UN(WebAuthNCtapManageResetDevice)); REQUIRE(UN(WebAuthNCtapManageEnrollFingerprint)); REQUIRE(UN(WebAuthNCtapManageDeleteCredential));
    REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint)); REQUIRE(UN(WebAuthNCtapManageSetPin));
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageSetPin)(NULL, NULL, NULL, &r), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, NULL), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 1, kCred), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageEnrollFingerprint)(NULL, NULL, 1, 0, &st, &rem), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, NULL), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, NULL), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageEnrollFingerprint)(NULL, NULL, 1, 0, &st, &rem), 0x80090027);
    EXPECT_EQ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 1, kCred), 0x80090027);
}

TEST(cmorder_last_error_not_required_to_be_set)
{
    /* The failures are returned as HRESULTs; do not rely on GetLastError being set. */
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    SET_ERR(0);
    UN(WebAuthNCtapManageResetDevice)(NULL, NULL);
    t_note("GetLastError after ResetDevice(NULL,NULL) = %lu", GetLastError());
    CHECK(1);
}

/* ---------------- Process-level sweep ---------------- */
CHILD(cm_null_sweep)
{
    DWORD st, rem; int r; DWORD u; void *list = NULL; WCHAR p1[8] = L"123456", p2[8] = L"654321";
    UN(WebAuthNCtapManageClose)(NULL);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    if ((DWORD)UN(WebAuthNCtapManageSetPin)(NULL, NULL, NULL, &r) != 0x80090027) return 10;
    if ((DWORD)UN(WebAuthNCtapManageChangePin)(NULL, NULL, p1, p2, &r, &u) != 0x80090027) return 11;
    if ((DWORD)UN(WebAuthNCtapManageAuthenticatePin)(NULL, NULL, p2, &r, &u) != 0x80090027) return 12;
    if ((DWORD)UN(WebAuthNCtapManageGetDisplayCredentials)(NULL, NULL, &list) != 0x80090027) return 13;
    if ((DWORD)UN(WebAuthNCtapManageDeleteCredential)(NULL, NULL, 0, NULL) != 0x80090027) return 14;
    if ((DWORD)UN(WebAuthNCtapManageEnrollFingerprint)(NULL, NULL, 1, 0, &st, &rem) != 0x80090027) return 15;
    if ((DWORD)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, NULL) != 0x80090027) return 16;
    if ((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(NULL, NULL) != 0x80090027) return 17;
    if ((DWORD)UN(WebAuthNCtapManageResetDevice)(NULL, NULL) != 0x80090027) return 18;
    UN(WebAuthNCtapManageClose)(NULL);
    return 0;
}

TEST(cmproc_null_sweep_in_clean_process)
{
    REQUIRE(UN(WebAuthNCtapManageResetDevice));
    EXPECT_EQ(t_run_child("cm_null_sweep", "", 20000), 0);
}


TEST(cmproc_thread_independence)
{
    /* The entry points are stateless for invalid handles: the result does not depend on which thread calls. */
    REQUIRE(UN(WebAuthNCtapManageRemoveFingerprints));
    {
        struct { HANDLE th; } t[4]; int i; DWORD code;
        extern DWORD WINAPI cm_thread_main(LPVOID);
        for (i = 0; i < 4; i++) t[i].th = CreateThread(NULL, 0, cm_thread_main, NULL, 0, NULL);
        for (i = 0; i < 4; i++) {
            if (!t[i].th) continue;
            CHECK(WaitForSingleObject(t[i].th, 10000) == WAIT_OBJECT_0);
            GetExitCodeThread(t[i].th, &code); CHECK(code == 0);
            CloseHandle(t[i].th);
        }
    }
}

DWORD WINAPI cm_thread_main(LPVOID p)
{
    int i; DWORD st, rem;
    (void)p;
    for (i = 0; i < 50; i++) {
        if ((DWORD)UN(WebAuthNCtapManageRemoveFingerprints)(NULL, NULL) != 0x80090027) return 1;
        if ((DWORD)UN(WebAuthNCtapManageEnrollFingerprint)(NULL, NULL, 1, 0, &st, &rem) != 0x80090027) return 2;
        UN(WebAuthNCtapManageClose)(NULL);
    }
    return 0;
}

/* ---------------- Select: resolve only ---------------- */
TEST(cmselect_resolve_only)
{
    /* Select enumerates and opens an authenticator before it returns anything, so no argument
     * combination is proven to fail early: it is never called here. */
    REQUIRE(UN(WebAuthNCtapManageSelect));
    CHECK(UN(WebAuthNCtapManageSelect) != NULL);
    t_note("WebAuthNCtapManageSelect(hWnd, flags, session GUID, &hManage) is intentionally not invoked (device enumeration)");
}
