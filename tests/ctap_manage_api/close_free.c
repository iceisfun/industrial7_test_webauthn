/* WebAuthNCtapManageClose and WebAuthNCtapManageFreeDisplayCredentials.
 *
 * Close(NULL) is a no-op. Close(h) with a context that has no device session (ctx == NULL, or
 * *ctx == NULL) sends nothing and just releases the memory: handle and context are freed with
 * LocalFree, so only LocalAlloc'd synthetic handles may be passed. Neither function touches the
 * thread's last-error value on the NULL path.
 * FreeDisplayCredentials(list) walks list->items[0..count) (items at list+8 -> pointer array),
 * LocalFree()s each non-NULL item, then LocalFree()s the list. NULL is a no-op.
 */
#include "cm_api.h"

typedef struct { DWORD count; DWORD pad; void **items; } CM_LIST;

TEST(cmclose_null)
{
    REQUIRE(UN(WebAuthNCtapManageClose));
    UN(WebAuthNCtapManageClose)(NULL);
    CHECK(1);
}

TEST(cmclose_null_twice)
{
    REQUIRE(UN(WebAuthNCtapManageClose));
    UN(WebAuthNCtapManageClose)(NULL);
    UN(WebAuthNCtapManageClose)(NULL);
    CHECK(1);
}

TEST(cmclose_null_many_times)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageClose));
    for (i = 0; i < 1000; i++) UN(WebAuthNCtapManageClose)(NULL);
    CHECK(1);
}

TEST(cmclose_null_preserves_last_error)
{
    REQUIRE(UN(WebAuthNCtapManageClose));
    SET_ERR(0x1234);
    UN(WebAuthNCtapManageClose)(NULL);
    EXPECT_ERR(0x1234);
}

TEST(cmclose_null_after_failed_management_call)
{
    /* Close(NULL) after a call that failed on a NULL handle is still a no-op. */
    int ret = 0;
    REQUIRE(UN(WebAuthNCtapManageClose)); REQUIRE(UN(WebAuthNCtapManageCancelEnrollFingerprint));
    ret = (int)UN(WebAuthNCtapManageCancelEnrollFingerprint)(NULL, NULL);
    EXPECT_EQ((DWORD)ret, 0x80090027);
    UN(WebAuthNCtapManageClose)(NULL);
    UN(WebAuthNCtapManageClose)(NULL);
    CHECK(1);
}

static void *alloc_handle(void **ctx_out, int with_ctx)
{
    void **h = LocalAlloc(LPTR, 0x10 + 0x10);
    if (!h) return NULL;
    if (with_ctx) {
        void *ctx = LocalAlloc(LPTR, 0x40);
        h[1] = ctx; /* handle + 8 */
        if (ctx_out) *ctx_out = ctx;
    } else if (ctx_out) *ctx_out = NULL;
    return h;
}

TEST(cmclose_synthetic_handle_without_context)
{
    void *h;
    REQUIRE(UN(WebAuthNCtapManageClose));
    h = alloc_handle(NULL, 0); REQUIRE(h);
    UN(WebAuthNCtapManageClose)(h);
    CHECK(1);
}

TEST(cmclose_synthetic_handle_with_empty_context)
{
    void *h, *ctx;
    REQUIRE(UN(WebAuthNCtapManageClose));
    h = alloc_handle(&ctx, 1); REQUIRE(h);
    UN(WebAuthNCtapManageClose)(h);
    CHECK(1);
}

TEST(cmclose_synthetic_handle_with_owned_device_record)
{
    /* ctx + 0 stays NULL, so no close request is sent; ctx + 0x30 holds a LocalAlloc'd block that
     * the context destructor releases together with the context and the handle. */
    void *h, *ctx;
    REQUIRE(UN(WebAuthNCtapManageClose));
    h = alloc_handle(&ctx, 1); REQUIRE(h);
    *(void **)((BYTE *)ctx + 0x30) = LocalAlloc(LPTR, 16);
    UN(WebAuthNCtapManageClose)(h);
    CHECK(1);
}

TEST(cmclose_many_synthetic_handles)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageClose));
    for (i = 0; i < 500; i++) {
        void *ctx; void *h = alloc_handle(&ctx, i & 1); REQUIRE(h);
        UN(WebAuthNCtapManageClose)(h);
    }
    CHECK(1);
}

TEST(cmclose_and_free_null_interleaved)
{
    REQUIRE(UN(WebAuthNCtapManageClose)); REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    UN(WebAuthNCtapManageClose)(NULL);
    CHECK(1);
}

/* --- FreeDisplayCredentials --- */
TEST(cmfree_null)
{
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    CHECK(1);
}

TEST(cmfree_null_twice)
{
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    CHECK(1);
}

TEST(cmfree_null_preserves_last_error)
{
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    SET_ERR(0x4321);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(NULL);
    EXPECT_ERR(0x4321);
}

TEST(cmfree_empty_list)
{
    CM_LIST *l;
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    l = LocalAlloc(LPTR, sizeof *l); REQUIRE(l);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(l);
    CHECK(1);
}

TEST(cmfree_list_with_zero_count_and_items_array)
{
    /* count == 0: the item array is not walked and (per the decomp) not freed by this routine. */
    CM_LIST *l; void **arr;
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    l = LocalAlloc(LPTR, sizeof *l + 16 * sizeof(void *)); REQUIRE(l);
    arr = (void **)(l + 1); l->items = arr; l->count = 0;
    UN(WebAuthNCtapManageFreeDisplayCredentials)(l);
    CHECK(1);
}

TEST(cmfree_list_null_items_pointer_with_nonzero_count)
{
    /* items == NULL guards the walk even when count != 0. */
    CM_LIST *l;
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    l = LocalAlloc(LPTR, sizeof *l); REQUIRE(l);
    l->count = 5; l->items = NULL;
    UN(WebAuthNCtapManageFreeDisplayCredentials)(l);
    CHECK(1);
}

static void free_list_n(int n, int null_mask)
{
    CM_LIST *l; void **arr; int i;
    l = LocalAlloc(LPTR, sizeof *l + (n ? n : 1) * sizeof(void *)); REQUIRE(l);
    arr = (void **)(l + 1); l->items = arr; l->count = n;
    for (i = 0; i < n; i++) arr[i] = (null_mask & (1 << (i & 7))) ? NULL : LocalAlloc(LPTR, 32 + i);
    UN(WebAuthNCtapManageFreeDisplayCredentials)(l);
}
#define FREE_N(name, n, mask) TEST(cmfree_##name) { REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials)); free_list_n(n, mask); CHECK(1); }
FREE_N(one_item, 1, 0)
FREE_N(two_items, 2, 0)
FREE_N(eight_items, 8, 0)
FREE_N(hundred_items, 100, 0)
FREE_N(one_null_item, 1, 0xff)
FREE_N(alternating_null_items, 16, 0x55)
FREE_N(all_null_items, 16, 0xff)
FREE_N(first_null_only, 4, 0x01)
FREE_N(last_null_only, 4, 0x08)

TEST(cmfree_repeat_alloc_free_cycles)
{
    int i;
    REQUIRE(UN(WebAuthNCtapManageFreeDisplayCredentials));
    for (i = 0; i < 200; i++) free_list_n(i % 7, 0);
    CHECK(1);
}

TEST(cmfree_platform_credentials_alias_accepts_same_list)
{
    /* WebAuthNFreePlatformCredentials is the same code as FreeDisplayCredentials. */
    CM_LIST *l; void **arr;
    REQUIRE(UN(WebAuthNFreePlatformCredentials));
    l = LocalAlloc(LPTR, sizeof *l + 2 * sizeof(void *)); REQUIRE(l);
    arr = (void **)(l + 1); l->items = arr; l->count = 2;
    arr[0] = LocalAlloc(LPTR, 8); arr[1] = LocalAlloc(LPTR, 8);
    UN(WebAuthNFreePlatformCredentials)(l);
    UN(WebAuthNFreePlatformCredentials)(NULL);
    CHECK(1);
}
