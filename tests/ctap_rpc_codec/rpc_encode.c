/* ctap_rpc_codec: I_WebAuthNCtapEncodeMakeCredentialRpcRequest and
 * I_WebAuthNCtapEncodeGetAssertionRpcRequest.
 *
 * Behaviour taken from the Windows 10 reference decompilation:
 *   - *pcbOut = 0 and *ppbOut = NULL are written before any validation (no NULL check on them).
 *   - Missing/zero mandatory arguments return NTE_INVALID_PARAMETER (0x80090027).
 *   - The client data hash is SHA-256 over pbClientDataJSON (pwszHashAlgId must merely be non-NULL).
 *   - On success *ppbOut is a LocalAlloc block holding an RPC request map (see rpc.h) whose "request"
 *     bstr is the CTAP request: byte 0x01 + CBOR map {1: hash, 2: rp, 3: user, 4: pubKeyCredParams, ...}
 *     for make-credential, byte 0x02 + {1: rpId, 2: hash, ...} for get-assertion.
 *   - "timeout" is min(options->dwTimeoutMilliseconds, 300000); "flags" = (extra & 0x1f) | flags | 0x40000
 *     where 0x40000 is only added when none of 0x500000 are set (make-credential).
 */
#include "rpc.h"

/* ----------------------------- helpers ------------------------------------ */
typedef struct {
    int ok; unsigned long long cmd, flags, timeout;
    const BYTE *txid; size_t txlen; const BYTE *req; size_t reqlen;
    char keys[256]; int nkeys; size_t endpos;
} rpcmap;

static int parse_rpc(const BYTE *p, size_t n, rpcmap *m) {
    memset(m, 0, sizeof *m);
    m->nkeys = cr_text_keys(p, n, m->keys, sizeof m->keys, &m->endpos);
    if (m->nkeys < 0) return 0;
    if (!cr_text_uint(p, n, "command", &m->cmd) || !cr_text_uint(p, n, "flags", &m->flags) ||
        !cr_text_uint(p, n, "timeout", &m->timeout)) return 0;
    if (!cr_text_bytes(p, n, "transactionId", &m->txid, &m->txlen)) return 0;
    if (!cr_text_bytes(p, n, "request", &m->req, &m->reqlen)) { m->req = NULL; m->reqlen = 0; }
    m->ok = 1; return 1;
}

static BYTE g_opts[0x100];
static void *mc_opts(DWORD ver, DWORD timeout) { memset(g_opts, 0, sizeof g_opts); *(DWORD *)g_opts = ver; *(DWORD *)(g_opts + 4) = timeout; return g_opts; }

/* Encode with defaults and parse; returns result (caller frees). */
static enc_res mc_ok(rpcmap *m, ULONG cmd, ULONG flags, ULONG extra, const void *opts) {
    mc_args a; mc_args_init(&a);
    enc_res r = mc_encode(&a, cmd, flags, extra, opts, NULL, NULL);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    memset(m, 0, sizeof *m);
    if (r.hr == 0 && r.pb) CHECK(parse_rpc(r.pb, r.cb, m));
    return r;
}

/* ===================== make-credential: parameter validation ================== */
#define MC_BAD(name, stmt) \
TEST(ctaprpc_mc_encode_invalid_##name) { \
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)); \
    mc_args a; mc_args_init(&a); stmt; \
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL); \
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_PARAM); \
    EXPECT_EQ(r.cb, 0); CHECK(r.pb == NULL); \
}
MC_BAD(rp_version_zero, a.rp.dwVersion = 0)
MC_BAD(rp_id_null, a.rp.pwszId = NULL)
MC_BAD(user_id_len_zero, a.user.cbId = 0)
MC_BAD(user_id_null, a.user.pbId = NULL)
MC_BAD(no_algs_count_zero, a.cps.cCredentialParameters = 0)
MC_BAD(no_algs_ptr_null, a.cps.pCredentialParameters = NULL)
MC_BAD(clientdata_version_zero, a.cd.dwVersion = 0)
MC_BAD(clientdata_hashalg_null, a.cd.pwszHashAlgId = NULL)
MC_BAD(clientdata_json_null, a.cd.pbClientDataJSON = NULL)
MC_BAD(clientdata_json_len_zero, a.cd.cbClientDataJSON = 0)

TEST(ctaprpc_mc_encode_invalid_null_rp) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 5, 0, 0, NULL, &a.user, &a.cps, &a.cd, NULL, NULL, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_null_user) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 5, 0, 0, &a.rp, NULL, &a.cps, &a.cd, NULL, NULL, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_null_params) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 5, 0, 0, &a.rp, &a.user, NULL, &a.cd, NULL, NULL, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_null_clientdata) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 5, 0, 0, &a.rp, &a.user, &a.cps, NULL, NULL, NULL, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_options_version_zero) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    enc_res r = mc_encode(&a, 5, 0, 0, mc_opts(0, 1234), NULL, NULL);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(r.cb, 0); CHECK(r.pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_all_null_pointers) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_mc_encode_invalid_user_name_not_required) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* The validation block only inspects user id; name/icon/displayName may be NULL (record result). */
    mc_args a; mc_args_init(&a); a.user.pwszName = NULL; a.user.pwszDisplayName = NULL;
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    t_note("mc encode with NULL user name/displayName: hr=0x%08lx", (unsigned long)r.hr);
    CHECKF(r.hr != (LONG)HR_INVALID_PARAM || r.pb == NULL, "invalid-parameter path must leave no buffer");
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_invalid_leaves_no_allocation) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); a.rp.pwszId = NULL;
    SIZE_T before = crc_private_bytes();
    for (int i = 0; i < 20000; i++) { enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL); if (r.hr != HR_INVALID_PARAM || r.pb) { CHECK(0); break; } }
    SIZE_T after = crc_private_bytes();
    if (before && after) CHECKF(after < before + 2 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}

/* ===================== make-credential: successful encoding ================== */
TEST(ctaprpc_mc_encode_minimal_succeeds) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    CHECK(r.pb != NULL); CHECK(r.cb > 0);
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_output_is_localalloc_block) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) {
        SIZE_T sz = LocalSize(r.pb);
        CHECKF(sz >= r.cb, "LocalSize=%zu cb=%lu", sz, r.cb);
        CHECK(LocalFree(r.pb) == NULL);   /* LocalFree succeeded: ownership passes to the caller */
        r.pb = NULL;
    }
}
TEST(ctaprpc_mc_encode_map_has_exact_length) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) { CHECKF(m.endpos == r.cb, "cbor ends at %zu, cb=%lu", m.endpos, r.cb); }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_map_key_order) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) {
        EXPECT_STR(m.keys, "command,flags,timeout,transactionId,request");
        CHECK(m.nkeys == 5);
        CHECK(r.pb[0] == 0xA5);
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_command_passthrough) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    static const ULONG cmds[] = { 0, 1, 5, 6, 0x1234 };
    for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
        rpcmap m; enc_res r = mc_ok(&m, cmds[i], 0, 0, NULL);
        if (r.pb) CHECKF(m.cmd == cmds[i], "cmd %lu -> %llu", cmds[i], m.cmd);
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_transaction_id_is_guid_bytes) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) {
        CHECK(m.txlen == 16);
        if (m.txlen == 16) CHECK(!memcmp(m.txid, CRC_TXID_BYTES, 16));
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_only_txid_differs_between_guids) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); GUID g2 = CRC_TXID; g2.Data1 ^= 0xFFFFFFFF; g2.Data4[7] ^= 0xFF;
    enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, &CRC_TXID), r2 = mc_encode(&a, 5, 0, 0, NULL, NULL, &g2);
    CHECK(r1.hr == 0 && r2.hr == 0);
    if (r1.pb && r2.pb) {
        CHECK(r1.cb == r2.cb);
        if (r1.cb == r2.cb) { int diff = 0; for (ULONG i = 0; i < r1.cb; i++) diff += r1.pb[i] != r2.pb[i]; CHECKF(diff == 5, "diff=%d", diff); }
    }
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_deterministic) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL), r2 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r1.hr == 0 && r2.hr == 0);
    if (r1.pb && r2.pb) { CHECK(r1.cb == r2.cb); CHECK(r1.cb == r2.cb && !memcmp(r1.pb, r2.pb, r1.cb)); }
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_distinct_allocations) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL), r2 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r1.pb != NULL && r1.pb != r2.pb);
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_request_begins_with_ctap_makecredential) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) { CHECK(m.reqlen > 2); CHECK(m.req[0] == 0x01); CHECK(m.req[1] == 0xA4); }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_request_int_keys_ascending) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) {
        char keys[64]; size_t end = 0;
        int n = cr_int_keys(m.req + 1, m.reqlen - 1, keys, sizeof keys, &end);
        CHECK(n == 4); EXPECT_STR(keys, "1,2,3,4");
        CHECKF(end == m.reqlen - 1, "end=%zu len=%zu", end, m.reqlen - 1);
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_clientdata_hash_is_sha256_of_json) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) {
        size_t o, l; BYTE want[32]; crc_sha256(CRC_CLIENTDATA_JSON, sizeof CRC_CLIENTDATA_JSON - 1, want);
        CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 1, &o, &l));
        size_t pos = o; citem it;
        if (!cr_head(m.req + 1, m.reqlen - 1, &pos, &it)) {
            CHECK(it.major == 2); CHECK(it.hlen == 32);
            if (it.hlen == 32) CHECK(!memcmp(it.data, want, 32));
        }
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_hash_alg_name_not_used_for_hashing) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* pwszHashAlgId is only required to be non-NULL; the hash is SHA-256 whatever the string says. */
    mc_args a; mc_args_init(&a); enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    a.cd.pwszHashAlgId = L"SHA-512"; enc_res r2 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r1.hr == 0); CHECKF(r2.hr == 0, "hr=0x%08lx", (unsigned long)r2.hr);
    if (r1.pb && r2.pb) CHECK(r1.cb == r2.cb && !memcmp(r1.pb, r2.pb, r1.cb));
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_hash_changes_with_json) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    a.cdj[10] ^= 1; enc_res r2 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r1.hr == 0 && r2.hr == 0);
    if (r1.pb && r2.pb) { CHECK(r1.cb == r2.cb); CHECK(r1.cb != r2.cb || memcmp(r1.pb, r2.pb, r1.cb) != 0); }
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_rp_entity_map) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 2, &o, &l));
        const BYTE *rp = m.req + 1 + o; const BYTE *s; size_t sl;
        CHECK(rp[0] >= 0xA1 && rp[0] <= 0xA3);       /* map of id[,icon][,name] */
        CHECK(cr_text_bytes(rp, l, "id", &s, &sl) && sl == 11 && !memcmp(s, "example.com", 11));
        CHECK(cr_text_bytes(rp, l, "name", &s, &sl) && sl == 7 && !memcmp(s, "Example", 7));
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_user_entity_map) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 3, &o, &l));
        const BYTE *u = m.req + 1 + o; const BYTE *s; size_t sl;
        CHECK(cr_text_bytes(u, l, "id", &s, &sl) && sl == 8);
        if (sl == 8) { for (int i = 0; i < 8; i++) CHECK(s[i] == 0xA0 + i); }
        CHECK(cr_text_bytes(u, l, "name", &s, &sl) && sl == 5 && !memcmp(s, "alice", 5));
        CHECK(cr_text_bytes(u, l, "displayName", &s, &sl) && sl == 5 && !memcmp(s, "Alice", 5));
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_cred_params_array) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 4, &o, &l));
        const BYTE *p = m.req + 1 + o;
        /* [ { "alg": -7, "type": "public-key" } ] */
        static const BYTE want[] = { 0x81, 0xA2, 0x63, 'a', 'l', 'g', 0x26, 0x64, 't', 'y', 'p', 'e', 0x6A, 'p', 'u', 'b', 'l', 'i', 'c', '-', 'k', 'e', 'y' };
        CHECKF(l == sizeof want && !memcmp(p, want, sizeof want), "params len=%zu", l);
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_multiple_algs_in_order) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    CRC_COSE_PARAM cp[3] = { { 1, L"public-key", -7 }, { 1, L"public-key", -257 }, { 1, L"public-key", -8 } };
    a.cps.cCredentialParameters = 3; a.cps.pCredentialParameters = cp;
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r.hr == 0);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m) && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 4, &o, &l));
        const BYTE *p = m.req + 1 + o; size_t pos = 0; citem it;
        CHECK(!cr_head(p, l, &pos, &it) && it.major == 4 && it.val == 3);
        static const long long want[3] = { -7, -257, -8 };
        for (int i = 0; i < 3; i++) {
            citem mp; CHECK(!cr_head(p, l, &pos, &mp) && mp.major == 5 && mp.val == 2);
            citem k, v; CHECK(!cr_head(p, l, &pos, &k) && k.hlen == 3 && !memcmp(k.data, "alg", 3));
            CHECK(!cr_head(p, l, &pos, &v) && v.major == 1 && (long long)(-1 - (long long)v.val) == want[i]);
            CHECK(!cr_skip(p, l, &pos) && !cr_skip(p, l, &pos));
        }
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_scopedcred_type_becomes_public_key) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); a.cp.pwszCredentialType = L"ScopedCred";
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r.hr == 0);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m) && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 4, &o, &l));
        const BYTE *p = m.req + 1 + o; const BYTE *s; size_t sl;
        CHECK(l > 4 && cr_text_bytes(p + 1, l - 1, "type", &s, &sl) && sl == 10 && !memcmp(s, "public-key", 10));
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_timeout_null_options_is_zero) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) CHECK(m.timeout == 0);
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_timeout_from_options) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    static const DWORD tin[] = { 0, 1, 1000, 60000, 299999, 300000 };
    for (size_t i = 0; i < sizeof tin / sizeof tin[0]; i++) {
        rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, mc_opts(1, tin[i]));
        if (r.pb) CHECKF(m.timeout == tin[i], "in=%lu out=%llu", tin[i], m.timeout);
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_timeout_clamped_to_300000) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    static const DWORD tin[] = { 300001, 400000, 0x7FFFFFFF, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof tin / sizeof tin[0]; i++) {
        rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, mc_opts(1, tin[i]));
        if (r.pb) CHECKF(m.timeout == 300000, "in=%lu out=%llu", tin[i], m.timeout);
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_flags_default_adds_0x40000) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) { CHECKF((m.flags & 0x40000) != 0, "flags=0x%llx", m.flags); t_note("mc flags (default) = 0x%llx", m.flags); }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_flags_passthrough_table) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* flags with any of 0x500000 set suppress the implicit 0x40000; every input bit is preserved. */
    static const ULONG fin[] = { 0, 0x100000, 0x400000, 0x500000, 0x800000, 0x1000000, 0x8000000, 0x2000, 0x1 };
    for (size_t i = 0; i < sizeof fin / sizeof fin[0]; i++) {
        rpcmap m; enc_res r = mc_ok(&m, 5, fin[i], 0, NULL);
        if (!r.pb) { enc_free(&r); continue; }
        CHECKF((m.flags & fin[i]) == fin[i], "in=0x%lx out=0x%llx", fin[i], m.flags);
        int want40000 = (fin[i] & 0x500000) == 0;
        CHECKF(((m.flags & 0x40000) != 0) == want40000, "in=0x%lx out=0x%llx", fin[i], m.flags);
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_extra_low_five_bits_merged) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    static const ULONG ein[] = { 0x1, 0x3, 0x10, 0x1F };
    for (size_t i = 0; i < sizeof ein / sizeof ein[0]; i++) {
        rpcmap m; enc_res r = mc_ok(&m, 5, 0, ein[i], NULL);
        if (r.pb) CHECKF((m.flags & 0x1F) == ein[i], "in=0x%lx out=0x%llx", ein[i], m.flags);
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_extra_bit5_not_merged) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m0, m1; enc_res r0 = mc_ok(&m0, 5, 0, 0, NULL), r1 = mc_ok(&m1, 5, 0, 0x20, NULL);
    if (r0.pb && r1.pb) CHECKF(m0.flags == m1.flags, "0x%llx vs 0x%llx", m0.flags, m1.flags);
    enc_free(&r0); enc_free(&r1);
}
TEST(ctaprpc_mc_encode_user_verification_option_flags) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* options->dwUserVerificationRequirement (offset 0x30): 1 -> 0x400000, 2 -> 0x800000 */
    for (DWORD uv = 1; uv <= 2; uv++) {
        BYTE *o = (BYTE *)mc_opts(1, 0); *(DWORD *)(o + 0x30) = uv;
        rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, o);
        if (r.pb) {
            ULONG bit = uv == 1 ? 0x400000 : 0x800000;
            CHECKF((m.flags & bit) != 0, "uv=%lu flags=0x%llx", uv, m.flags);
            if (uv == 1) CHECKF((m.flags & 0x40000) == 0, "0x40000 must not be added with UV required: 0x%llx", m.flags);
        }
        enc_free(&r);
    }
}
TEST(ctaprpc_mc_encode_options_v1_zero_equals_null_options) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    enc_res r1 = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL), r2 = mc_encode(&a, 5, 0, 0, mc_opts(1, 0), NULL, NULL);
    CHECK(r1.hr == 0); CHECKF(r2.hr == 0, "hr=0x%08lx", (unsigned long)r2.hr);
    if (r1.pb && r2.pb) { CHECK(r1.cb == r2.cb); if (r1.cb == r2.cb) CHECK(!memcmp(r1.pb, r2.pb, r1.cb)); }
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_mc_encode_without_device_info_has_no_list) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    rpcmap m; enc_res r = mc_ok(&m, 5, 0, 0, NULL);
    if (r.pb) CHECK(strstr(m.keys, "deviceInfoList") == NULL);
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_with_device_info_adds_list) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); devinfo_t d; devinfo_init(&d, L"TestProvider");
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, &d, NULL);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m)) {
        CHECKF(strstr(m.keys, "deviceInfoList") != NULL, "keys=%s", m.keys);
        CHECK(m.nkeys == 6);
        size_t o, l; if (cr_text_find(r.pb, r.cb, "deviceInfoList", &o, &l)) {
            CHECK(r.pb[o] >> 5 == 4);   /* array */
        }
    }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_device_info_without_provider_name) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* providerName is mandatory when a device info structure is supplied; outcome recorded. */
    mc_args a; mc_args_init(&a); devinfo_t d; devinfo_init(&d, NULL);
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, &d, NULL);
    t_note("mc encode with devinfo lacking providerName: hr=0x%08lx cb=%lu", (unsigned long)r.hr, r.cb);
    if (r.hr < 0) { CHECK(r.pb == NULL); CHECK(r.cb == 0); }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_device_info_version_zero) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); devinfo_t d; devinfo_init(&d, L"TestProvider"); *(DWORD *)d.raw = 0;
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, &d, NULL);
    t_note("mc encode with devinfo version 0: hr=0x%08lx", (unsigned long)r.hr);
    if (r.hr < 0) { CHECK(r.pb == NULL); CHECK(r.cb == 0); }
    enc_free(&r);
}
TEST(ctaprpc_mc_encode_rpc_request_struct_filled) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* The _CTAPCBOR_RPC_REQUEST out structure: version 1 at +0, command at +4, flags at +8, timeout at +0xC,
     * transaction GUID at +0x10, CTAP request length at +0x88 and pointer at +0x90. */
    mc_args a; mc_args_init(&a); static BYTE rq[0x200]; memset(rq, 0, sizeof rq); /* out struct must start zeroed: Windows dereferences stale pointers in it (0xCC poison -> access violation) */
    GUID g = CRC_TXID; ULONG cb = 0; BYTE *pb = NULL;
    LONG hr = UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)(&g, 5, 0, 0, &a.rp, &a.user, &a.cps, &a.cd, mc_opts(1, 4321), NULL, NULL, rq, &cb, &pb);
    CHECK(hr == 0);
    if (hr == 0) {
        CHECK(*(DWORD *)(rq + 0) == 1);
        CHECK(*(DWORD *)(rq + 4) == 5);
        CHECK(*(DWORD *)(rq + 0xC) == 4321);
        CHECK(!memcmp(rq + 0x10, &CRC_TXID, 16));
        CHECK(*(DWORD *)(rq + 0x88) > 2);
        CHECK(*(void **)(rq + 0x90) != NULL);
        t_note("rpc request flags field = 0x%08lx", (unsigned long)*(DWORD *)(rq + 8));
    }
    if (pb) LocalFree(pb);
}
TEST(ctaprpc_mc_encode_repeated_calls_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a);
    enc_res w = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL); ULONG ref = w.cb; enc_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 20000; i++) { enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL); if (r.hr != 0 || r.cb != ref) bad++; enc_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d bad results", bad);
    if (before && after) { CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before); t_note("mc encode x20000 private-bytes growth within bound"); }
}
TEST(ctaprpc_mc_encode_large_user_id) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* A 64-byte user handle is the CTAP maximum; larger is not rejected by this layer (recorded). */
    mc_args a; mc_args_init(&a); BYTE big[64]; memset(big, 0x77, sizeof big);
    a.user.cbId = 64; a.user.pbId = big;
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m) && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 3, &o, &l));
        const BYTE *s; size_t sl; CHECK(cr_text_bytes(m.req + 1 + o, l, "id", &s, &sl) && sl == 64);
    }
    enc_free(&r);
    BYTE *huge = (BYTE *)calloc(1, 200); a.user.cbId = 200; a.user.pbId = huge;
    r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    t_note("mc encode with 200-byte user id: hr=0x%08lx", (unsigned long)r.hr);
    enc_free(&r); free(huge);
}
TEST(ctaprpc_mc_encode_unicode_names_utf8) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    /* "Zoë" -> UTF-8 5A 6F C3 AB */
    mc_args a; mc_args_init(&a); a.user.pwszName = L"Zo\x00EB"; a.user.pwszDisplayName = L"Zo\x00EB";
    enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    CHECK(r.hr == 0);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m) && m.req) {
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 3, &o, &l));
        const BYTE *s; size_t sl;
        CHECK(cr_text_bytes(m.req + 1 + o, l, "name", &s, &sl) && sl == 4 && !memcmp(s, "Zo\xC3\xAB", 4));
    }
    enc_free(&r);
}

/* ===================== get-assertion: parameter validation =================== */
#define GA_BAD(name, stmt, rpid) \
TEST(ctaprpc_ga_encode_invalid_##name) { \
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); \
    ga_args a; ga_args_init(&a); stmt; \
    enc_res r = ga_encode(&a, rpid, 6, 0, 0, NULL, NULL, NULL); \
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(r.cb, 0); CHECK(r.pb == NULL); \
}
GA_BAD(rpid_null, (void)0, NULL)
GA_BAD(clientdata_version_zero, a.cd.dwVersion = 0, L"example.com")
GA_BAD(clientdata_hashalg_null, a.cd.pwszHashAlgId = NULL, L"example.com")
GA_BAD(clientdata_json_null, a.cd.pbClientDataJSON = NULL, L"example.com")
GA_BAD(clientdata_json_len_zero, a.cd.cbClientDataJSON = 0, L"example.com")

TEST(ctaprpc_ga_encode_invalid_null_clientdata) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)(&g, 6, 0, 0, L"example.com", NULL, NULL, NULL, NULL, 0, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}
TEST(ctaprpc_ga_encode_invalid_options_version_zero) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    ga_args a; ga_args_init(&a);
    enc_res r = ga_encode(&a, L"example.com", 6, 0, 0, mc_opts(0, 500), NULL, NULL);
    EXPECT_EQ((ULONG)r.hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(r.cb, 0); CHECK(r.pb == NULL);
}
TEST(ctaprpc_ga_encode_invalid_all_null) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    GUID g = CRC_TXID; static BYTE rq[0x200]; ULONG cb = 77; BYTE *pb = (BYTE *)1;
    LONG hr = UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)(&g, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, rq, &cb, &pb);
    EXPECT_EQ((ULONG)hr, (ULONG)HR_INVALID_PARAM); EXPECT_EQ(cb, 0); CHECK(pb == NULL);
}

/* ===================== get-assertion: successful encoding ==================== */
static enc_res ga_ok(rpcmap *m, LPCWSTR rpid, ULONG cmd, ULONG flags, ULONG extra, const void *opts) {
    ga_args a; ga_args_init(&a);
    enc_res r = ga_encode(&a, rpid, cmd, flags, extra, opts, NULL, NULL);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    memset(m, 0, sizeof *m);
    if (r.hr == 0 && r.pb) CHECK(parse_rpc(r.pb, r.cb, m));
    return r;
}
TEST(ctaprpc_ga_encode_minimal_succeeds) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    rpcmap m; enc_res r = ga_ok(&m, L"example.com", 6, 0, 0, NULL);
    CHECK(r.pb != NULL && r.cb > 0);
    if (r.pb) { CHECK(LocalSize(r.pb) >= r.cb); CHECKF(m.endpos == r.cb, "end=%zu cb=%lu", m.endpos, r.cb); }
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_map_key_order) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    rpcmap m; enc_res r = ga_ok(&m, L"example.com", 6, 0, 0, NULL);
    if (r.pb) { EXPECT_STR(m.keys, "command,flags,timeout,transactionId,request"); CHECK(r.pb[0] == 0xA5); }
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_command_and_txid) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    static const ULONG cmds[] = { 0, 6, 0x99 };
    for (size_t i = 0; i < 3; i++) {
        rpcmap m; enc_res r = ga_ok(&m, L"example.com", cmds[i], 0, 0, NULL);
        if (r.pb) { CHECK(m.cmd == cmds[i]); CHECK(m.txlen == 16 && !memcmp(m.txid, CRC_TXID_BYTES, 16)); }
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_request_begins_with_ctap_getassertion) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, 0, NULL);
    if (r.pb && m.req) { CHECK(m.reqlen > 2); CHECK(m.req[0] == 0x02); CHECK(m.req[1] == 0xA3); /* Windows 10 also emits key 5 (options) */ }
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_request_keys_rpid_then_hash) {
    /* Windows 10 emits keys 1 (rpId), 2 (clientDataHash) and 5 (options map). */
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, 0, NULL);
    if (r.pb && m.req) {
        char keys[32]; size_t end = 0; int n = cr_int_keys(m.req + 1, m.reqlen - 1, keys, sizeof keys, &end);
        CHECK(n == 3); EXPECT_STR(keys, "1,2,5"); CHECK(end == m.reqlen - 1);
        { size_t o5, l5, p5; citem i5; if (cr_int_find(m.req + 1, m.reqlen - 1, 5, &o5, &l5)) { p5 = o5; if (!cr_head(m.req + 1, m.reqlen - 1, &p5, &i5)) CHECK(i5.major == 5); } else CHECK(0); }
        size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 1, &o, &l));
        size_t pos = o; citem it;
        if (!cr_head(m.req + 1, m.reqlen - 1, &pos, &it)) { CHECK(it.major == 3); CHECK(it.hlen == 11 && !memcmp(it.data, "example.com", 11)); }
        CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 2, &o, &l));
        pos = o; BYTE want[32]; crc_sha256(CRC_GA_CLIENTDATA_JSON, sizeof CRC_GA_CLIENTDATA_JSON - 1, want);
        if (!cr_head(m.req + 1, m.reqlen - 1, &pos, &it)) { CHECK(it.major == 2 && it.hlen == 32); if (it.hlen == 32) CHECK(!memcmp(it.data, want, 32)); }
    }
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_rpid_variants) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    static const struct { LPCWSTR w; const char *u; } t[] = {
        { L"a.b", "a.b" }, { L"localhost", "localhost" }, { L"sub.domain.example.org", "sub.domain.example.org" },
        { L"xn--bcher-kva.example", "xn--bcher-kva.example" }, { L"B\x00FC" L"cher.example", "B\xC3\xBC" "cher.example" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        rpcmap m; enc_res r = ga_ok(&m, t[i].w, 0, 0, 0, NULL);
        if (r.pb && m.req) {
            size_t o, l; CHECK(cr_int_find(m.req + 1, m.reqlen - 1, 1, &o, &l));
            size_t pos = o; citem it;
            if (!cr_head(m.req + 1, m.reqlen - 1, &pos, &it)) CHECKF(it.hlen == strlen(t[i].u) && !memcmp(it.data, t[i].u, it.hlen), "rpid #%zu", i);
        }
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_timeout_from_options) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    static const struct { DWORD in, out; } t[] = { { 0, 0 }, { 1, 1 }, { 5000, 5000 }, { 300000, 300000 }, { 300001, 300000 }, { 0xFFFFFFFF, 300000 } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, 0, mc_opts(1, t[i].in));
        if (r.pb) CHECKF(m.timeout == t[i].out, "in=%lu out=%llu", t[i].in, m.timeout);
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_timeout_null_options_zero) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, 0, NULL);
    if (r.pb) CHECK(m.timeout == 0);
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_user_verification_flags) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    /* options->dwUserVerificationRequirement (offset 0x2c): 1 -> 0x400000, 2 -> 0x800000, 3 -> 0x1000000 */
    static const ULONG bits[] = { 0, 0x400000, 0x800000, 0x1000000 };
    for (DWORD uv = 1; uv <= 3; uv++) {
        BYTE *o = (BYTE *)mc_opts(1, 0); *(DWORD *)(o + 0x2c) = uv;
        rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, 0, o);
        if (r.pb) CHECKF((m.flags & bits[uv]) == bits[uv], "uv=%lu flags=0x%llx", uv, m.flags);
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_flags_passthrough) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    static const ULONG fin[] = { 0, 0x400000, 0x800000, 0x1000000, 0x100000 };
    for (size_t i = 0; i < sizeof fin / sizeof fin[0]; i++) {
        rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, fin[i], 0, NULL);
        if (r.pb) CHECKF((m.flags & fin[i]) == fin[i], "in=0x%lx out=0x%llx", fin[i], m.flags);
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_extra_low_bits) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    static const ULONG e[] = { 1, 2, 0x1F };
    for (size_t i = 0; i < 3; i++) {
        rpcmap m; enc_res r = ga_ok(&m, L"example.com", 0, 0, e[i], NULL);
        if (r.pb) CHECKF((m.flags & 0x1F) == e[i], "in=0x%lx out=0x%llx", e[i], m.flags);
        enc_free(&r);
    }
}
TEST(ctaprpc_ga_encode_deterministic_and_owned) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    ga_args a; ga_args_init(&a);
    enc_res r1 = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL), r2 = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL);
    CHECK(r1.hr == 0 && r2.hr == 0);
    if (r1.pb && r2.pb) { CHECK(r1.pb != r2.pb); CHECK(r1.cb == r2.cb && !memcmp(r1.pb, r2.pb, r1.cb)); CHECK(LocalSize(r1.pb) >= r1.cb); }
    enc_free(&r1); enc_free(&r2);
}
TEST(ctaprpc_ga_encode_struct_filled) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    ga_args a; ga_args_init(&a); static BYTE rq[0x200]; memset(rq, 0, sizeof rq); /* out struct must start zeroed: Windows dereferences stale pointers in it (0xCC poison -> access violation) */
    GUID g = CRC_TXID; ULONG cb = 0; BYTE *pb = NULL;
    LONG hr = UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)(&g, 6, 0, 0, L"example.com", &a.cd, mc_opts(1, 777), NULL, NULL, 0, NULL, rq, &cb, &pb);
    CHECK(hr == 0);
    if (hr == 0) {
        CHECK(*(DWORD *)(rq + 0) == 1); CHECK(*(DWORD *)(rq + 4) == 6); CHECK(*(DWORD *)(rq + 0xC) == 777);
        CHECK(!memcmp(rq + 0x10, &CRC_TXID, 16)); CHECK(*(DWORD *)(rq + 0x88) > 2); CHECK(*(BYTE **)(rq + 0x90) != NULL);
    }
    if (pb) LocalFree(pb);
}
TEST(ctaprpc_ga_encode_with_device_info_adds_list) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    ga_args a; ga_args_init(&a); devinfo_t d; devinfo_init(&d, L"TestProvider");
    enc_res r = ga_encode(&a, L"example.com", 0, 0, 0, NULL, &d, NULL);
    CHECKF(r.hr == 0, "hr=0x%08lx", (unsigned long)r.hr);
    rpcmap m; if (r.pb && parse_rpc(r.pb, r.cb, &m)) { CHECKF(strstr(m.keys, "deviceInfoList") != NULL, "keys=%s", m.keys); CHECK(m.nkeys == 6); }
    enc_free(&r);
}
TEST(ctaprpc_ga_encode_repeated_calls_no_leak) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest));
    ga_args a; ga_args_init(&a);
    enc_res w = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL); ULONG ref = w.cb; enc_free(&w);
    SIZE_T before = crc_private_bytes(); int bad = 0;
    for (int i = 0; i < 20000; i++) { enc_res r = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL); if (r.hr != 0 || r.cb != ref) bad++; enc_free(&r); }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d bad results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "grew %lld", (long long)after - (long long)before);
}

/* ===================== round trips into WebAuthNCtapRpcGetCborCommand ========== */
TEST(ctaprpc_roundtrip_mc_encode_to_getcbor_command) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)); REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* RPC command 0 is what WebAuthNCtapRpcGetCborCommand accepts; the CTAP byte yields 1. */
    mc_args a; mc_args_init(&a); enc_res r = mc_encode(&a, 0, 0, 0, NULL, NULL, NULL);
    CHECK(r.hr == 0);
    if (r.pb) { BYTE cmd = 0xEE; ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(r.cb, r.pb, &cmd); CHECKF(hr == 0 && cmd == 1, "hr=0x%08lx cmd=%u", (unsigned long)hr, cmd); }
    enc_free(&r);
}
TEST(ctaprpc_roundtrip_ga_encode_to_getcbor_command) {
    REQUIRE(UN(I_WebAuthNCtapEncodeGetAssertionRpcRequest)); REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    ga_args a; ga_args_init(&a); enc_res r = ga_encode(&a, L"example.com", 0, 0, 0, NULL, NULL, NULL);
    CHECK(r.hr == 0);
    if (r.pb) { BYTE cmd = 0xEE; ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(r.cb, r.pb, &cmd); CHECKF(hr == 0 && cmd == 2, "hr=0x%08lx cmd=%u", (unsigned long)hr, cmd); }
    enc_free(&r);
}
TEST(ctaprpc_roundtrip_mc_command5_rejected_by_getcbor_command) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest)); REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    mc_args a; mc_args_init(&a); enc_res r = mc_encode(&a, 5, 0, 0, NULL, NULL, NULL);
    if (r.pb) { BYTE cmd = 0xEE; ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(r.cb, r.pb, &cmd); CHECKF(hr == (ULONG)HR_INVALID_PARAM && cmd == 0, "hr=0x%08lx cmd=%u", (unsigned long)hr, cmd); }
    enc_free(&r);
}
TEST(ctaprpc_roundtrip_encoded_request_fits_cbor_layer_limit) {
    REQUIRE(UN(I_WebAuthNCtapEncodeMakeCredentialRpcRequest));
    mc_args a; mc_args_init(&a); enc_res r = mc_encode(&a, 0, 0, 0, NULL, NULL, NULL);
    if (r.pb) CHECKF(r.cb <= 0x2000, "encoded request is %lu bytes", r.cb);
    enc_free(&r);
}
