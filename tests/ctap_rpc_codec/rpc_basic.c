/* ctap_rpc_codec: export presence/ordinals and WebAuthNCtapRpcGetCborCommand.
 *
 * WebAuthNCtapRpcGetCborCommand(cb, pb, &cmd): decodes an RPC request map (see rpc.h), requires
 *   command == 0 and a non-empty "request" bstr whose first byte is the CTAP command:
 *   0x01 -> *cmd = 1, 0x02 -> *cmd = 2, anything else -> 0x80090027 with *cmd = 0.
 *   Input size 0, NULL pointer, or more than 0x2000 bytes -> 0x8007044C. *cmd is always written.
 */
#include "rpc.h"

/* ---- presence and ordinals ---------------------------------------------- */
static const struct { const char *name; unsigned ord; } k_exports[] = {
    { "I_WebAuthNCtapDecodeGetAssertionRpcResponse", 2 },
    { "I_WebAuthNCtapDecodeMakeCredentialRpcResponse", 3 },
    { "I_WebAuthNCtapEncodeGetAssertionRpcRequest", 4 },
    { "I_WebAuthNCtapEncodeMakeCredentialRpcRequest", 5 },
    { "WebAuthNCtapRpcGetAssertionUserList", 32 },
    { "WebAuthNCtapRpcGetCborCommand", 33 },
    { "WebAuthNCtapRpcSelectGetAssertion", 34 },
};
#define NEXP (sizeof k_exports / sizeof k_exports[0])

TEST(ctaprpc_exports_resolve_by_name) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < NEXP; i++) {
        FARPROC p = t_proc_in("webauthn.dll", k_exports[i].name);
        CHECKF(p != NULL, "%s", k_exports[i].name);
    }
}
TEST(ctaprpc_exports_ordinals_match_names) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < NEXP; i++) {
        FARPROC byName = t_proc_in("webauthn.dll", k_exports[i].name);
        FARPROC byOrd = t_proc_ord("webauthn.dll", k_exports[i].ord);
        CHECKF(byName != NULL && byName == byOrd, "%s ordinal %u", k_exports[i].name, k_exports[i].ord);
    }
}
TEST(ctaprpc_exports_not_forwarded) {
    /* All seven are real code in webauthn.dll itself. */
    HMODULE m = t_module("webauthn.dll"); REQUIRE(m);
    for (size_t i = 0; i < NEXP; i++) {
        FARPROC p = GetProcAddress(m, k_exports[i].name);
        HMODULE owner = NULL;
        BOOL ok = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner);
        CHECKF(ok && owner == m, "%s owned by webauthn.dll", k_exports[i].name);
    }
}
TEST(ctaprpc_exports_distinct_addresses) {
    REQUIRE(t_module("webauthn.dll"));
    for (size_t i = 0; i < NEXP; i++)
        for (size_t j = i + 1; j < NEXP; j++)
            CHECKF(t_proc_in("webauthn.dll", k_exports[i].name) != t_proc_in("webauthn.dll", k_exports[j].name), "%s vs %s", k_exports[i].name, k_exports[j].name);
}
TEST(ctaprpc_exports_case_sensitive) {
    HMODULE m = t_module("webauthn.dll"); REQUIRE(m);
    SET_ERR(0);
    FARPROC p = GetProcAddress(m, "webauthnctaprpcgetcborcommand");
    CHECK(p == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(ctaprpc_exports_noexist_neighbour) {
    HMODULE m = t_module("webauthn.dll"); REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "WebAuthNCtapRpcGetCborCommandA") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "WebAuthNCtapRpcGetCborCommandW") == NULL); EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}
TEST(ctaprpc_exports_free_helpers_present) {
    /* Used for ownership checks below. */
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    REQUIRE(UN(WebAuthNFreeAssertion));
    CHECK(crc_cotaskfree() != NULL);
}
TEST(ctaprpc_free_helpers_accept_null) {
    REQUIRE(UN(WebAuthNFreeCredentialAttestation));
    REQUIRE(UN(WebAuthNFreeAssertion));
    UN(WebAuthNFreeCredentialAttestation)(NULL);   /* NULL-checked in the reference implementation */
    UN(WebAuthNFreeAssertion)(NULL);
    CHECK(1);
}

/* ---- WebAuthNCtapRpcGetCborCommand ---------------------------------------- */
static ULONG gcc_call(const cbuf *c, size_t cb, BYTE *cmd) {
    return (ULONG)UN(WebAuthNCtapRpcGetCborCommand)((ULONG)cb, c->b, cmd);
}
static void gcc_expect(const char *what, unsigned cmdv, const BYTE *req, size_t reqlen, ULONG want, BYTE wantCmd) {
    cbuf c; BYTE txid[16]; memset(txid, 0x5A, 16);
    rpc_request(&c, cmdv, 0x40000, 1000, txid, 16, req, reqlen);
    BYTE cmd = 0xEE;
    ULONG hr = gcc_call(&c, c.n, &cmd);
    CHECKF(hr == want, "%s: hr=0x%08lx want 0x%08lx", what, (unsigned long)hr, (unsigned long)want);
    CHECKF(cmd == wantCmd, "%s: cmd=%u want %u", what, cmd, wantCmd);
}

TEST(ctaprpc_getcbor_makecredential_byte) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE r[] = { 0x01, 0xA0 };
    gcc_expect("mc", 0, r, sizeof r, 0, 1);
}
TEST(ctaprpc_getcbor_getassertion_byte) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE r[] = { 0x02, 0xA0 };
    gcc_expect("ga", 0, r, sizeof r, 0, 2);
}
TEST(ctaprpc_getcbor_single_byte_request) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE r1[] = { 0x01 }, r2[] = { 0x02 };
    gcc_expect("mc-1byte", 0, r1, 1, 0, 1);
    gcc_expect("ga-1byte", 0, r2, 1, 0, 2);
}
TEST(ctaprpc_getcbor_unsupported_ctap_commands) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* Only 0x01 and 0x02 are accepted; everything else is NTE_INVALID_PARAMETER with *cmd == 0. */
    static const BYTE bad[] = { 0x00, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x40, 0x7F, 0x80, 0xA0, 0xC0, 0xFE, 0xFF };
    for (size_t i = 0; i < sizeof bad; i++) {
        BYTE r[2] = { bad[i], 0xA0 }; char w[32]; wsprintfA(w, "ctap=0x%02x", bad[i]);
        gcc_expect(w, 0, r, 2, (ULONG)HR_INVALID_PARAM, 0);
    }
}
TEST(ctaprpc_getcbor_nonzero_rpc_command_rejected) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* The RPC-level "command" must be 0; the make-credential encoder is normally called with 5. */
    static const unsigned cmds[] = { 1, 2, 3, 5, 6, 0x80, 0xFFFF, 0xFFFFFFFFu };
    BYTE r[] = { 0x01, 0xA0 };
    for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
        char w[32]; wsprintfA(w, "command=%u", cmds[i]);
        gcc_expect(w, cmds[i], r, sizeof r, (ULONG)HR_INVALID_PARAM, 0);
    }
}
TEST(ctaprpc_getcbor_flags_and_timeout_ignored) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE r[] = { 0x02, 0xA0 }, txid[16] = { 1 };
    static const unsigned long long fl[] = { 0, 0x40000, 0xFFFFFFFFull };
    for (size_t i = 0; i < 3; i++) {
        cbuf c; rpc_request(&c, 0, fl[i], i * 1000, txid, 16, r, sizeof r);
        BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
        CHECKF(hr == 0 && cmd == 2, "flags=%llx hr=%lx cmd=%u", fl[i], (unsigned long)hr, cmd);
    }
}
TEST(ctaprpc_getcbor_request_missing) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* command == 0 with no "request" is a decode error (0x301 -> ERROR_INVALID_DATA). */
    gcc_expect("no request", 0, NULL, 0, (ULONG)HR_INVALID_DATA, 0);
}
TEST(ctaprpc_getcbor_request_empty_bstr) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE dummy = 0;
    gcc_expect("empty request", 0, &dummy, 0, (ULONG)HR_INVALID_DATA, 0);
}
TEST(ctaprpc_getcbor_transactionid_wrong_length) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* transactionId must be exactly 16 bytes. */
    static const size_t lens[] = { 0, 1, 8, 15, 17, 32 };
    BYTE tx[32]; memset(tx, 7, sizeof tx); BYTE r[] = { 0x01, 0xA0 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        cbuf c; rpc_request(&c, 0, 0, 0, tx, lens[i], r, sizeof r);
        BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
        CHECKF(hr == (ULONG)HR_INVALID_DATA, "len=%zu hr=0x%08lx", lens[i], (unsigned long)hr);
        CHECK(cmd == 0);
    }
}
TEST(ctaprpc_getcbor_transactionid_missing) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE r[] = { 0x01, 0xA0 };
    rpc_request(&c, 0, 0, 0, NULL, 0, r, sizeof r);
    BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
    CHECK_CBOR_ERR((LONG)hr); CHECK(cmd == 0);
}
TEST(ctaprpc_getcbor_unknown_keys_ignored) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE tx[16] = { 9 }; BYTE r[] = { 0x01, 0xA0 };
    c.n = 0; cb_map(&c, 7);
    cb_tstr(&c, "zzz-extra"); cb_uint(&c, 42);
    cb_tstr(&c, "command"); cb_uint(&c, 0);
    cb_tstr(&c, "flags"); cb_uint(&c, 0);
    cb_tstr(&c, "timeout"); cb_uint(&c, 0);
    cb_tstr(&c, "transactionId"); cb_bstr(&c, tx, 16);
    cb_tstr(&c, "another"); cb_arr(&c, 1); cb_tstr(&c, "x");
    cb_tstr(&c, "request"); cb_bstr(&c, r, sizeof r);
    BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
    CHECKF(hr == 0 && cmd == 1, "hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
}
TEST(ctaprpc_getcbor_key_order_irrelevant) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE tx[16] = { 9 }; BYTE r[] = { 0x02, 0xA0 };
    c.n = 0; cb_map(&c, 5);
    cb_tstr(&c, "request"); cb_bstr(&c, r, sizeof r);
    cb_tstr(&c, "transactionId"); cb_bstr(&c, tx, 16);
    cb_tstr(&c, "timeout"); cb_uint(&c, 0);
    cb_tstr(&c, "flags"); cb_uint(&c, 0);
    cb_tstr(&c, "command"); cb_uint(&c, 0);
    BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
    CHECKF(hr == 0 && cmd == 2, "hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
}
TEST(ctaprpc_getcbor_required_keys_missing) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* "command", "flags", "timeout" and "transactionId" are required; drop each in turn. */
    static const char *keys[] = { "command", "flags", "timeout", "transactionId" };
    BYTE tx[16] = { 3 }; BYTE r[] = { 0x01, 0xA0 };
    for (int drop = 0; drop < 4; drop++) {
        cbuf c; c.n = 0; cb_map(&c, 4);
        for (int k = 0; k < 4; k++) {
            if (k == drop) continue;
            cb_tstr(&c, keys[k]);
            if (k == 3) cb_bstr(&c, tx, 16); else cb_uint(&c, 0);
        }
        cb_tstr(&c, "request"); cb_bstr(&c, r, sizeof r);
        BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
        CHECKF(FAILED((LONG)hr) && is_cbor_layer_error((LONG)hr), "drop %s: hr=0x%08lx", keys[drop], (unsigned long)hr);
        CHECKF(cmd == 0, "drop %s: cmd=%u", keys[drop], cmd);
    }
}
TEST(ctaprpc_getcbor_zero_length) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE b[4] = { 0xA0 }; BYTE cmd = 0xEE;
    ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(0, b, &cmd);
    CHECKF(hr == (ULONG)HR_CBOR_EMPTY, "hr=0x%08lx", (unsigned long)hr);
    CHECK(cmd == 0);
}
TEST(ctaprpc_getcbor_null_buffer) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    BYTE cmd = 0xEE;
    ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(16, NULL, &cmd);
    CHECKF(hr == (ULONG)HR_CBOR_EMPTY, "hr=0x%08lx", (unsigned long)hr);
    CHECK(cmd == 0);
    cmd = 0xEE;
    hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(0, NULL, &cmd);
    CHECKF(hr == (ULONG)HR_CBOR_EMPTY, "hr=0x%08lx", (unsigned long)hr);
    CHECK(cmd == 0);
}
TEST(ctaprpc_getcbor_size_limit_boundary) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* The CBOR layer accepts 1..0x2000 bytes and rejects 0x2001 and above before parsing. */
    static BYTE req[0x2000]; memset(req, 0, sizeof req); req[0] = 0x01;
    cbuf *c = (cbuf *)calloc(1, sizeof(cbuf) + 0x4000);
    BYTE tx[16] = { 1 };
    /* Construct with a bstr sized so the whole map is exactly 0x2000 bytes. */
    size_t reqlen = 0x1F00;
    for (;;) {
        rpc_request(c, 0, 0, 0, tx, 16, req, reqlen);
        if (c->n == 0x2000 || reqlen > 0x2000) break;
        reqlen += (c->n < 0x2000) ? (0x2000 - c->n) : 0;
        if (c->n > 0x2000) break;
    }
    /* c is a 16 KiB cbuf, large enough. */
    if (c->n != 0x2000) { t_note("could not build exact 0x2000 map, n=%zu", c->n); free(c); return; }
    BYTE cmd = 0xEE;
    ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(0x2000, c->b, &cmd);
    CHECKF(hr == 0 && cmd == 1, "0x2000: hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
    cmd = 0xEE;
    BYTE *over = (BYTE *)calloc(1, 0x2001); memcpy(over, c->b, 0x2000);
    hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(0x2001, over, &cmd);
    CHECKF(hr == (ULONG)HR_CBOR_EMPTY, "0x2001: hr=0x%08lx", (unsigned long)hr);
    CHECK(cmd == 0);
    cmd = 0xEE;
    hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)(0x10000, over, &cmd);
    CHECKF(hr == (ULONG)HR_CBOR_EMPTY, "0x10000: hr=0x%08lx", (unsigned long)hr);
    free(over); free(c);
}
TEST(ctaprpc_getcbor_garbage_inputs) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    static const BYTE g1[] = { 0xFF }, g2[] = { 0x00 }, g3[] = { 0x01, 0x02, 0x03 }, g4[] = { 0xA0 },
        g5[] = { 0x80 }, g6[] = { 0x60 }, g7[] = { 0xA1, 0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd' }, g8[] = { 0x5F, 0xFF },
        g9[] = { 0xBF, 0xFF }, g10[] = { 0xA5 };
    static const struct { const BYTE *p; size_t n; const char *w; } t[] = {
        { g1, 1, "break byte" }, { g2, 1, "uint 0" }, { g3, 3, "three uints" }, { g4, 1, "empty map" },
        { g5, 1, "empty array" }, { g6, 1, "empty text" }, { g7, sizeof g7, "truncated pair" },
        { g8, 2, "indefinite bstr" }, { g9, 2, "indefinite empty map" }, { g10, 1, "map(5) truncated" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        BYTE cmd = 0xEE;
        ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)((ULONG)t[i].n, t[i].p, &cmd);
        CHECKF(FAILED((LONG)hr), "%s: hr=0x%08lx", t[i].w, (unsigned long)hr);
        CHECKF(cmd == 0, "%s: cmd=%u", t[i].w, cmd);
        if ((LONG)hr < 0) t_note("getcbor garbage '%s' -> 0x%08lx", t[i].w, (unsigned long)hr);
    }
}
TEST(ctaprpc_getcbor_every_truncation_fails) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE tx[16]; memset(tx, 0x33, 16); BYTE r[] = { 0x01, 0xA0 };
    rpc_request(&c, 0, 0x40000, 5000, tx, 16, r, sizeof r);   /* "request" is the last pair */
    BYTE cmd = 0;
    CHECK(gcc_call(&c, c.n, &cmd) == 0 && cmd == 1);
    for (size_t n = 1; n < c.n; n++) {
        BYTE *copy = (BYTE *)malloc(n); memcpy(copy, c.b, n);   /* exact-size heap block */
        cmd = 0xEE;
        ULONG hr = (ULONG)UN(WebAuthNCtapRpcGetCborCommand)((ULONG)n, copy, &cmd);
        CHECKF(FAILED((LONG)hr), "prefix %zu: hr=0x%08lx", n, (unsigned long)hr);
        CHECKF(cmd == 0, "prefix %zu: cmd=%u", n, cmd);
        free(copy);
    }
}
TEST(ctaprpc_getcbor_trailing_bytes) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* Behaviour with bytes after the top-level map is not asserted: record it. */
    cbuf c; BYTE tx[16] = { 1 }; BYTE r[] = { 0x01, 0xA0 };
    rpc_request(&c, 0, 0, 0, tx, 16, r, sizeof r);
    cb_byte(&c, 0x00); cb_byte(&c, 0x00);
    BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
    t_note("getcbor with 2 trailing bytes: hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
}
TEST(ctaprpc_getcbor_request_bstr_wrong_type) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    /* "request" encoded as text instead of bstr must not be accepted as a CTAP payload. */
    cbuf c; BYTE tx[16] = { 1 };
    c.n = 0; cb_map(&c, 5);
    cb_tstr(&c, "command"); cb_uint(&c, 0);
    cb_tstr(&c, "flags"); cb_uint(&c, 0);
    cb_tstr(&c, "timeout"); cb_uint(&c, 0);
    cb_tstr(&c, "transactionId"); cb_bstr(&c, tx, 16);
    cb_tstr(&c, "request"); cb_tstr(&c, "\x01\x02");
    BYTE cmd = 0xEE; ULONG hr = gcc_call(&c, c.n, &cmd);
    CHECKF(hr != 0 || cmd == 0, "text request accepted: hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
    t_note("getcbor with text 'request': hr=0x%08lx cmd=%u", (unsigned long)hr, cmd);
}
TEST(ctaprpc_getcbor_repeat_stable_no_leak) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE tx[16] = { 1 }; BYTE r[] = { 0x02, 0xA0 };
    rpc_request(&c, 0, 0x40000, 0, tx, 16, r, sizeof r);
    BYTE cmd = 0; (void)gcc_call(&c, c.n, &cmd);    /* warm-up */
    SIZE_T before = crc_private_bytes();
    int bad = 0;
    for (int i = 0; i < 20000; i++) { cmd = 0xEE; if (gcc_call(&c, c.n, &cmd) != 0 || cmd != 2) bad++; }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unstable results", bad);
    if (before && after) {
        CHECKF(after < before + 3 * 1024 * 1024, "private bytes grew %lld", (long long)after - (long long)before);
        t_note("getcbor x20000 private bytes delta=%lld", (long long)after - (long long)before);
    }
}
TEST(ctaprpc_getcbor_failure_path_no_leak) {
    REQUIRE(UN(WebAuthNCtapRpcGetCborCommand));
    cbuf c; BYTE tx[16] = { 1 }; BYTE r[] = { 0x09, 0xA0 };
    rpc_request(&c, 0, 0, 0, tx, 16, r, sizeof r);
    BYTE cmd = 0; (void)gcc_call(&c, c.n, &cmd);
    SIZE_T before = crc_private_bytes();
    int bad = 0;
    for (int i = 0; i < 20000; i++) { cmd = 0xEE; if (gcc_call(&c, c.n, &cmd) != (ULONG)HR_INVALID_PARAM || cmd != 0) bad++; }
    SIZE_T after = crc_private_bytes();
    CHECKF(bad == 0, "%d unstable results", bad);
    if (before && after) CHECKF(after < before + 3 * 1024 * 1024, "private bytes grew %lld", (long long)after - (long long)before);
}

TEST(ctaprpc_free_helper_alias_addresses) {
    /* In the reference build several free helpers are one shared LocalFree wrapper; record only. */
    REQUIRE(UN(WebAuthNFreeAssertion));
    static const char *names[] = { "WebAuthNCtapFreeSelectedDeviceInformation", "WebAuthNFreeDecodedAccountInformation",
        "WebAuthNFreeEncodedAccountInformation", "WebAuthNFreeUserEntityList" };
    FARPROC base = t_proc_in("webauthn.dll", "WebAuthNFreeAssertion");
    for (size_t i = 0; i < 4; i++) {
        FARPROC p = t_proc_in("webauthn.dll", names[i]);
        t_note("%s %s WebAuthNFreeAssertion", names[i], p == base ? "==" : "!=");
    }
    CHECK(base != NULL);
}
