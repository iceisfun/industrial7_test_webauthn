#include "cd.h"
/* WebAuthNCtapVerifyGetAssertion(rpId, clientData, assertion, cbCredAuthData, pbCredAuthData)
 *
 * Crypto-only: it never touches a device. Reference behaviour relied on (Windows 10 decompilation):
 *   1. SHA-256 over clientData->pbClientDataJSON[0..cbClientDataJSON) (the hash algorithm string is not consulted).
 *   2. Unpack pbCredAuthData: needs >= 37 bytes (else ERROR_INVALID_DATA -> 0x8007000D); if the AT flag (0x40) is set the
 *      attested credential data must be well formed (aaguid, big-endian credId length, credId, one CBOR COSE_Key);
 *      after that bytes remain only if the ED flag (0x80) is set, else 0x8007000D.
 *   3. Unpack the assertion authenticator data with the same rules (normally exactly 37 bytes).
 *   4. rpId NULL or "": no rpId check. Otherwise SHA-256(UTF-8(rpId)) must equal the first 32 bytes of the ASSERTION
 *      authenticator data, else 0x80090002; an rpId that is not valid UTF-16 -> 0x80070057. The credential authenticator
 *      data's rpIdHash is never compared.
 *   5. COSE_Key from the credential data (the alg is key 3) is imported; failures: unknown alg 0x80070032, unusable
 *      coordinates 0x80090015, malformed 0x8007000D.
 *   6. ECDSA signature (ASN.1 DER SEQUENCE{r,s}) over SHA-hash(authData || SHA-256(clientDataJSON)) is verified.
 *      Bad signature: STATUS_INVALID_SIGNATURE (0xC000A000) is returned as is. Success: 0.
 * The UP / UV / counter fields of the assertion are not checked by this function.
 */

#define JSON "{\"type\":\"webauthn.get\",\"challenge\":\"3q2-7w\",\"origin\":\"https://example.com\"}"
#define SETUP(v, k, rp, flags, ctr) \
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY(); \
    cd_key k; if (!cd_key_gen(&k)) { t_skip("P-256 key generation unavailable"); return; } \
    cd_vec v; cd_vec_init(&v, &k, rp, flags, ctr, JSON)
#define DONE(k) cd_key_free(&k)

static void der_pos(const BYTE *sig, ULONG *ro, ULONG *rl, ULONG *so, ULONG *sl) {   /* value positions without sign pad */
    ULONG o = 2; ULONG l = sig[o + 1]; ULONG s = o + 2; if (sig[s] == 0 && l > 1) { s++; l--; }
    *ro = s; *rl = l;
    o = o + 2 + sig[o + 1]; l = sig[o + 1]; s = o + 2; if (sig[s] == 0 && l > 1) { s++; l--; }
    *so = s; *sl = l;
}

/* ---- positives ---- */
TEST(ctapdev_vga_valid_baseline) {
    SETUP(v, k, L"example.com", 0x05, 1);
    CDHR r = cd_vec_call(&v);
    EXPECT_EQ(r, 0);
    DONE(k);
}
TEST(ctapdev_vga_valid_without_rpid_check) {
    SETUP(v, k, L"example.com", 0x01, 1);
    v.rp = NULL; EXPECT_EQ(cd_vec_call(&v), 0);
    v.rp = L"";  EXPECT_EQ(cd_vec_call(&v), 0);
    DONE(k);
}
TEST(ctapdev_vga_valid_many_keys) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    int bad = 0;
    for (int i = 0; i < 40; i++) {
        cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
        cd_vec v; cd_vec_init(&v, &k, L"example.com", (BYTE)(i & 0x1F), (ULONG)i * 77777, JSON);
        CDHR r = cd_vec_call(&v);
        if (r != 0) { bad++; t_note("key %d r=0x%08lx", i, (unsigned long)r); }
        cd_key_free(&k);
    }
    CHECK(bad == 0);
}
TEST(ctapdev_vga_valid_signature_repeats) {
    SETUP(v, k, L"example.com", 0x05, 9);
    for (int i = 0; i < 100; i++) { CDHR r = cd_vec_call(&v); if (r != 0) { CHECKF(0, "iteration %d r=0x%lx", i, (unsigned long)r); break; } }
    DONE(k);
}
TEST(ctapdev_vga_inputs_not_modified) {
    SETUP(v, k, L"example.com", 0x05, 9);
    cd_vec before = v; cd_vec_call(&v);
    CHECK(!memcmp(&before, &v, sizeof v));
    DONE(k);
}
TEST(ctapdev_vga_flags_not_enforced) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    static const BYTE fl[] = { 0x00, 0x01, 0x04, 0x05, 0x08, 0x10, 0x18, 0x19, 0x3F, 0x3E };
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    for (size_t i = 0; i < sizeof fl; i++) {
        cd_vec v; cd_vec_init(&v, &k, L"example.com", fl[i], 3, JSON);
        CDHR r = cd_vec_call(&v);
        CHECKF(r == 0, "flags=0x%02x r=0x%lx", fl[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_up_uv_clear_still_verifies) {
    SETUP(v, k, L"example.com", 0x00, 0);
    EXPECT_EQ(cd_vec_call(&v), 0);   /* neither user presence nor verification is required by the verifier */
    DONE(k);
}
TEST(ctapdev_vga_counter_values) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    static const ULONG ctr[] = { 0, 1, 255, 256, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF };
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    for (size_t i = 0; i < sizeof ctr / sizeof ctr[0]; i++) {
        cd_vec v; cd_vec_init(&v, &k, L"example.com", 0x01, ctr[i], JSON);
        CHECKF(cd_vec_call(&v) == 0, "counter=0x%lx", (unsigned long)ctr[i]);
    }
    DONE(k);
}
TEST(ctapdev_vga_hash_alg_string_ignored) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const PCWSTR algs[] = { NULL, L"", L"SHA-256", L"SHA-512", L"MD5", L"not-a-hash" };
    for (size_t i = 0; i < sizeof algs / sizeof algs[0]; i++) {
        CD_CLIENT_DATA cd = { 1, v.cjLen, v.cj, algs[i] };
        CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
        CDHR r = cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca);
        CHECKF(r == 0, "alg #%zu r=0x%lx", i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_struct_versions_ignored) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const DWORD vers[] = { 0, 1, 2, 99, 0xFFFFFFFF };
    for (size_t i = 0; i < sizeof vers / sizeof vers[0]; i++) {
        CD_CLIENT_DATA cd = { vers[i], v.cjLen, v.cj, L"SHA-256" };
        CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = vers[i]; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
        CDHR r = cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca);
        CHECKF(r == 0, "version 0x%lx r=0x%lx", (unsigned long)vers[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_assertion_credential_fields_ignored) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE id[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    CD_CLIENT_DATA cd = { 1, v.cjLen, v.cj, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
    as.credVersion = 1; as.cbCredId = 8; as.pbCredId = id; as.pwszCredType = L"public-key"; as.cbUserId = 8; as.pbUserId = id;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca), 0);
    as.cbCredId = 0; as.pbCredId = NULL; as.pwszCredType = NULL; as.cbUserId = 0; as.pbUserId = NULL;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca), 0);
    DONE(k);
}
TEST(ctapdev_vga_credential_rpidhash_not_compared) {
    SETUP(v, k, L"example.com", 0x05, 1);
    memset(v.ca, 0xEE, 32);                     /* wrong rpIdHash inside the credential authenticator data */
    EXPECT_EQ(cd_vec_call(&v), 0);
    DONE(k);
}
TEST(ctapdev_vga_credential_flags_and_counter_irrelevant) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const BYTE fl[] = { 0x41, 0x45, 0x65 };   /* AT always present; UP/UV/BS vary */
    for (size_t i = 0; i < sizeof fl; i++) {
        v.ca[32] = fl[i]; v.ca[33] = 0xFF; v.ca[34] = 0xFF; v.ca[35] = 0xFF; v.ca[36] = 0xFF;
        CHECKF(cd_vec_call(&v) == 0, "cred flags 0x%02x", fl[i]);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_id_length_table) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    static const ULONG lens[] = { 0, 1, 16, 32, 64, 127, 128, 255, 256, 300 };
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        cd_vec v; cd_vec_init(&v, &k, L"example.com", 0x05, 1, JSON);
        BYTE cose[77]; memcpy(cose, v.ca + v.caKeyOff, 77);
        ULONG n = 32 + 1 + 4 + 16; v.ca[n++] = (BYTE)(lens[i] >> 8); v.ca[n++] = (BYTE)lens[i];
        for (ULONG j = 0; j < lens[i]; j++) v.ca[n++] = (BYTE)j;
        memcpy(v.ca + n, cose, 77); v.caLen = n + 77;
        CHECKF(cd_vec_call(&v) == 0, "credId len %lu", (unsigned long)lens[i]);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_extensions_with_ed_flag) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const BYTE ext[] = { 0xA1, 0x6B, 'h','m','a','c','-','s','e','c','r','e','t', 0xF5 };
    v.ca[32] = 0xC1; memcpy(v.ca + v.caLen, ext, sizeof ext); v.caLen += sizeof ext;
    CDHR r = cd_vec_call(&v);
    EXPECT_EQ(r, 0);
    DONE(k);
}
TEST(ctapdev_vga_assertion_extensions_with_ed_flag) {
    SETUP(v, k, L"example.com", 0x81, 1);   /* UP | ED */
    static const BYTE ext[] = { 0xA1, 0x61, 'x', 0xF5 };
    memcpy(v.aa + 37, ext, sizeof ext); v.aaLen = 37 + sizeof ext; cd_vec_resign(&v, &k);
    EXPECT_EQ(cd_vec_call(&v), 0);          /* the signature covers the extension bytes */
    DONE(k);
}

/* ---- authenticator data shape errors ---- */
TEST(ctapdev_vga_assertion_data_too_short) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const ULONG lens[] = { 0, 1, 31, 32, 33, 36 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        cd_vec w = v; w.aaLen = lens[i];
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_HR_INVALID_DATA, "len=%lu r=0x%lx", (unsigned long)lens[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_assertion_data_null_zero_length) {
    SETUP(v, k, L"example.com", 0x05, 1);
    CD_CLIENT_DATA cd = { 1, v.cjLen, v.cj, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca), CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_assertion_trailing_bytes_without_ed_flag) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const ULONG extra[] = { 1, 2, 16 };
    for (size_t i = 0; i < sizeof extra / sizeof extra[0]; i++) {
        cd_vec w = v; for (ULONG j = 0; j < extra[i]; j++) w.aa[37 + j] = 0xA0; w.aaLen = 37 + extra[i]; cd_vec_resign(&w, &k);
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_HR_INVALID_DATA, "extra=%lu r=0x%lx", (unsigned long)extra[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_assertion_with_attested_flag_needs_credential_data) {
    SETUP(v, k, L"example.com", 0x45, 1);   /* AT set but only 37 bytes */
    EXPECT_EQ(cd_vec_call(&v), CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_credential_data_too_short) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const ULONG lens[] = { 0, 1, 36 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        cd_vec w = v; w.caLen = lens[i];
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_HR_INVALID_DATA, "len=%lu r=0x%lx", (unsigned long)lens[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_data_null_zero_length) {
    SETUP(v, k, L"example.com", 0x05, 1);
    CD_CLIENT_DATA cd = { 1, v.cjLen, v.cj, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, 0, NULL), CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_credential_without_attested_data_has_no_key) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.caLen = 37; v.ca[32] = 0x01;          /* header only, AT clear: nothing to import */
    CDHR r = cd_vec_call(&v);
    CHECK(CD_FAILED(r)); EXPECT_EQ(r, CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_credential_attested_header_truncated) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const ULONG lens[] = { 37, 38, 45, 53, 54 };    /* AT set, fewer than 0x12 bytes after the 37-byte header */
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        cd_vec w = v; w.caLen = lens[i];
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_HR_INVALID_DATA, "len=%lu r=0x%lx", (unsigned long)lens[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_no_key_bytes) {
    SETUP(v, k, L"example.com", 0x05, 1);
    cd_vec w = v; w.caLen = 32 + 1 + 4 + 16 + 2 + 16;      /* complete header and credId, no COSE key */
    EXPECT_EQ(cd_vec_call(&w), CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_credential_id_length_overruns) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const USHORT bad[] = { 0xFFFF, 0x1000, 0x0200, 0x00B0 };   /* larger than the bytes that follow */
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        cd_vec w = v; w.ca[32 + 1 + 4 + 16] = (BYTE)(bad[i] >> 8); w.ca[32 + 1 + 4 + 16 + 1] = (BYTE)bad[i];
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_HR_INVALID_DATA, "credIdLen=0x%x r=0x%lx", bad[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_key_not_a_map) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const BYTE first[] = { 0x00, 0x01, 0x18, 0x40, 0x60, 0xF5, 0xFF };
    for (size_t i = 0; i < sizeof first; i++) {
        cd_vec w = v; w.ca[w.caKeyOff] = first[i]; w.caLen = w.caKeyOff + 3;
        CDHR r = cd_vec_call(&w);
        CHECKF(CD_FAILED(r), "first byte 0x%02x r=0x%lx", first[i], (unsigned long)r);
        t_note("cred key first byte 0x%02x -> 0x%08lx", first[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_key_trailing_bytes_without_ed) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.ca[v.caLen++] = 0x00;
    EXPECT_EQ(cd_vec_call(&v), CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_credential_key_truncated) {
    SETUP(v, k, L"example.com", 0x05, 1);
    for (ULONG cut = 1; cut <= 40; cut += 13) {
        cd_vec w = v; w.caLen -= cut;
        CDHR r = cd_vec_call(&w);
        CHECKF(CD_FAILED(r), "cut=%lu r=0x%lx", (unsigned long)cut, (unsigned long)r);
        t_note("cred key truncated by %lu -> 0x%08lx", (unsigned long)cut, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_credential_key_empty_map) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.ca[v.caKeyOff] = 0xA0; v.caLen = v.caKeyOff + 1;
    EXPECT_EQ(cd_vec_call(&v), CD_HR_INVALID_DATA);
    DONE(k);
}

/* ---- COSE key content ---- */
static CDHR with_key(const cd_key *k, long alg, const BYTE *x, ULONG cx, const BYTE *y, ULONG cy, PCWSTR rp) {
    cd_vec v; cd_vec_init(&v, k, rp, 0x05, 1, JSON);
    v.caLen = v.caKeyOff + cd_cose_ec(v.ca + v.caKeyOff, alg, x, cx, y, cy);
    return cd_vec_call(&v);
}
TEST(ctapdev_vga_cose_alg_es256_explicit) {
    SETUP(v, k, L"example.com", 0x05, 1);
    EXPECT_EQ(with_key(&k, -7, k.x, 32, k.y, 32, L"example.com"), 0);
    DONE(k);
}
TEST(ctapdev_vga_cose_alg_unknown) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const long algs[] = { 9999, 1000, 500 };
    for (size_t i = 0; i < sizeof algs / sizeof algs[0]; i++) {
        CDHR r = with_key(&k, algs[i], k.x, 32, k.y, 32, L"example.com");
        CHECKF(r == CD_HR_NOT_SUPPORTED, "alg=%ld r=0x%lx", algs[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_cose_coordinate_size_mismatch) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE big[64]; memset(big, 0x42, sizeof big);
    static const ULONG sizes[] = { 31, 33, 16, 48, 64 };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        BYTE x[64], y[64]; memcpy(x, k.x, 32); memcpy(y, k.y, 32);
        CDHR rx = with_key(&k, -7, big, sizes[i], k.y, 32, L"example.com");
        CDHR ry = with_key(&k, -7, k.x, 32, big, sizes[i], L"example.com");
        CDHR rb = with_key(&k, -7, big, sizes[i], big, sizes[i], L"example.com");
        CHECKF(rx == CD_NTE_BAD_KEY_SIZE, "x size %lu r=0x%lx", (unsigned long)sizes[i], (unsigned long)rx);
        CHECKF(ry == CD_NTE_BAD_KEY_SIZE, "y size %lu r=0x%lx", (unsigned long)sizes[i], (unsigned long)ry);
        CHECKF(rb == CD_NTE_BAD_KEY_SIZE, "xy size %lu r=0x%lx", (unsigned long)sizes[i], (unsigned long)rb);
    }
    DONE(k);
}
TEST(ctapdev_vga_cose_point_not_on_curve) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE x[32], y[32]; memcpy(x, k.x, 32); memcpy(y, k.y, 32); y[31] ^= 1;
    CDHR r = with_key(&k, -7, x, 32, y, 32, L"example.com");
    CHECK(CD_FAILED(r));
    t_note("COSE point not on curve -> 0x%08lx", (unsigned long)r);
    DONE(k);
}
TEST(ctapdev_vga_cose_missing_coordinates) {
    SETUP(v, k, L"example.com", 0x05, 1);
    /* {1:2, 3:-7, -1:1} without -2/-3 */
    static const BYTE nokeys[] = { 0xA3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01 };
    cd_vec w = v; memcpy(w.ca + w.caKeyOff, nokeys, sizeof nokeys); w.caLen = w.caKeyOff + sizeof nokeys;
    CDHR r = cd_vec_call(&w);
    CHECK(CD_FAILED(r)); EXPECT_EQ(r, CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_cose_wrong_public_key) {
    SETUP(v, k, L"example.com", 0x05, 1);
    cd_key other; if (!cd_key_gen(&other)) { t_skip("keygen"); DONE(k); return; }
    CDHR r = with_key(&k, -7, other.x, 32, other.y, 32, L"example.com");   /* signature made with k, key from other */
    EXPECT_EQ(r, CD_STATUS_INVALID_SIGNATURE);
    cd_key_free(&other); DONE(k);
}
TEST(ctapdev_vga_cose_swapped_coordinates) {
    SETUP(v, k, L"example.com", 0x05, 1);
    CDHR r = with_key(&k, -7, k.y, 32, k.x, 32, L"example.com");
    CHECK(CD_FAILED(r));
    t_note("COSE x/y swapped -> 0x%08lx", (unsigned long)r);
    DONE(k);
}
TEST(ctapdev_vga_cose_extra_and_reordered_entries_note) {
    SETUP(v, k, L"example.com", 0x05, 1);
    /* reversed order: {-3:y, -2:x, -1:1, 3:-7, 1:2} */
    BYTE c[100]; ULONG n = 0;
    c[n++] = 0xA5; c[n++] = 0x22; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.y, 32); n += 32;
    c[n++] = 0x21; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.x, 32); n += 32;
    c[n++] = 0x20; c[n++] = 0x01; c[n++] = 0x03; c[n++] = 0x26; c[n++] = 0x01; c[n++] = 0x02;
    cd_vec w = v; memcpy(w.ca + w.caKeyOff, c, n); w.caLen = w.caKeyOff + n;
    t_note("COSE key entries in reverse order -> 0x%08lx", (unsigned long)cd_vec_call(&w));
    /* kty/crv omitted: {3:-7, -2:x, -3:y} */
    n = 0; c[n++] = 0xA3; c[n++] = 0x03; c[n++] = 0x26; c[n++] = 0x21; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.x, 32); n += 32;
    c[n++] = 0x22; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.y, 32); n += 32;
    w = v; memcpy(w.ca + w.caKeyOff, c, n); w.caLen = w.caKeyOff + n;
    t_note("COSE key without kty/crv -> 0x%08lx", (unsigned long)cd_vec_call(&w));
    DONE(k);
}
TEST(ctapdev_vga_cose_alg_missing_note) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE c[100]; ULONG n = 0;
    c[n++] = 0xA4; c[n++] = 0x01; c[n++] = 0x02; c[n++] = 0x20; c[n++] = 0x01;
    c[n++] = 0x21; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.x, 32); n += 32;
    c[n++] = 0x22; c[n++] = 0x58; c[n++] = 0x20; memcpy(c + n, k.y, 32); n += 32;
    cd_vec w = v; memcpy(w.ca + w.caKeyOff, c, n); w.caLen = w.caKeyOff + n;
    CDHR r = cd_vec_call(&w);
    CHECK(CD_FAILED(r));
    t_note("COSE key without alg -> 0x%08lx", (unsigned long)r);
    DONE(k);
}

/* ---- rpId ---- */
TEST(ctapdev_vga_rpid_mismatch_table) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const PCWSTR bad[] = { L"example.org", L"EXAMPLE.COM", L"Example.com", L"example.com.", L"example.co", L"xexample.com", L" example.com",
                                  L"example.com ", L"sub.example.com", L"a", L"https://example.com", L"example.com:443" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        v.rp = bad[i];
        CDHR r = cd_vec_call(&v);
        CHECKF(r == CD_NTE_BAD_HASH, "rpId %ls r=0x%lx", bad[i], (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_rpid_unicode_matches_utf8_hash) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    static const PCWSTR rps[] = { L"bücher.example", L"中文.example", L"\xD83D\xDD11.example", L"café.example" };
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    for (size_t i = 0; i < sizeof rps / sizeof rps[0]; i++) {
        cd_vec v; cd_vec_init(&v, &k, rps[i], 0x05, 1, JSON);
        CDHR r = cd_vec_call(&v);
        CHECKF(r == 0, "rp #%zu r=0x%lx", i, (unsigned long)r);
        v.rp = L"example.com";
        r = cd_vec_call(&v);
        CHECKF(r == CD_NTE_BAD_HASH, "rp #%zu vs example.com r=0x%lx", i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_rpid_lone_surrogate_invalid_arg) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const WCHAR lone[][4] = { { 0xD800, 0 }, { 0xDC00, 0 }, { L'a', 0xD800, L'b', 0 }, { 0xDC00, 0xD800, 0 } };
    for (size_t i = 0; i < 4; i++) {
        v.rp = lone[i];
        CDHR r = cd_vec_call(&v);
        CHECKF(r == CD_HR_INVALID_ARG, "lone surrogate #%zu r=0x%lx", i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_rpid_long_names) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    WCHAR rp[64]; for (int i = 0; i < 63; i++) rp[i] = L'a' + (i % 26); rp[63] = 0;
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    cd_vec v; cd_vec_init(&v, &k, rp, 0x05, 1, JSON);
    EXPECT_EQ(cd_vec_call(&v), 0);
    DONE(k);
}
TEST(ctapdev_vga_rpid_check_uses_assertion_data_flip_each_byte) {
    SETUP(v, k, L"example.com", 0x05, 1);
    for (int i = 0; i < 32; i++) {
        cd_vec w = v; w.aa[i] ^= 1; cd_vec_resign(&w, &k);      /* re-signed: only the rpIdHash differs */
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_NTE_BAD_HASH, "byte %d r=0x%lx", i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_rpid_mismatch_precedes_signature_check) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.rp = L"other.example"; v.sig[v.sigLen - 1] ^= 1;       /* both wrong: rpId is reported */
    EXPECT_EQ(cd_vec_call(&v), CD_NTE_BAD_HASH);
    DONE(k);
}
TEST(ctapdev_vga_data_errors_precede_rpid_check) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.rp = L"other.example"; v.aaLen = 10;
    EXPECT_EQ(cd_vec_call(&v), CD_HR_INVALID_DATA);
    DONE(k);
}

/* ---- tampering ---- */
TEST(ctapdev_vga_signature_bit_flip_every_value_byte) {
    SETUP(v, k, L"example.com", 0x05, 1);
    ULONG ro, rl, so, sl; der_pos(v.sig, &ro, &rl, &so, &sl);
    int n = 0;
    for (ULONG i = 0; i < rl + sl; i++) {
        ULONG off = i < rl ? ro + i : so + (i - rl);
        cd_vec w = v; w.sig[off] ^= 1;
        CDHR r = cd_vec_call(&w); n++;
        CHECKF(r == CD_STATUS_INVALID_SIGNATURE, "sig byte %lu r=0x%lx", (unsigned long)off, (unsigned long)r);
    }
    CHECK(n >= 60);
    DONE(k);
}
TEST(ctapdev_vga_signature_high_bit_flips) {
    SETUP(v, k, L"example.com", 0x05, 1);
    ULONG ro, rl, so, sl; der_pos(v.sig, &ro, &rl, &so, &sl);
    cd_vec w = v; w.sig[ro + rl - 1] ^= 0x80; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    w = v; w.sig[so + sl - 1] ^= 0x80; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    w = v; w.sig[ro + rl - 1] ^= 0xFF; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    DONE(k);
}
TEST(ctapdev_vga_assertion_data_bit_flip_every_byte) {
    SETUP(v, k, NULL, 0x05, 1);     /* no rpId check, so the signature alone decides */
    for (int i = 0; i < 37; i++) {
        cd_vec w = v; w.aa[i] ^= 1;
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_STATUS_INVALID_SIGNATURE, "authData byte %d r=0x%lx", i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_client_data_bit_flip_every_byte) {
    SETUP(v, k, L"example.com", 0x05, 1);
    for (ULONG i = 0; i < v.cjLen; i++) {
        cd_vec w = v; w.cj[i] ^= 1;
        CDHR r = cd_vec_call(&w);
        CHECKF(r == CD_STATUS_INVALID_SIGNATURE, "clientData byte %lu r=0x%lx", (unsigned long)i, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_client_data_length_changes) {
    SETUP(v, k, L"example.com", 0x05, 1);
    cd_vec w = v; w.cjLen -= 1; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    w = v; w.cj[w.cjLen] = ' '; w.cjLen += 1; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);   /* trailing space matters */
    w = v; w.cjLen = 1; EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    DONE(k);
}
TEST(ctapdev_vga_client_data_is_hashed_as_raw_bytes) {
    /* Same JSON text, different bytes (re-encoded whitespace) must not verify against the original signature. */
    SETUP(v, k, L"example.com", 0x05, 1);
    static const char alt[] = "{\"type\": \"webauthn.get\",\"challenge\":\"3q2-7w\",\"origin\":\"https://example.com\"}";
    cd_vec w = v; memcpy(w.cj, alt, sizeof alt - 1); w.cjLen = sizeof alt - 1;
    EXPECT_EQ(cd_vec_call(&w), CD_STATUS_INVALID_SIGNATURE);
    cd_sha256(w.cj, w.cjLen, w.chash); cd_vec_resign(&w, &k);
    EXPECT_EQ(cd_vec_call(&w), 0);
    DONE(k);
}
TEST(ctapdev_vga_signature_over_wrong_message) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE raw[64]; BYTE msg[69]; memcpy(msg, v.aa, 37); memset(msg + 37, 0, 32);          /* zero client data hash */
    CHECK(cd_sign_raw(&k, msg, 69, raw)); v.sigLen = cd_der_from_raw(raw, v.sig);
    EXPECT_EQ(cd_vec_call(&v), CD_STATUS_INVALID_SIGNATURE);
    memcpy(msg, v.chash, 32); memcpy(msg + 32, v.aa, 37);                                  /* swapped order */
    CHECK(cd_sign_raw(&k, msg, 69, raw)); v.sigLen = cd_der_from_raw(raw, v.sig);
    EXPECT_EQ(cd_vec_call(&v), CD_STATUS_INVALID_SIGNATURE);
    memcpy(msg, v.aa, 37); cd_sha256(v.cj, v.cjLen, msg + 37);                             /* correct again */
    CHECK(cd_sign_raw(&k, msg, 69, raw)); v.sigLen = cd_der_from_raw(raw, v.sig);
    EXPECT_EQ(cd_vec_call(&v), 0);
    DONE(k);
}
TEST(ctapdev_vga_signature_over_raw_client_data_not_hash) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE msg[400], raw[64]; memcpy(msg, v.aa, 37); memcpy(msg + 37, v.cj, v.cjLen);
    CHECK(cd_sign_raw(&k, msg, 37 + v.cjLen, raw)); v.sigLen = cd_der_from_raw(raw, v.sig);
    EXPECT_EQ(cd_vec_call(&v), CD_STATUS_INVALID_SIGNATURE);
    DONE(k);
}
TEST(ctapdev_vga_signature_replay_other_vector) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    cd_vec a, b; cd_vec_init(&a, &k, L"example.com", 0x05, 1, JSON); cd_vec_init(&b, &k, L"example.com", 0x05, 2, JSON);
    memcpy(a.sig, b.sig, b.sigLen); a.sigLen = b.sigLen;      /* signature from another counter value */
    EXPECT_EQ(cd_vec_call(&a), CD_STATUS_INVALID_SIGNATURE);
    EXPECT_EQ(cd_vec_call(&b), 0);
    cd_key_free(&k);
}

/* ---- signature encoding ---- */
TEST(ctapdev_vga_signature_not_der_is_rejected) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE msg[69], raw[64]; memcpy(msg, v.aa, 37); memcpy(msg + 37, v.chash, 32);
    CHECK(cd_sign_raw(&k, msg, 69, raw));
    memcpy(v.sig, raw, 64); v.sigLen = 64;                      /* IEEE P1363 r||s instead of DER */
    CDHR r = cd_vec_call(&v);
    CHECK(CD_FAILED(r)); CHECK(r != 0);
    t_note("raw P1363 signature -> 0x%08lx", (unsigned long)r);
    DONE(k);
}
TEST(ctapdev_vga_signature_garbage_forms) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const struct { const char *tag; BYTE b[12]; ULONG n; } g[] = {
        { "one byte", { 0x30 }, 1 }, { "empty sequence", { 0x30, 0x00 }, 2 }, { "zeros", { 0, 0, 0, 0, 0, 0, 0, 0 }, 8 },
        { "ints only", { 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, 6 }, { "one int", { 0x30, 0x03, 0x02, 0x01, 0x01 }, 5 },
        { "octets", { 0x30, 0x06, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01 }, 8 }, { "length overrun", { 0x30, 0x7F, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, 8 },
    };
    for (size_t i = 0; i < sizeof g / sizeof g[0]; i++) {
        cd_vec w = v; memcpy(w.sig, g[i].b, g[i].n); w.sigLen = g[i].n;
        CDHR r = cd_vec_call(&w);
        CHECKF(CD_FAILED(r), "%s r=0x%lx", g[i].tag, (unsigned long)r);
        t_note("signature '%s' -> 0x%08lx", g[i].tag, (unsigned long)r);
    }
    DONE(k);
}
TEST(ctapdev_vga_signature_empty) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.sigLen = 0;
    CDHR r = cd_vec_call(&v);
    CHECK(CD_FAILED(r));
    t_note("empty signature -> 0x%08lx", (unsigned long)r);
    DONE(k);
}
TEST(ctapdev_vga_signature_zero_scalars) {
    SETUP(v, k, L"example.com", 0x05, 1);
    static const BYTE z[] = { 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 };
    memcpy(v.sig, z, sizeof z); v.sigLen = sizeof z;
    CDHR r = cd_vec_call(&v);
    CHECK(CD_FAILED(r));
    t_note("r=s=0 signature -> 0x%08lx", (unsigned long)r);
    DONE(k);
}
static ULONG put_int(BYTE *o, const BYTE *v, ULONG l) {      /* minimal positive DER INTEGER from big-endian bytes */
    while (l > 1 && *v == 0) { v++; l--; }
    int pad = (*v & 0x80) != 0; o[0] = 2; o[1] = (BYTE)(l + pad); if (pad) o[2] = 0; memcpy(o + 2 + pad, v, l);
    return 2 + pad + l;
}
TEST(ctapdev_vga_signature_integer_wider_than_curve) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE raw[64], msg[69], wide[33]; memcpy(msg, v.aa, 37); memcpy(msg + 37, v.chash, 32); CHECK(cd_sign_raw(&k, msg, 69, raw));
    wide[0] = 0x01; memcpy(wide + 1, raw, 32);                    /* r as a 33-byte positive integer */
    BYTE d[100]; ULONG n = put_int(d, wide, 33); n += put_int(d + n, raw + 32, 32);
    v.sig[0] = 0x30; v.sig[1] = (BYTE)n; memcpy(v.sig + 2, d, n); v.sigLen = n + 2;
    CDHR r = cd_vec_call(&v);
    CHECK(CD_FAILED(r)); EXPECT_EQ(r, CD_HR_INVALID_DATA);
    DONE(k);
}
TEST(ctapdev_vga_signature_trailing_bytes_note) {
    SETUP(v, k, L"example.com", 0x05, 1);
    v.sig[v.sigLen++] = 0x00;
    t_note("DER signature with one trailing byte outside the SEQUENCE -> 0x%08lx", (unsigned long)cd_vec_call(&v));
    DONE(k);
}
TEST(ctapdev_vga_signature_short_integers_accepted) {
    /* r or s with leading zero bytes in the fixed-width form are encoded as shorter DER integers; they must verify. */
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    int shortR = 0, shortS = 0, total = 0;
    for (int i = 0; i < 3000 && (shortR < 1 || shortS < 1); i++) {
        cd_vec v; cd_vec_init(&v, &k, L"example.com", 0x05, (ULONG)i, JSON);
        ULONG ro, rl, so, sl; der_pos(v.sig, &ro, &rl, &so, &sl);
        if (rl < 32) shortR++;
        if (sl < 32) shortS++;
        CHECKF(cd_vec_call(&v) == 0, "iteration %d rl=%lu sl=%lu", i, (unsigned long)rl, (unsigned long)sl);
        total++;
    }
    t_note("short-integer signatures seen: r=%d s=%d in %d signatures", shortR, shortS, total);
    cd_key_free(&k);
}

/* ---- clientData edge cases ---- */
TEST(ctapdev_vga_client_data_single_byte_and_large) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    cd_key k; if (!cd_key_gen(&k)) { t_skip("keygen"); return; }
    cd_vec v; cd_vec_init(&v, &k, L"example.com", 0x05, 1, "x");
    EXPECT_EQ(cd_vec_call(&v), 0);
    char big[256]; memset(big, 'a', 255); big[255] = 0;
    cd_vec_init(&v, &k, L"example.com", 0x05, 1, big);
    EXPECT_EQ(cd_vec_call(&v), 0);
    cd_key_free(&k);
}
TEST(ctapdev_vga_client_data_large_buffer_hashed_fully) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE *big = (BYTE *)LocalAlloc(LPTR, 1 << 20); if (!big) { t_skip("alloc"); DONE(k); return; }
    for (int i = 0; i < (1 << 20); i++) big[i] = (BYTE)(i * 31);
    cd_sha256(big, 1 << 20, v.chash); cd_vec_resign(&v, &k);
    CD_CLIENT_DATA cd = { 1, 1 << 20, big, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca), 0);
    big[(1 << 20) - 1] ^= 1;
    EXPECT_EQ(cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca), CD_STATUS_INVALID_SIGNATURE);
    LocalFree(big); DONE(k);
}
TEST(ctapdev_vga_client_data_empty_note) {
    SETUP(v, k, L"example.com", 0x05, 1);
    BYTE dummy = 0; cd_sha256("", 0, v.chash); cd_vec_resign(&v, &k);
    CD_CLIENT_DATA cd = { 1, 0, &dummy, L"SHA-256" };
    CD_ASSERTION as; memset(&as, 0, sizeof as); as.dwVersion = 1; as.cbAuthenticatorData = v.aaLen; as.pbAuthenticatorData = v.aa; as.cbSignature = v.sigLen; as.pbSignature = v.sig;
    t_note("empty clientDataJSON (non-NULL pointer, length 0) with matching signature -> 0x%08lx", (unsigned long)cd_verify_call(v.rp, &cd, &as, v.caLen, v.ca));
    DONE(k);
}

/* ---- other ECDSA curves: observed behaviour only ---- */
static void other_curve(LPCWSTR ecAlg, ULONG bits, LPCWSTR hashAlg, ULONG hashBytes, long cose, const char *tag) {
    BCRYPT_ALG_HANDLE ec = NULL, h = NULL; BCRYPT_KEY_HANDLE key = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&ec, ecAlg, NULL, 0) != 0 || U(BCryptOpenAlgorithmProvider)(&h, hashAlg, NULL, 0) != 0) { t_note("%s: curve/hash not available here", tag); goto out; }
    if (U(BCryptGenerateKeyPair)(ec, &key, bits, 0) != 0 || U(BCryptFinalizeKeyPair)(key, 0) != 0) { t_note("%s: keygen failed", tag); goto out; }
    ULONG cb = (bits + 7) / 8; BYTE blob[8 + 140]; ULONG got = 0;
    if (U(BCryptExportKey)(key, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &got, 0) != 0) { t_note("%s: export failed", tag); goto out; }
    cd_vec v; cd_key dummy;
    if (!cd_key_gen(&dummy)) goto out;
    cd_vec_init(&v, &dummy, L"example.com", 0x05, 1, JSON);      /* sig and key replaced below */
    cd_key_free(&dummy);
    BYTE msg[69], hash[64], raw[140]; memcpy(msg, v.aa, 37); memcpy(msg + 37, v.chash, 32);
    BYTE hh[64]; ULONG hgot = 0;
    if (U(BCryptHash)(h, NULL, 0, msg, 69, hh, hashBytes) != 0) goto out;
    memcpy(hash, hh, hashBytes);
    if (U(BCryptSignHash)(key, NULL, hash, hashBytes, raw, 2 * cb, &hgot, 0) != 0) { t_note("%s: sign failed", tag); goto out; }
    /* DER */
    BYTE d[300]; ULONG n = 0;
    for (int part = 0; part < 2; part++) {
        const BYTE *p = raw + part * cb; ULONG l = cb; while (l > 1 && *p == 0) { p++; l--; }
        int pad = (*p & 0x80) != 0; d[n++] = 0x02; d[n++] = (BYTE)(l + pad); if (pad) d[n++] = 0; memcpy(d + n, p, l); n += l;
    }
    v.sig[0] = 0x30;
    if (n < 128) { v.sig[1] = (BYTE)n; memcpy(v.sig + 2, d, n); v.sigLen = n + 2; }
    else { v.sig[1] = 0x81; v.sig[2] = (BYTE)n; memcpy(v.sig + 3, d, n); v.sigLen = n + 3; }
    v.caLen = v.caKeyOff + cd_cose_ec(v.ca + v.caKeyOff, cose, blob + 8, cb, blob + 8 + cb, cb);
    CDHR r = cd_vec_call(&v);
    t_note("%s (COSE alg %ld, %lu-byte coordinates) -> 0x%08lx", tag, cose, (unsigned long)cb, (unsigned long)r);
out:
    if (key) U(BCryptDestroyKey)(key);
    if (ec) U(BCryptCloseAlgorithmProvider)(ec, 0);
    if (h) U(BCryptCloseAlgorithmProvider)(h, 0);
}
TEST(ctapdev_vga_other_curves_observed) {
    CD_NEED_CRYPTO(); CD_REQUIRE_VERIFY();
    if (!U(BCryptCloseAlgorithmProvider) || !U(BCryptFinalizeKeyPair)) { t_skip("bcrypt entry points"); return; }
    other_curve(BCRYPT_ECDSA_P384_ALGORITHM, 384, BCRYPT_SHA384_ALGORITHM, 48, -35, "ES384");
    other_curve(BCRYPT_ECDSA_P521_ALGORITHM, 521, BCRYPT_SHA512_ALGORITHM, 64, -36, "ES512");
}
