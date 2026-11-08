#include "gap4.h"
/* BCryptExportKey */

#define XREQ() do { if (!BC(BCryptExportKey) || !BC(BCryptGenerateKeyPair) || !BC(BCryptFinalizeKeyPair) || !BC(BCryptDestroyKey)) { t_skip("missing key exports"); return; } } while (0)

typedef struct { const wchar_t *alg; ULONG bits; ULONG cbKey; ULONG pubMagic; ULONG privMagic; } ecc_t;
static const ecc_t ecc[] = {
    { BCRYPT_ECDSA_P256_ALGORITHM, 256, 32, 0x31534345, 0x32534345 },
    { BCRYPT_ECDSA_P384_ALGORITHM, 384, 48, 0x33534345, 0x34534345 },
    { BCRYPT_ECDSA_P521_ALGORITHM, 521, 66, 0x35534345, 0x36534345 },
    { BCRYPT_ECDH_P256_ALGORITHM, 256, 32, 0x314B4345, 0x324B4345 },
    { BCRYPT_ECDH_P384_ALGORITHM, 384, 48, 0x334B4345, 0x344B4345 },
    { BCRYPT_ECDH_P521_ALGORITHM, 521, 66, 0x354B4345, 0x364B4345 },
};

static void ecc_export(const ecc_t *e)
{
    BCRYPT_ALG_HANDLE a = g4_open(e->alg, 0);
    if (!a) { CHECK(0); return; }
    BCRYPT_KEY_HANDLE k = g4_keypair(a, e->bits);
    if (!k) { CHECKF(0, "key pair %ls", e->alg); g4_close(a); return; }
    BYTE blob[512]; ULONG n = 0xDEADBEEF;
    /* size query */
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 8 + 2 * e->cbKey);
    n = 0;
    memset(blob, 0xEE, sizeof blob);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof blob, &n, 0), 0);
    EXPECT_EQ(n, 8 + 2 * e->cbKey);
    BCRYPT_ECCKEY_BLOB *h = (BCRYPT_ECCKEY_BLOB *)blob;
    EXPECT_EQ(h->dwMagic, e->pubMagic);
    EXPECT_EQ(h->cbKey, e->cbKey);
    int over = 0; for (ULONG i = n; i < sizeof blob; i++) if (blob[i] != 0xEE) over++;
    EXPECT_EQ(over, 0);
    /* exact fit works, one byte short does not */
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, e->cbKey * 2 + 8, &n, 0), 0);
    n = 0;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, e->cbKey * 2 + 7, &n, 0), G4_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, 8 + 2 * e->cbKey);
    /* private */
    n = 0;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &n, 0), 0);
    EXPECT_EQ(n, 8 + 3 * e->cbKey);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, sizeof blob, &n, 0), 0);
    EXPECT_EQ(h->dwMagic, e->privMagic);
    EXPECT_EQ(h->cbKey, e->cbKey);
    BC(BCryptDestroyKey)(k);
    g4_close(a);
}
#define ECC_T(i) TEST(gap4_export_ecc_##i) { XREQ(); ecc_export(&ecc[i]); }
ECC_T(0) ECC_T(1) ECC_T(2) ECC_T(3) ECC_T(4) ECC_T(5)

TEST(gap4_export_pubkey_matches_private_prefix) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE pub[72], priv[104]; ULONG n;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, pub, 72, &n, 0), 0);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPRIVATE_BLOB, priv, 104, &n, 0), 0);
    CHECK(!memcmp(pub + 8, priv + 8, 64));
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_public_stable_between_calls) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE p1[72], p2[72]; ULONG n;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, p1, 72, &n, 0), 0);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, p2, 72, &n, 0), 0);
    CHECK(!memcmp(p1, p2, 72));
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_import_roundtrip_public) {
    XREQ();
    if (!BC(BCryptImportKeyPair)) { t_skip("missing BCryptImportKeyPair"); return; }
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE p1[72], p2[72]; ULONG n;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, p1, 72, &n, 0), 0);
    BCRYPT_KEY_HANDLE k2 = NULL;
    EQC(BC(BCryptImportKeyPair)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k2, p1, 72, 0), 0);
    if (k2) {
        EQC(BC(BCryptExportKey)(k2, NULL, BCRYPT_ECCPUBLIC_BLOB, p2, 72, &n, 0), 0);
        CHECK(!memcmp(p1, p2, 72));
        BC(BCryptDestroyKey)(k2);
    }
    BC(BCryptDestroyKey)(k); g4_close(a);
}

/* RSA: header {magic, bitlen, cbPublicExp, cbModulus, cbPrime1, cbPrime2} */
TEST(gap4_export_rsa_public_and_private_layout) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 1024); REQUIRE(k);
    BYTE blob[1024]; ULONG n = 0;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &n, 0), 0);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, blob, sizeof blob, &n, 0), 0);
    BCRYPT_RSAKEY_BLOB *h = (BCRYPT_RSAKEY_BLOB *)blob;
    EXPECT_EQ(h->Magic, BCRYPT_RSAPUBLIC_MAGIC);
    EXPECT_EQ(h->BitLength, 1024);
    EXPECT_EQ(h->cbModulus, 128);
    EXPECT_EQ(h->cbPrime1, 0);
    EXPECT_EQ(h->cbPrime2, 0);
    EXPECT_EQ(n, sizeof(BCRYPT_RSAKEY_BLOB) + h->cbPublicExp + h->cbModulus);
    /* default public exponent is 65537 */
    CHECK(h->cbPublicExp == 3 && blob[24] == 1 && blob[25] == 0 && blob[26] == 1);
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_RSAPRIVATE_BLOB, blob, sizeof blob, &n, 0), 0);
    EXPECT_EQ(h->Magic, BCRYPT_RSAPRIVATE_MAGIC);
    EXPECT_EQ(h->BitLength, 1024);
    EXPECT_EQ(h->cbPrime1, 64);
    EXPECT_EQ(h->cbPrime2, 64);
    EXPECT_EQ(n, sizeof(BCRYPT_RSAKEY_BLOB) + h->cbPublicExp + h->cbModulus + h->cbPrime1 + h->cbPrime2);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_rsa_modulus_top_bit_set) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 1024); REQUIRE(k);
    BYTE blob[512]; ULONG n;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, blob, sizeof blob, &n, 0), 0);
    CHECK(blob[24 + 3] & 0x80); /* big-endian modulus follows the exponent */
    BC(BCryptDestroyKey)(k); g4_close(a);
}

/* ---- argument validation (order: pcbResult / blob type, key handle, key class, export key) ---- */
TEST(gap4_export_null_pcbresult) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE b[128];
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, b, sizeof b, NULL, 0), G4_INVALID_PARAM);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_null_blob_type) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE b[128]; ULONG n = 0x77;
    EQC(BC(BCryptExportKey)(k, NULL, NULL, b, sizeof b, &n, 0), G4_INVALID_PARAM);
    EXPECT_EQ(n, 0x77);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_null_key_valid_args) {
    XREQ();
    BYTE b[128]; ULONG n = 0x77;
    EQC(BC(BCryptExportKey)(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, b, sizeof b, &n, 0), G4_INVALID_HANDLE);
}
TEST(gap4_export_params_checked_before_handle) {
    XREQ();
    ULONG n;
    /* NULL pcbResult / blob type win over an invalid key handle */
    EQC(BC(BCryptExportKey)(NULL, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, NULL, 0), G4_INVALID_PARAM);
    EQC(BC(BCryptExportKey)(NULL, NULL, NULL, NULL, 0, &n, 0), G4_INVALID_PARAM);
}
TEST(gap4_export_algorithm_handle_is_wrong_object) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    ULONG n;
    EQC(BC(BCryptExportKey)(a, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &n, 0), G4_INVALID_HANDLE);
    g4_close(a);
}
TEST(gap4_export_hash_handle_is_wrong_object) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_SHA256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_HASH_HANDLE hh = NULL;
    EQC(BC(BCryptCreateHash)(a, &hh, NULL, 0, NULL, 0, 0), 0);
    ULONG n;
    if (hh) { EQC(BC(BCryptExportKey)(hh, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &n, 0), G4_INVALID_HANDLE); BC(BCryptDestroyHash)(hh); }
    g4_close(a);
}
TEST(gap4_export_export_key_must_be_symmetric_key) {
    XREQ();
    /* hExportKey that is not a key handle at all */
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    ULONG n;
    EQC(BC(BCryptExportKey)(k, a, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &n, 0), G4_INVALID_HANDLE);
    /* hExportKey that is an asymmetric key (class != symmetric) */
    BCRYPT_KEY_HANDLE k2 = g4_keypair(a, 256); REQUIRE(k2);
    EQC(BC(BCryptExportKey)(k, k2, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &n, 0), G4_INVALID_HANDLE);
    BC(BCryptDestroyKey)(k2); BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_unknown_blob_type) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE b[256]; ULONG n = 0;
    NTSTATUS s = BC(BCryptExportKey)(k, NULL, L"NoSuchBlobType", b, sizeof b, &n, 0);
    CHECK(s < 0);
    t_note("unknown blob type -> 0x%lx", (unsigned long)s);
    s = BC(BCryptExportKey)(k, NULL, L"", b, sizeof b, &n, 0);
    CHECK(s < 0);
    t_note("empty blob type -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_rsa_blob_type_on_ecc_key) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE b[512]; ULONG n = 0;
    NTSTATUS s = BC(BCryptExportKey)(k, NULL, BCRYPT_RSAPUBLIC_BLOB, b, sizeof b, &n, 0);
    t_note("RSAPUBLICBLOB on ECDSA key -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_ecc_blob_type_on_rsa_key) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_RSA_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 1024); REQUIRE(k);
    BYTE b[512]; ULONG n = 0;
    NTSTATUS s = BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, b, sizeof b, &n, 0);
    t_note("ECCPUBLICBLOB on RSA key -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_unfinalized_key) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = NULL;
    REQUIRE(BC(BCryptGenerateKeyPair)(a, &k, 256, 0) == 0);
    BYTE b[256]; ULONG n = 0;
    NTSTATUS s = BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, b, sizeof b, &n, 0);
    t_note("export before BCryptFinalizeKeyPair -> 0x%lx", (unsigned long)s);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
TEST(gap4_export_zero_output_with_buffer) {
    XREQ();
    BCRYPT_ALG_HANDLE a = g4_open(BCRYPT_ECDSA_P256_ALGORITHM, 0); REQUIRE(a);
    BCRYPT_KEY_HANDLE k = g4_keypair(a, 256); REQUIRE(k);
    BYTE b[8]; ULONG n = 0;
    EQC(BC(BCryptExportKey)(k, NULL, BCRYPT_ECCPUBLIC_BLOB, b, 0, &n, 0), G4_BUFFER_TOO_SMALL);
    EXPECT_EQ(n, 72);
    BC(BCryptDestroyKey)(k); g4_close(a);
}
