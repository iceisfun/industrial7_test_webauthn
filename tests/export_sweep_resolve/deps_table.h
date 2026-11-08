/* Functions of bcrypt.dll / ncrypt.dll that a WebAuthn client implementation depends on. */
#define SWEEP_BCRYPT(X) \
    X(BCryptOpenAlgorithmProvider) \
    X(BCryptCloseAlgorithmProvider) \
    X(BCryptGenRandom) \
    X(BCryptHash) \
    X(BCryptCreateHash) \
    X(BCryptHashData) \
    X(BCryptFinishHash) \
    X(BCryptDestroyHash) \
    X(BCryptDuplicateHash) \
    X(BCryptGetProperty) \
    X(BCryptSetProperty) \
    X(BCryptGenerateKeyPair) \
    X(BCryptFinalizeKeyPair) \
    X(BCryptExportKey) \
    X(BCryptImportKey) \
    X(BCryptImportKeyPair) \
    X(BCryptSignHash) \
    X(BCryptVerifySignature) \
    X(BCryptDestroyKey) \
    X(BCryptEncrypt) \
    X(BCryptDecrypt) \
    X(BCryptSecretAgreement) \
    X(BCryptDeriveKey) \
    X(BCryptGenerateSymmetricKey) \
    X(BCryptDestroySecret) \
    X(BCryptKeyDerivation) \
    X(BCryptDuplicateKey) \
    X(BCryptFreeBuffer) \
    X(BCryptEnumAlgorithms) \
    /* end */
#define SWEEP_NCRYPT(X) \
    X(NCryptOpenStorageProvider) \
    X(NCryptCreatePersistedKey) \
    X(NCryptFinalizeKey) \
    X(NCryptOpenKey) \
    X(NCryptDeleteKey) \
    X(NCryptFreeObject) \
    X(NCryptSetProperty) \
    X(NCryptGetProperty) \
    X(NCryptExportKey) \
    X(NCryptImportKey) \
    X(NCryptSignHash) \
    X(NCryptVerifySignature) \
    X(NCryptEncrypt) \
    X(NCryptDecrypt) \
    X(NCryptEnumKeys) \
    X(NCryptEnumStorageProviders) \
    X(NCryptFreeBuffer) \
    X(NCryptIsAlgSupported) \
    X(NCryptSecretAgreement) \
    X(NCryptDeriveKey) \
    X(NCryptKeyDerivation) \
    X(NCryptIsKeyHandle) \
    X(NCryptTranslateHandle) \
    /* end */
