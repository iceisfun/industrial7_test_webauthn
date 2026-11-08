/* Import dependencies of webauthn.dll 10.0.19041.x (reference build). */
#define APV_STATIC_DLLS(X) \
    X(api_ms_win_core_apiquery_l1_1_0, "api-ms-win-core-apiquery-l1-1-0.dll") \
    X(api_ms_win_core_datetime_l1_1_0, "api-ms-win-core-datetime-l1-1-0.dll") \
    X(api_ms_win_core_debug_l1_1_0, "api-ms-win-core-debug-l1-1-0.dll") \
    X(api_ms_win_core_delayload_l1_1_0, "api-ms-win-core-delayload-l1-1-0.dll") \
    X(api_ms_win_core_delayload_l1_1_1, "api-ms-win-core-delayload-l1-1-1.dll") \
    X(api_ms_win_core_errorhandling_l1_1_0, "api-ms-win-core-errorhandling-l1-1-0.dll") \
    X(api_ms_win_core_file_l1_1_0, "api-ms-win-core-file-l1-1-0.dll") \
    X(api_ms_win_core_handle_l1_1_0, "api-ms-win-core-handle-l1-1-0.dll") \
    X(api_ms_win_core_heap_l1_1_0, "api-ms-win-core-heap-l1-1-0.dll") \
    X(api_ms_win_core_heap_l2_1_0, "api-ms-win-core-heap-l2-1-0.dll") \
    X(api_ms_win_core_heap_obsolete_l1_1_0, "api-ms-win-core-heap-obsolete-l1-1-0.dll") \
    X(api_ms_win_core_interlocked_l1_1_0, "api-ms-win-core-interlocked-l1-1-0.dll") \
    X(api_ms_win_core_io_l1_1_0, "api-ms-win-core-io-l1-1-0.dll") \
    X(api_ms_win_core_libraryloader_l1_2_0, "api-ms-win-core-libraryloader-l1-2-0.dll") \
    X(api_ms_win_core_localization_l1_2_0, "api-ms-win-core-localization-l1-2-0.dll") \
    X(api_ms_win_core_processenvironment_l1_1_0, "api-ms-win-core-processenvironment-l1-1-0.dll") \
    X(api_ms_win_core_processthreads_l1_1_0, "api-ms-win-core-processthreads-l1-1-0.dll") \
    X(api_ms_win_core_processthreads_l1_1_1, "api-ms-win-core-processthreads-l1-1-1.dll") \
    X(api_ms_win_core_psapi_l1_1_0, "api-ms-win-core-psapi-l1-1-0.dll") \
    X(api_ms_win_core_registry_l1_1_0, "api-ms-win-core-registry-l1-1-0.dll") \
    X(api_ms_win_core_rtlsupport_l1_1_0, "api-ms-win-core-rtlsupport-l1-1-0.dll") \
    X(api_ms_win_core_string_l1_1_0, "api-ms-win-core-string-l1-1-0.dll") \
    X(api_ms_win_core_synch_l1_1_0, "api-ms-win-core-synch-l1-1-0.dll") \
    X(api_ms_win_core_synch_l1_2_0, "api-ms-win-core-synch-l1-2-0.dll") \
    X(api_ms_win_core_synch_l1_2_1, "api-ms-win-core-synch-l1-2-1.dll") \
    X(api_ms_win_core_sysinfo_l1_1_0, "api-ms-win-core-sysinfo-l1-1-0.dll") \
    X(api_ms_win_core_threadpool_l1_2_0, "api-ms-win-core-threadpool-l1-2-0.dll") \
    X(api_ms_win_core_timezone_l1_1_0, "api-ms-win-core-timezone-l1-1-0.dll") \
    X(api_ms_win_crt_private_l1_1_0, "api-ms-win-crt-private-l1-1-0.dll") \
    X(api_ms_win_crt_runtime_l1_1_0, "api-ms-win-crt-runtime-l1-1-0.dll") \
    X(api_ms_win_crt_string_l1_1_0, "api-ms-win-crt-string-l1-1-0.dll") \
    X(api_ms_win_eventing_provider_l1_1_0, "api-ms-win-eventing-provider-l1-1-0.dll") \
    X(bcrypt, "bcrypt.dll") \
    X(msvcp_win, "msvcp_win.dll") \
    X(ntdll, "ntdll.dll")
#define APV_DELAY_DLLS(X) \
    X(crypt32, "CRYPT32.dll") \
    X(cryptbase, "CRYPTBASE.dll") \
    X(devobj, "DEVOBJ.dll") \
    X(hid, "HID.DLL") \
    X(rpcrt4, "RPCRT4.dll") \
    X(wintrust, "WINTRUST.dll") \
    X(api_ms_win_core_com_l1_1_0, "api-ms-win-core-com-l1-1-0.dll") \
    X(api_ms_win_core_winrt_error_l1_1_0, "api-ms-win-core-winrt-error-l1-1-0.dll") \
    X(api_ms_win_core_winrt_l1_1_0, "api-ms-win-core-winrt-l1-1-0.dll") \
    X(api_ms_win_core_winrt_robuffer_l1_1_0, "api-ms-win-core-winrt-robuffer-l1-1-0.dll") \
    X(api_ms_win_core_winrt_string_l1_1_0, "api-ms-win-core-winrt-string-l1-1-0.dll") \
    X(api_ms_win_security_base_l1_1_0, "api-ms-win-security-base-l1-1-0.dll") \
    X(api_ms_win_security_capability_l1_1_0, "api-ms-win-security-capability-l1-1-0.dll") \
    X(api_ms_win_security_sddl_l1_1_0, "api-ms-win-security-sddl-l1-1-0.dll") \
    X(api_ms_win_service_management_l1_1_0, "api-ms-win-service-management-l1-1-0.dll") \
    X(api_ms_win_service_management_l2_1_0, "api-ms-win-service-management-l2-1-0.dll") \
    X(api_ms_win_service_private_l1_1_0, "api-ms-win-service-private-l1-1-0.dll") \
    X(api_ms_win_service_winsvc_l1_1_0, "api-ms-win-service-winsvc-l1-1-0.dll") \
    X(credui, "credui.dll") \
    X(cryptngc, "cryptngc.dll") \
    X(ext_ms_win_ntuser_window_l1_1_0, "ext-ms-win-ntuser-window-l1-1-0.dll") \
    X(ext_ms_win_security_winscard_l1_1_0, "ext-ms-win-security-winscard-l1-1-0.dll") \
    X(ext_ms_win_security_winscard_l1_1_1, "ext-ms-win-security-winscard-l1-1-1.dll") \
    X(ext_ms_win_session_winsta_l1_1_0, "ext-ms-win-session-winsta-l1-1-0.dll") \
    X(ext_ms_win_session_wtsapi32_l1_1_0, "ext-ms-win-session-wtsapi32-l1-1-0.dll") \
    X(ext_ms_win_session_wtsapi32_l1_1_1, "ext-ms-win-session-wtsapi32-l1-1-1.dll") \
    X(ncrypt, "ncrypt.dll") \
    X(tbs, "tbs.dll")
static const char *const apv_imp_bcrypt[] = {"BCryptGenerateKeyPair","BCryptCloseAlgorithmProvider","BCryptImportKeyPair","BCryptFinalizeKeyPair","BCryptDecrypt","BCryptSignHash","BCryptExportKey","BCryptSecretAgreement","BCryptDeriveKey","BCryptSetProperty","BCryptOpenAlgorithmProvider","BCryptDestroyHash","BCryptGenerateSymmetricKey","BCryptFinishHash","BCryptHashData","BCryptCreateHash","BCryptDestroySecret","BCryptDestroyKey","BCryptVerifySignature","BCryptEncrypt"};
static const char *const apv_imp_ntdll[] = {"RtlCompareUnicodeString","NtQueryInformationToken","RtlUnhandledExceptionFilter","NtTerminateProcess","RtlIsMultiSessionSku","RtlPublishWnfStateData"};
static const char *const apv_dimp_ncrypt[] = {"NCryptEnumKeys","NCryptFreeBuffer","NCryptFinalizeKey","NCryptCreatePersistedKey","NCryptDeleteKey","NCryptOpenKey","NCryptOpenStorageProvider","NCryptSignHash","NCryptFreeObject","NCryptSetProperty","NCryptGetProperty","NCryptExportKey"};
static const char *const apv_dimp_cryptngc[] = {"NgcCreateUserIdKeyHandle","NgcCancelPendingUIRequest","NgcOpenUserIdKey","NgcFreeEnumState","NgcSignWithUserIdKeyAndPadding","NgcGetUserIdKeyName","NgcEnumContainers","NgcRenewKeyAttestation","NgcDeleteUserIdKey","NgcEnumUserIdKeys","NgcGetKeyAttestationForUserIdKey2"};
static const char *const apv_dimp_crypt32[] = {"CertFreeCertificateContext","CryptSignAndEncodeCertificate","CryptHashCertificate2","CertStrToNameW","CryptExportPublicKeyInfoEx","CryptEncodeObject","CryptEncodeObjectEx","CryptProtectMemory","CryptUnprotectMemory","CertFreeCertificateChain","CertGetNameStringW","CryptStringToBinaryW","CryptBinaryToStringW","CertGetCertificateChain","CertCreateCertificateContext","CryptDecodeObjectEx"};
static const char *const apv_dimp_hid[] = {"HidD_SetNumInputBuffers","HidD_GetAttributes","HidD_GetProductString","HidD_GetHidGuid","HidD_FlushQueue","HidD_FreePreparsedData","HidP_GetCaps","HidD_GetManufacturerString","HidD_GetPreparsedData"};
static const char *const apv_dimp_devobj[] = {"DevObjGetClassDevs","DevObjDestroyDeviceInfoList","DevObjGetDeviceInterfaceDetail","DevObjCreateDeviceInfoList","DevObjEnumDeviceInterfaces"};
static const char *const apv_dimp_rpcrt4[] = {"NdrAsyncServerCall","RpcEpResolveBinding","RpcBindingFromStringBindingA","RpcBindingFree","RpcServerUnregisterIf","RpcServerRegisterIf3","Ndr64AsyncClientCall","RpcServerUnsubscribeForNotification","RpcServerSubscribeForNotification","RpcAsyncCompleteCall","RpcServerTestCancel","RpcBindingSetAuthInfoExW","RpcStringBindingComposeA","I_RpcBindingInqLocalClientPID","RpcImpersonateClient","RpcRevertToSelfEx","UuidFromStringW","Ndr64AsyncServerCallAll","UuidCreate","RpcStringFreeA","RpcAsyncCancelCall","I_RpcBindingIsClientLocal","RpcAsyncGetCallStatus","RpcAsyncInitializeHandle"};
static const char *const apv_dimp_wintrust[] = {"WTGetSignatureInfo"};
static const char *const apv_dimp_tbs[] = {"Tbsi_GetDeviceInfo"};
static const char *const apv_dimp_credui[] = {"CredUIPromptForWindowsCredentialsW"};
static const char *const apv_dimp_cryptbase[] = {"SystemFunction036"};
