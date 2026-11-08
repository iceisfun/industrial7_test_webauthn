# Coverage

Target: Windows 10 x64 `webauthn.dll` (56 exports, no forwarders), plus the `ncrypt.dll` and `bcrypt.dll`
exports that webauthn.dll depends on. About 3800 tests (some table generated) and several thousand checks.

## Export coverage (static scan, `python3 tools/coverage.py .`)

- 207 named exports across the three modules, 176 called through a resolved pointer, 31 not called.
- All 56 webauthn.dll exports are exercised or resolve-checked. The remaining 31 uncovered names are in
  `tools/uncovered.txt` (mostly ncrypt TLS 1.3 key-schedule exports, key-protector exports and CNG
  provider registration, which are intentionally skipped: they change machine state or need live providers).

## Areas

| Area | Content | Tests |
|---|---|---|
| `core_smoke` | Harness smoke test: load, resolve, invoke. | 3 |
| `api_version_platform` | WebAuthNGetApiVersionNumber, IsUserVerifyingPlatformAuthenticatorAvailable, module load/PE/export/import facts. | 550 |
| `export_sweep_resolve` | Whole-DLL export sweep: export directory, ordinals, per-export resolve and alias groups. | 365 |
| `error_names_dom` | WebAuthNGetErrorName and DOM exception mapping, exact strings per code. | 100 |
| `cancellation_ids` | WebAuthNGetCancellationId / CancelCurrentOperation / Free* helpers. | 122 |
| `platform_credentials` | WebAuthNFreePlatformCredentials, WebAuthNFreeUserEntityList, platform credential enumeration validation. | 134 |
| `account_information_codec` | Account information encode/decode/free, mutation robustness, round trips. | 335 |
| `ctap_authdata_cose` | GetCredentialIdFromAuthenticatorData, COSE algorithm and key parsing, malformed inputs. | 205 |
| `ctap_rpc_codec` | I_WebAuthNCtap* RPC request encoders/decoders and helpers. | 204 |
| `ctap_helpers_misc` | Supported transports, device-change notify, string helpers, stop/send helpers. | 119 |
| `ctap_manage_api` | WebAuthNCtapManage* family with synthetic handle shapes (never a real device). | 144 |
| `ctap_device_ops_negative` | CtapGetAssertion / MakeCredential / SendCommand / PIN / Verify early-failure paths. | 165 |
| `make_credential_validation` | WebAuthNAuthenticatorMakeCredential early validation (child process, timeout). | 138 |
| `get_assertion_validation` | WebAuthNAuthenticatorGetAssertion early validation and allow-list handling. | 397 |
| `dx_state_and_threading` | Device-change notify start/stop and threading behaviour. | 139 |
| `gap_00 .. gap_05` | bcrypt/ncrypt public exports: rng, hash, KDF, properties, keys, sign/verify, DPAPI-NG, SSL provider interface, ResetDevice presence. | 130/187/90/38/205/7 |
| `dx_gap_00 .. dx_gap_05` | State-changing CNG calls (context writers, persisted keys, protection descriptor names, SSL provider handles, delete with impossible ids, ResetDevice). | 7/12/5/18/17/1 |

## Method

Every call goes through `GetProcAddress`. Hard checks cover only behaviour confirmed from the Windows 10
decompilation or documentation: parameter validation order, exact status or HRESULT, last-error mapping,
output reset on entry, buffer-size protocols, free-function idempotence and handle lifetime. Build-, locale-
and hardware-dependent observations use `t_note`.

## Not covered on purpose

- Any path that reaches Windows Hello or security-key UI, a physical authenticator, or user presence.
- Successful MakeCredential/GetAssertion/Ctap* flows and `WebAuthNCtapResetDevice` invocation.
- Exhaustion tests and random-pointer tests.
