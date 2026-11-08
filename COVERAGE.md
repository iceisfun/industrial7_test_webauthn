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
| `browser_surface` | Entry points and argument shapes that browser integrations use: required export set and version gating, struct-version handling and bytes read per structure and version (guard-page probes), browser-shaped calls, extension payload reads, error-name/DOM mapping for browser-seen HRESULTs, cancellation ids across two threads, module facts. | 48 |
| `dx_state_and_threading` | Device-change notify start/stop and threading behaviour. | 139 |
| `gap_00 .. gap_05` | bcrypt/ncrypt public exports: rng, hash, KDF, properties, keys, sign/verify, DPAPI-NG, SSL provider interface, ResetDevice presence. | 130/187/90/38/205/7 |
| `dx_gap_00 .. dx_gap_05` | State-changing CNG calls (context writers, persisted keys, protection descriptor names, SSL provider handles, delete with impossible ids, ResetDevice). | 7/12/5/18/17/1 |

## browser_surface method

Structure-read probing places one structure at the end of a committed page whose successor is `PAGE_NOACCESS`,
with only its first S bytes present. A vectored exception handler in the child process (first chance, so
a handler inside the DLL cannot hide the fault) reports the access violation. The smallest S for which the call
returns normally is the number of bytes the DLL reads (4-byte granularity) before the call ends with its local
rejection. Every call carries two independent faults that are rejected locally (MakeCredential: COSE
algorithm 0 and a zero-length exclude-list entry; GetAssertion: an RP id that is not valid UTF-16 and a
zero-length allow-list entry), so no probe can reach UI, the service or a device even if one fault is accepted.
Rows are logged as `NOTE table <m|g> <kind> v<version> mode<n> read=0x.. declared_end=0x.. hr=0x..`. Hard checks
are the build-independent invariants (a documented version is never read beyond its documented size, versions
are accepted or rejected with the same HRESULT, read size is monotonic in the version, the output pointer is
reset). Read sizes themselves and anything that depends on the API version of the build are `NOTE` rows.

## Method

Every call goes through `GetProcAddress`. Hard checks cover only behaviour confirmed from the Windows 10
decompilation or documentation: parameter validation order, exact status or HRESULT, last-error mapping,
output reset on entry, buffer-size protocols, free-function idempotence and handle lifetime. Build-, locale-
and hardware-dependent observations use `t_note`.

## Not covered on purpose

- Any path that reaches Windows Hello or security-key UI, a physical authenticator, or user presence.
- Successful MakeCredential/GetAssertion/Ctap* flows and `WebAuthNCtapResetDevice` invocation.
- Exhaustion tests and random-pointer tests.
