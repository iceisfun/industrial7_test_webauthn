# webauthn.dll conformance corpus

Black-box tests for Windows 10 x64 `webauthn.dll`. The DLL is never linked: each test loads it with `LoadLibrary`,
resolves entry points with `GetProcAddress` (`U(Name)` gives a pointer typed from the SDK header;
`UIN("module.dll", Name)` pins one module, which matters for forwarders) and calls through the pointer.

Modules searched by `U()`: webauthn.dll ncrypt.dll bcrypt.dll ntdll.dll kernel32.dll.

    make                         # cross-compile build/<area>.exe (mingw-w64)
    build\<area>.exe [substr]    # on Windows; optional test-name filter
    tools\run_all.bat            # everything, results\<area>.txt (add /destructive for dx_* areas)
    python tools\summarize.py results [--failures]

Output: `RUN/OK/FAIL/SKIP` per test, `  FAIL file:line expr (detail)` per failed check, `SUMMARY` last;
exit code 1 if any test failed. `NOTE` lines record observed, version-dependent behaviour.

Tests that need a second process re-launch the exe (`--child <name>`). Scratch files live in
`%TEMP%\webautt_<pid>\` and are removed on exit. `tools/*_exports.txt` list the named exports.

See `HANDOFF.md` (when present) for how to run and triage the Windows passes.

## Areas and layout

Each directory under `tests/` builds into `build/<area>.exe`. Areas named `dx_*` are state-changing and are
skipped by `tools\run_all.bat` unless `/destructive` is passed. `COVERAGE.md` lists what each area covers.

- WebAuthn client: `api_version_platform`, `export_sweep_resolve`, `error_names_dom`, `cancellation_ids`,
  `platform_credentials`, `account_information_codec`, `ctap_authdata_cose`, `ctap_rpc_codec`,
  `ctap_helpers_misc`, `ctap_manage_api`, `ctap_device_ops_negative`, `make_credential_validation`,
  `get_assertion_validation`, `browser_surface`.
- CNG dependencies: `gap_00` to `gap_05` (bcrypt/ncrypt exports).
- State-changing: `dx_state_and_threading`, `dx_gap_00` to `dx_gap_05`.
- Harness check: `core_smoke`.

## Safety

The tests must never show Windows Hello or security-key UI, touch an authenticator, or wait for user
presence. Calls to MakeCredential, GetAssertion, Ctap* and Manage* are made only with arguments that the
reference decompilation shows are rejected before any UI or device work, usually in a child process with a
timeout. Manage* calls use synthetic handle shapes. `WebAuthNCtapResetDevice` is never invoked. Credential
deletion uses ids that cannot match a real credential. Anything not provable is resolve-only.

## Running on Windows 10

Build on Linux with `make` (needs mingw-w64), copy `build/*.exe` and `tools/` to the machine, then run
`tools\run_all.bat`. Details, triage and cleanup are in `HANDOFF.md`.
