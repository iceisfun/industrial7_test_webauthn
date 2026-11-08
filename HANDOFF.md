# Handoff: Windows 10 pass for the webauthn.dll corpus

## Purpose
This corpus asserts the behaviour of Windows 10 x64 `webauthn.dll` (with `ncrypt.dll` and `bcrypt.dll` as
dependencies) so that an implementation can be checked against it. Windows 10 results are the authority.
So far the binaries have only been validated under an emulator that lacks `webauthn.dll`: every webauthn test
skipped there, so expect some wrong expectations in the first real run, mostly in areas never executed.

## Prerequisites
- Disposable Windows 10 x64 VM (22H2 or a documented build) with a snapshot. Record `winver` and the
  version of `webauthn.dll`.
- No security key plugged in and no Bluetooth/NFC authenticator nearby. The tests are designed not to touch
  one, but keep the machine clean anyway. A Windows Hello dialog appearing is a corpus bug: stop and report.
- A standard user and an elevated administrator account (run both).
- Build host with `x86_64-w64-mingw32-gcc` and `make`, or a prebuilt `build/` copied across.

## Build
    make clean && make -j8      # build/<area>.exe, 27 executables

## Run
1. Standard user:  `tools\run_all.bat`
2. Administrator:  `tools\run_all.bat`
3. Revert snapshot, administrator, state-changing areas: `tools\run_all.bat /destructive`
Single area or test: `build\<area>.exe <name-substring>`. Each exe has a hard 600 s limit in run_all.bat.
Collect: `python tools\summarize.py build\results --failures`, and zip `build\results\*.txt`.

## Triage
Classify each failing check:
1. Wrong expectation: Windows behaves differently from the test. Fix the test, use `t_note` if the behaviour
   depends on build, locale or SKU.
2. Environment: privilege, hardware, policy. Turn into `t_skip` or `t_note`.
3. Real divergence: the point of the corpus. Record it with the exact expected and observed values.
Fix, rebuild, re-run only that test, commit with a short message.

## Expected skips
- Under the emulator every webauthn.dll test skips (library missing). On Windows 10 these should run.
- `dx_*` areas are skipped without `/destructive`.
- Tests needing a window handle or platform authenticator state skip when the environment cannot supply it.

## Known weak spots
- `gap_00` (24 tests) and `gap_04` (25 tests) fail under the emulator because its bcrypt returns different
  statuses (for example STATUS_INVALID_PARAMETER vs STATUS_INVALID_HANDLE ordering, unsupported algorithms,
  ECDSA signature sizes). The expectations came from the Windows 10 decompilation, so these are probably
  emulator differences, but they are the first place to look for wrong expectations on Windows.
- `ctap_*`, `make_credential_validation`, `get_assertion_validation` encode early-validation order from
  the decompilation; none have run against the real DLL.

## Cleanup after a crashed run
- Scratch files: `%TEMP%\webautt_<pid>\` (delete the folders).
- Kill strays: `taskkill /f /im <area>.exe`.
- After `dx_*`: revert the VM snapshot. These areas can touch per-user CNG key containers whose names carry
  the corpus tag, protection descriptor names in HKCU, and CNG context configuration. No test deletes or
  resets a real credential or authenticator.

## Report back
Totals per area (tests, failed, skipped), the list of wrong expectations fixed, the list of real divergences
with expected and observed values, any area that could not run, and the exact Windows build and
`webauthn.dll` version.
