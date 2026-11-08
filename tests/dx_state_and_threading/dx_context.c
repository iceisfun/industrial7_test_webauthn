/* Calling context variants: COM apartment models, security contexts (impersonation, restricted /
 * low-integrity token), processes without a console or interactive desktop. Each variant runs the
 * same non-UI calls in a child and records exact HRESULTs via t_note; hard checks are limited to
 * no-crash / no-hang and values proven by the reference decompilation. */
#include "dx_common.h"
#include <ole2.h>

#define DX_REQ_ALL() dx_api a_; if (!dx_resolve(&a_)) { t_skip("missing export"); return; }
#define OLE(name) UIN("ole32.dll", name)
#define USR(name) UIN("user32.dll", name)

/* ---------------- COM apartments ---------------- */
static dx_api g_a;
static DWORD WINAPI call_thread_plain(LPVOID p) { dx_call_all(&g_a, (const char *)p); return 0; }
static DWORD WINAPI call_thread_mta(LPVOID p) {
    HRESULT hr = OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
    dx_call_all(&g_a, (const char *)p);
    if (SUCCEEDED(hr)) OLE(CoUninitialize)();
    return 0;
}
static DWORD WINAPI call_thread_sta(LPVOID p) {
    HRESULT hr = OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
    dx_call_all(&g_a, (const char *)p);
    if (SUCCEEDED(hr)) OLE(CoUninitialize)();
    return 0;
}
static void run_thread(LPTHREAD_START_ROUTINE f, const char *label) {
    HANDLE h = CreateThread(NULL, 0, f, (LPVOID)label, 0, NULL);
    DXC(h != NULL);
    if (h && WaitForSingleObject(h, 60000) != WAIT_OBJECT_0) { printf("  FAIL %s hang\n", label); TerminateProcess(GetCurrentProcess(), 99); }
    if (h) CloseHandle(h);
}

CHILD(dx_apt) {
    const char *m = argc > 1 ? argv[1] : "none";
    if (!dx_resolve(&g_a)) return 97;
    HRESULT hr;
    if (!strcmp(m, "none")) {
        dx_call_all(&g_a, "no-com");
    } else if (!strcmp(m, "mta")) {
        hr = OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED); DXCF(SUCCEEDED(hr), "CoInitializeEx hr=0x%08lx", (unsigned long)hr);
        dx_call_all(&g_a, "mta"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "sta")) {
        hr = OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED); DXCF(SUCCEEDED(hr), "CoInitializeEx hr=0x%08lx", (unsigned long)hr);
        dx_call_all(&g_a, "sta"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "sta_ole")) {
        hr = OLE(OleInitialize)(NULL); DXCF(SUCCEEDED(hr), "OleInitialize hr=0x%08lx", (unsigned long)hr);
        dx_call_all(&g_a, "ole-sta"); OLE(OleUninitialize)();
    } else if (!strcmp(m, "sta_nested")) {
        OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED); OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
        dx_call_all(&g_a, "sta-nested"); OLE(CoUninitialize)(); dx_call_all(&g_a, "sta-after-one-uninit"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "mta_then_uninit")) {
        OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        dx_call_all(&g_a, "mta-before-uninit"); OLE(CoUninitialize)();
        dx_call_all(&g_a, "after-uninit");
    } else if (!strcmp(m, "mta_changed_mode")) {
        OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        hr = OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
        DXCF(hr == (HRESULT)0x80010106u, "mixed-model CoInitializeEx hr=0x%08lx", (unsigned long)hr);   /* RPC_E_CHANGED_MODE */
        dx_call_all(&g_a, "mta-after-changed-mode"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "sta_changed_mode")) {
        OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
        hr = OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        DXCF(hr == (HRESULT)0x80010106u, "mixed-model CoInitializeEx hr=0x%08lx", (unsigned long)hr);
        dx_call_all(&g_a, "sta-after-changed-mode"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "thread_mta")) {
        run_thread(call_thread_mta, "worker-mta");
    } else if (!strcmp(m, "thread_sta")) {
        run_thread(call_thread_sta, "worker-sta");
    } else if (!strcmp(m, "main_sta_worker_mta")) {
        OLE(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
        run_thread(call_thread_mta, "worker-mta");
        dx_call_all(&g_a, "main-sta"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "main_mta_worker_sta")) {
        OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        run_thread(call_thread_sta, "worker-sta");
        dx_call_all(&g_a, "main-mta"); OLE(CoUninitialize)();
    } else if (!strcmp(m, "main_mta_worker_plain")) {
        OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        run_thread(call_thread_plain, "worker-no-com");
        OLE(CoUninitialize)();
    } else if (!strcmp(m, "sec_identify") || !strcmp(m, "sec_default") || !strcmp(m, "sec_none")) {
        /* process-wide COM security set before the first call */
        OLE(CoInitializeEx)(NULL, COINIT_MULTITHREADED);
        DWORD authn = !strcmp(m, "sec_none") ? RPC_C_AUTHN_LEVEL_NONE : RPC_C_AUTHN_LEVEL_DEFAULT;
        DWORD imp = !strcmp(m, "sec_identify") ? RPC_C_IMP_LEVEL_IDENTIFY : RPC_C_IMP_LEVEL_IMPERSONATE;
        hr = OLE(CoInitializeSecurity)(NULL, -1, NULL, NULL, authn, imp, NULL, EOAC_NONE, NULL);
        t_note("%s: CoInitializeSecurity hr=0x%08lx", m, (unsigned long)hr);
        dx_call_all(&g_a, m); OLE(CoUninitialize)();
    } else if (!strcmp(m, "repeat_toggle")) {
        for (int i = 0; i < 20; i++) {
            OLE(CoInitializeEx)(NULL, (i & 1) ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED);
            BOOL b = 0x7777; DXC(g_a.iuv(&b) == 0); DXC(b != 0x7777);
            OLE(CoUninitialize)();
        }
    } else return 98;
    return dx_rc();
}
#define APT(name, arg) TEST(dx_apt_##name) { DX_REQ_ALL(); DX_CHILD_OK("dx_apt", arg, 90000); }
APT(none, "none")
APT(mta, "mta")
APT(sta, "sta")
APT(sta_ole, "sta_ole")
APT(sta_nested, "sta_nested")
APT(mta_then_uninit, "mta_then_uninit")
APT(mta_changed_mode, "mta_changed_mode")
APT(sta_changed_mode, "sta_changed_mode")
APT(worker_thread_mta, "thread_mta")
APT(worker_thread_sta, "thread_sta")
APT(main_sta_worker_mta, "main_sta_worker_mta")
APT(main_mta_worker_sta, "main_mta_worker_sta")
APT(main_mta_worker_plain, "main_mta_worker_plain")
APT(security_identify, "sec_identify")
APT(security_default, "sec_default")
APT(security_authn_none, "sec_none")
APT(repeat_toggle_models, "repeat_toggle")

/* ---------------- impersonation ---------------- */
static int thread_has_token(void) {
    HANDLE t = NULL;
    SetLastError(0);
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &t)) { CloseHandle(t); return 1; }
    return 0;
}
CHILD(dx_imp) {
    const char *m = argc > 1 ? argv[1] : "self";
    if (!dx_resolve(&g_a)) return 97;
    SECURITY_IMPERSONATION_LEVEL lvl = SecurityImpersonation;
    if (!strcmp(m, "ident")) lvl = SecurityIdentification;
    else if (!strcmp(m, "deleg")) lvl = SecurityDelegation;
    DXC(!thread_has_token());
    if (!strcmp(m, "anon")) {
        if (!ImpersonateAnonymousToken(GetCurrentThread())) { t_note("ImpersonateAnonymousToken failed err=%lu", GetLastError()); return 77; }
        dx_call_all(&g_a, "anonymous");
        DXC(RevertToSelf());
    } else if (!strcmp(m, "nested")) {
        if (!ImpersonateSelf(SecurityImpersonation)) return 77;
        if (!ImpersonateSelf(SecurityIdentification)) { RevertToSelf(); return 77; }
        dx_call_all(&g_a, "nested-impersonation");
        DXC(RevertToSelf());
        DXC(!thread_has_token());              /* one RevertToSelf clears the whole stack of ImpersonateSelf */
        dx_call_all(&g_a, "after-revert");
    } else if (!strcmp(m, "repeat")) {
        for (int i = 0; i < 25; i++) {
            if (!ImpersonateSelf(SecurityImpersonation)) return 77;
            BOOL b = 0x7777; DXC(g_a.iuv(&b) == 0); DXC(b != 0x7777);
            DXC(g_a.ver() <= 2);
            DXC(RevertToSelf());
        }
        DXC(!thread_has_token());
    } else if (!strcmp(m, "revert_between")) {
        for (int i = 0; i < 10; i++) {
            if (!ImpersonateSelf(SecurityImpersonation)) return 77;
            dx_call_all(&g_a, "impersonated");
            DXC(RevertToSelf());
            dx_call_all(&g_a, "reverted");
        }
    } else {
        if (!ImpersonateSelf(lvl)) { t_note("ImpersonateSelf(%d) failed err=%lu", (int)lvl, GetLastError()); return 77; }
        DXC(thread_has_token());
        dx_call_all(&g_a, m);
        /* the calls must not drop or replace our impersonation */
        int still = thread_has_token();
        t_note("%s: impersonation token still on thread after calls: %d", m, still);
        DXC(RevertToSelf());
        DXC(!thread_has_token());
    }
    int leaked = thread_has_token();
    if (leaked) t_note("%s: thread holds an impersonation token after the sequence", m);
    return dx_rc();
}
static void imp_variant(const char *m) {
    char b[64]; DWORD rc = t_run_child("dx_imp", m, 90000);
    if (rc == 77) { t_skip("impersonation variant not available here"); return; }
    t_check(rc == 0, __FILE__, __LINE__, "dx_imp child exit 0", "%s", dx_rc_text(rc, b, sizeof b));
}
TEST(dx_imp_self_impersonation)   { DX_REQ_ALL(); imp_variant("self"); }
TEST(dx_imp_self_identification)  { DX_REQ_ALL(); imp_variant("ident"); }
TEST(dx_imp_self_delegation)      { DX_REQ_ALL(); imp_variant("deleg"); }
TEST(dx_imp_anonymous_token)      { DX_REQ_ALL(); imp_variant("anon"); }
TEST(dx_imp_nested_then_single_revert) { DX_REQ_ALL(); imp_variant("nested"); }
TEST(dx_imp_repeat_25)            { DX_REQ_ALL(); imp_variant("repeat"); }
TEST(dx_imp_revert_between_calls) { DX_REQ_ALL(); imp_variant("revert_between"); }

static DWORD WINAPI imp_worker(LPVOID p) {
    if (!ImpersonateSelf(SecurityImpersonation)) return 77;
    dx_call_all(&g_a, "imp-thread");
    RevertToSelf();
    return 0;
}
CHILD(dx_imp_mixed) {      /* one impersonating thread and one plain thread running at the same time */
    if (!dx_resolve(&g_a)) return 97;
    HANDLE h = CreateThread(NULL, 0, imp_worker, NULL, 0, NULL);
    for (int i = 0; i < 20; i++) dx_call_all(&g_a, "plain-thread");
    if (WaitForSingleObject(h, 60000) != WAIT_OBJECT_0) TerminateProcess(GetCurrentProcess(), 99);
    DWORD ec = 0; GetExitCodeThread(h, &ec); CloseHandle(h);
    return ec == 77 ? 77 : dx_rc();
}
TEST(dx_imp_concurrent_impersonated_and_plain_threads) {
    DX_REQ_ALL();
    DWORD rc = t_run_child("dx_imp_mixed", "", 120000);
    if (rc == 77) { t_skip("ImpersonateSelf unavailable"); return; }
    CHECKF(rc == 0, "child rc 0x%lx", rc);
}

/* ---------------- restricted / low-integrity token child ---------------- */
CHILD(dx_tokchild) {
    if (!dx_resolve(&g_a)) return 97;
    HANDLE t = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        BYTE buf[256]; DWORD n = 0;
        if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof buf, &n)) {
            PSID sid = ((TOKEN_MANDATORY_LABEL *)buf)->Label.Sid;
            t_note("child integrity RID 0x%lx", (unsigned long)*GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1));
        }
        BOOL restricted = IsTokenRestricted(t);
        t_note("child token restricted=%d", (int)restricted);
        CloseHandle(t);
    }
    dx_call_all(&g_a, "restricted-child");
    return dx_rc();
}
/* variant: 0 DISABLE_MAX_PRIVILEGE, 1 + low integrity, 2 SANDBOX_INERT, 3 DISABLE_MAX_PRIVILEGE|SANDBOX_INERT + low integrity, 4 LUA_TOKEN */
static void token_variant(int variant) {
    HANDLE tok = NULL, rt = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &tok)) { t_skip("OpenProcessToken failed err=%lu", GetLastError()); return; }
    DWORD flags = variant == 0 ? DISABLE_MAX_PRIVILEGE : variant == 1 ? DISABLE_MAX_PRIVILEGE : variant == 2 ? SANDBOX_INERT : variant == 3 ? (DISABLE_MAX_PRIVILEGE | SANDBOX_INERT) : LUA_TOKEN;
    BOOL ok = CreateRestrictedToken(tok, flags, 0, NULL, 0, NULL, 0, NULL, &rt);
    CloseHandle(tok);
    if (!ok) { t_skip("CreateRestrictedToken failed err=%lu", GetLastError()); return; }
    if (variant == 1 || variant == 3) {
        BYTE sidbuf[SECURITY_MAX_SID_SIZE]; DWORD sz = sizeof sidbuf;
        if (!CreateWellKnownSid(WinLowLabelSid, NULL, sidbuf, &sz)) { CloseHandle(rt); t_skip("low label SID unavailable"); return; }
        TOKEN_MANDATORY_LABEL tml; tml.Label.Attributes = SE_GROUP_INTEGRITY; tml.Label.Sid = sidbuf;
        if (!SetTokenInformation(rt, TokenIntegrityLevel, &tml, sizeof tml + sz)) { t_skip("cannot lower integrity err=%lu", GetLastError()); CloseHandle(rt); return; }
    }
    HANDLE rd = NULL, wr = NULL; SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    if (!CreatePipe(&rd, &wr, &sa, 65536)) { CloseHandle(rt); t_skip("CreatePipe failed"); return; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    char cmd[1024]; STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si; si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = NULL; si.hStdOutput = wr; si.hStdError = wr;
    memset(&pi, 0, sizeof pi);
    snprintf(cmd, sizeof cmd, "\"%s\" --child dx_tokchild", t_self_path());
    if (!CreateProcessAsUserA(rt, NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD e = GetLastError();
        t_skip("CreateProcessAsUser failed err=%lu (privilege or environment)", e);
        CloseHandle(rd); CloseHandle(wr); CloseHandle(rt); return;
    }
    CloseHandle(wr); CloseHandle(rt);
    DWORD rc = 0;
    if (WaitForSingleObject(pi.hProcess, 90000) != WAIT_OBJECT_0) { TerminateProcess(pi.hProcess, 1); WaitForSingleObject(pi.hProcess, 5000); rc = 0xDEAD0001; }
    else GetExitCodeProcess(pi.hProcess, &rc);
    char out[8192]; DWORD got = 0, avail = 0;
    if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail) ReadFile(rd, out, avail < sizeof out - 1 ? avail : sizeof out - 1, &got, NULL);
    out[got] = 0;
    for (char *l = strtok(out, "\r\n"); l; l = strtok(NULL, "\r\n")) t_note("variant %d child: %s", variant, l);
    CloseHandle(rd); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (rc == 0xC0000142 || rc == 0xC0000022) { t_note("variant %d: child could not start in this environment (0x%08lx)", variant, rc); return; }
    char b[64];
    t_check(rc == 0, __FILE__, __LINE__, "restricted child exit 0", "%s", dx_rc_text(rc, b, sizeof b));
}
TEST(dx_token_disable_max_privilege)             { DX_REQ_ALL(); token_variant(0); }
TEST(dx_token_disable_max_privilege_low_integrity) { DX_REQ_ALL(); token_variant(1); }
TEST(dx_token_sandbox_inert)                     { DX_REQ_ALL(); token_variant(2); }
TEST(dx_token_dmp_sandbox_inert_low_integrity)   { DX_REQ_ALL(); token_variant(3); }
TEST(dx_token_lua_token)                         { DX_REQ_ALL(); token_variant(4); }

/* ---------------- no console / no interactive desktop ---------------- */
CHILD(dx_plain) {          /* just the call set; used with unusual creation flags */
    if (!dx_resolve(&g_a)) return 97;
    dx_call_all(&g_a, "plain");
    return dx_rc();
}
static void flags_variant(DWORD flags, const char *label) {
    char b[64]; DWORD rc = dx_run_flags("dx_plain", "", flags, 90000);
    t_check(rc == 0, __FILE__, __LINE__, label, "%s", dx_rc_text(rc, b, sizeof b));
}
TEST(dx_proc_detached_no_console)   { DX_REQ_ALL(); flags_variant(DETACHED_PROCESS, "DETACHED_PROCESS child exit 0"); }
TEST(dx_proc_create_no_window)      { DX_REQ_ALL(); flags_variant(CREATE_NO_WINDOW, "CREATE_NO_WINDOW child exit 0"); }
TEST(dx_proc_new_process_group)     { DX_REQ_ALL(); flags_variant(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, "new process group child exit 0"); }
TEST(dx_proc_idle_priority)         { DX_REQ_ALL(); flags_variant(IDLE_PRIORITY_CLASS | CREATE_NO_WINDOW, "idle priority child exit 0"); }
TEST(dx_proc_high_priority)         { DX_REQ_ALL(); flags_variant(ABOVE_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, "above-normal priority child exit 0"); }
TEST(dx_proc_default_error_mode)    { DX_REQ_ALL(); flags_variant(CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW, "default error mode child exit 0"); }

CHILD(dx_nodesk) {         /* private non-interactive window station + desktop (no input desktop) */
    if (!dx_resolve(&g_a)) return 97;
    DWORD sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    HWINSTA ws = USR(CreateWindowStationW)(NULL, 0, WINSTA_ALL_ACCESS, NULL);
    if (!ws) { t_note("CreateWindowStation failed err=%lu", GetLastError()); return 77; }
    HWINSTA old = USR(GetProcessWindowStation)();
    if (!USR(SetProcessWindowStation)(ws)) { t_note("SetProcessWindowStation failed err=%lu", GetLastError()); return 77; }
    HDESK dk = USR(CreateDesktopW)(L"dx_priv", NULL, NULL, 0, GENERIC_ALL, NULL);
    if (!dk) { t_note("CreateDesktop failed err=%lu", GetLastError()); return 77; }
    if (!USR(SetThreadDesktop)(dk)) { t_note("SetThreadDesktop failed err=%lu", GetLastError()); return 77; }
    dx_call_all(&g_a, "private-winsta");
    USR(SetProcessWindowStation)(old);
    return dx_rc();
}
TEST(dx_proc_private_window_station_no_input_desktop) {
    DX_REQ_ALL();
    DWORD sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    if (sid == 0) { t_skip("session 0: window-station switching not meaningful"); return; }
    DWORD rc = t_run_child("dx_nodesk", "", 90000);
    if (rc == 77) { t_skip("could not create a private window station here"); return; }
    char b[64]; t_check(rc == 0, __FILE__, __LINE__, "dx_nodesk child exit 0", "%s", dx_rc_text(rc, b, sizeof b));
}

TEST(dx_env_report) {
    DWORD sid = 0; ProcessIdToSessionId(GetCurrentProcessId(), &sid);
    t_note("session id %lu, SM_REMOTESESSION=%d, SM_SHUTTINGDOWN=%d", sid, GetSystemMetrics(SM_REMOTESESSION), GetSystemMetrics(SM_SHUTTINGDOWN));
    HANDLE t = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION el; DWORD n = 0;
        if (GetTokenInformation(t, TokenElevation, &el, sizeof el, &n)) t_note("token elevated=%lu", el.TokenIsElevated);
        BYTE buf[256];
        if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof buf, &n)) {
            PSID s = ((TOKEN_MANDATORY_LABEL *)buf)->Label.Sid;
            t_note("integrity RID 0x%lx", (unsigned long)*GetSidSubAuthority(s, *GetSidSubAuthorityCount(s) - 1));
        }
        CloseHandle(t);
    }
    HWINSTA ws = USR(GetProcessWindowStation)();
    char nm[128] = "?"; DWORD need = 0;
    if (ws) USR(GetUserObjectInformationA)(ws, UOI_NAME, nm, sizeof nm, &need);
    t_note("window station name '%s'", nm);
    HDESK dk = USR(GetThreadDesktop)(GetCurrentThreadId()); strcpy(nm, "?");
    if (dk) USR(GetUserObjectInformationA)(dk, UOI_NAME, nm, sizeof nm, &need);
    t_note("thread desktop name '%s'", nm);
    if (sid == 0) t_note("running in session 0: interactive-desktop dependent variants are skipped");
    CHECK(1);
}
