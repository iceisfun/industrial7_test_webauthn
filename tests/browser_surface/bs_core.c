/* Guarded-page probe child and the extent search. See bs.h. */
#include "bs.h"
#include <stdlib.h>

const unsigned bs_mc_end[10] = { 0, 0x3c, 0x48, 0x50, 0x5c, 0x60, 0x64, 0x80, 0x9c, 0xc8 };
const unsigned bs_ga_end[10] = { 0, 0x34, 0x48, 0x50, 0x58, 0x68, 0x74, 0x90, 0xa0, 0xc8 };

HMODULE bs_dll(void) { return t_module(BS_MOD); }

#define BS_XC_NO_EXPORT 0xBAD00002u
#define BS_XC_BAD_ARGS  0xBAD00003u
#define BS_XC_NOT_RESET 0xBAD00005u

/* ---- child ---- */
static BYTE *g_page;      /* two pages: [0] committed read/write, [1] PAGE_NOACCESS */
static BYTE *g_obj;       /* start of the object under test */

static LONG CALLBACK probe_veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    ULONG_PTR a = ep->ExceptionRecord->ExceptionInformation[1];
    DWORD off = 0xFFFF;
    if (g_obj && a >= (ULONG_PTR)g_obj && a < (ULONG_PTR)g_obj + 0x2000) off = (DWORD)(a - (ULONG_PTR)g_obj);
    TerminateProcess(GetCurrentProcess(), 0xFA170000u | off);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Copy min(imgsz, S) bytes of img to the end of the committed page, leaving S readable bytes. */
static void *place(const void *img, size_t imgsz, int S) {
    if (!g_page) {
        g_page = VirtualAlloc(NULL, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        DWORD old;
        if (!g_page || !VirtualProtect(g_page + 0x1000, 0x1000, PAGE_NOACCESS, &old)) ExitProcess(BS_XC_BAD_ARGS);
    }
    memset(g_page, 0, 0x1000);
    g_obj = g_page + 0x1000 - S;
    if (S > 0) memcpy(g_obj, img, imgsz < (size_t)S ? imgsz : (size_t)S);
    return g_obj;
}

const WCHAR *const bs_ext_ids[BS_NEXT] = {
    L"hmac-secret", L"credProtect", L"credBlob", L"minPinLength", L"largeBlob", L"prf", L"credProps",
    L"appid", L"uvm", L"hmac-secret-mc", L"devicePubKey", L"unknownExtension",
};

typedef HWND (WINAPI *pGetDesktopWindow_t)(void);
static HWND any_hwnd(void) {
    HMODULE u = LoadLibraryA("user32.dll");
    pGetDesktopWindow_t g = u ? (pGetDesktopWindow_t)GetProcAddress(u, "GetDesktopWindow") : NULL;
    return g ? g() : (HWND)(ULONG_PTR)0x10010;
}

static BYTE g_json[128];
static BYTE g_userid[16];
static BYTE g_credid[32];
static GUID g_cancel = { 0x6b29fc40, 0xca47, 0x1067, { 0xb3, 0x1d, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda } };

static BS_MC_OPTIONS g_mo;
static BS_GA_OPTIONS g_go;
static BS_CRED g_leg[1];
static BS_CRED_EX g_ex[1];
static BS_CRED_EX *g_exp[1];
static BS_CRED_LIST g_list;
static BS_EXTENSION g_extn[1];

static int run_make(const char *kind, DWORD ver, int mode, int S) {
    static const char *js = "{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://example.com\"}";
    memcpy(g_json, js, strlen(js));
    for (int i = 0; i < 16; i++) g_userid[i] = (BYTE)(i * 7 + 1);
    for (int i = 0; i < 32; i++) g_credid[i] = (BYTE)(0xA0 + i);

    BS_RP rp = { 1, L"example.com", L"Example RP", NULL };
    BS_USER user = { 1, 16, g_userid, L"alice@example.com", NULL, L"Alice" };
    BS_COSE_PARAM cp[2] = { { 1, L"public-key", -7 }, { 1, L"public-key", -257 } };
    BS_COSE_PARAMS cose = { 1, cp };
    BS_CLIENT_DATA cd = { 1, (DWORD)strlen(js), g_json, L"SHA-256" };
    const BS_RP *prp = &rp; const BS_USER *puser = &user; const BS_CLIENT_DATA *pcd = &cd; const BS_MC_OPTIONS *popts = NULL;

    /* Two independent local rejections so the call cannot reach the service even if one is accepted on some
     * build: (1) a COSE parameter with algorithm 0, (2) a zero-length credential id in the exclude list. */
    int is_opts = !strcmp(kind, "opts");
    cp[0].lAlg = 0;
    g_ex[0] = (BS_CRED_EX){ 1, 0, g_credid, L"public-key", 0 };
    g_exp[0] = &g_ex[0];
    g_list.cCredentials = 1; g_list.ppCredentials = g_exp;
    g_leg[0] = (BS_CRED){ 1, 0, g_credid, L"public-key" };

    g_mo.dwTimeoutMilliseconds = 30000;
    g_mo.pCancellationId = &g_cancel;

    if (!strcmp(kind, "rp")) { rp.dwVersion = ver; prp = place(&rp, sizeof rp, S); }
    else if (!strcmp(kind, "user")) { user.dwVersion = ver; puser = place(&user, sizeof user, S); }
    else if (!strcmp(kind, "cd")) { cd.dwVersion = ver; pcd = place(&cd, sizeof cd, S); }
    else if (!strcmp(kind, "cosep")) {
        cp[0].dwVersion = ver;   /* element read through the guarded copy */
        BS_COSE_PARAM *pg = place(&cp[0], sizeof cp[0], S);
        cose.pCredentialParameters = pg;
    }
    else if (is_opts) {
        g_mo.dwVersion = ver;
        if (ver <= 2) { g_mo.CredentialList.cCredentials = 1; g_mo.CredentialList.pCredentials = g_leg; }
        else { g_mo.pExcludeCredentialList = &g_list; }
        popts = place(&g_mo, sizeof g_mo, S);
    }
    else if (!strcmp(kind, "credex")) {
        g_ex[0] = (BS_CRED_EX){ ver, 0, g_credid, L"public-key", 0 };
        g_exp[0] = place(&g_ex[0], sizeof g_ex[0], S);
        g_list.cCredentials = 1; g_list.ppCredentials = g_exp;
        g_mo.dwVersion = 4; g_mo.pExcludeCredentialList = &g_list; popts = &g_mo;
    }
    else if (!strcmp(kind, "browser")) {
        /* the shape a browser integration builds: every field its options version has, cancellation id from the
         * DLL, an exclude list, extensions, hints, PRF salts; the two local faults still end the call locally */
        static BS_CRED_EX ex2[2]; static BS_CRED_EX *exp2[2]; static BS_CRED_LIST l2;
        static BS_EXTENSION ex_[2]; static DWORD cprot[2] = { 2, 1 }; static DWORD hmac = 1;
        static LPCWSTR hints[2] = { L"security-key", L"hybrid" };
        static BS_HMAC_SALT salt; static BYTE s1[32], s2[32];
        WebAuthNGetCancellationId_pfn gc = UN(WebAuthNGetCancellationId);
        if (gc) gc(&g_cancel);
        for (int i = 0; i < 2; i++) { ex2[i] = (BS_CRED_EX){ 1, i ? 32 : 0, g_credid, L"public-key", 1u << i }; exp2[i] = &ex2[i]; }
        l2.cCredentials = 2; l2.ppCredentials = exp2;
        g_mo.CredentialList.cCredentials = 1; g_mo.CredentialList.pCredentials = g_leg;   /* legacy form, options v1/v2 */
        ex_[0] = (BS_EXTENSION){ L"credProtect", 8, cprot }; ex_[1] = (BS_EXTENSION){ L"hmac-secret", 4, &hmac };
        salt.cbFirst = 32; salt.pbFirst = s1; salt.cbSecond = 32; salt.pbSecond = s2;
        g_mo.dwVersion = ver; g_mo.dwTimeoutMilliseconds = 60000;
        g_mo.Extensions.cExtensions = 2; g_mo.Extensions.pExtensions = ex_;
        g_mo.dwAuthenticatorAttachment = 1; g_mo.bRequireResidentKey = 1; g_mo.dwUserVerificationRequirement = 2; g_mo.dwAttestationConveyancePreference = 2;
        g_mo.pExcludeCredentialList = &l2; g_mo.dwEnterpriseAttestation = 0; g_mo.dwLargeBlobSupport = 2; g_mo.bPreferResidentKey = 1;
        g_mo.bBrowserInPrivateMode = 1; g_mo.bEnablePrf = 1; g_mo.pPRFGlobalEval = &salt;
        g_mo.cCredentialHints = 2; g_mo.ppwszCredentialHints = hints; g_mo.pwszRemoteWebOrigin = L"https://example.com";
        popts = &g_mo;
    }
    else if (!strcmp(kind, "ext")) {
        if (ver >= BS_NEXT) return BS_XC_BAD_ARGS;
        void *pv = place(g_credid, sizeof g_credid, S);
        g_extn[0].pwszExtensionIdentifier = bs_ext_ids[ver]; g_extn[0].cbExtension = 16; g_extn[0].pvExtension = pv;
        g_mo.dwVersion = 1; g_mo.Extensions.cExtensions = 1; g_mo.Extensions.pExtensions = g_extn;
        g_mo.CredentialList.cCredentials = 1; g_mo.CredentialList.pCredentials = g_leg;   /* legacy form, options v1 */
        popts = &g_mo;
    }
    else return BS_XC_BAD_ARGS;

    /* kinds whose structure is probed directly (rp/user/cd/cosep) leave options NULL; give them a minimal
     * v4 options carrying the bad exclude list so the second fault is present there too. */
    if (!popts) { g_mo.dwVersion = 4; g_mo.pExcludeCredentialList = &g_list; popts = &g_mo; }

    WebAuthNAuthenticatorMakeCredential_pfn fn = UN(WebAuthNAuthenticatorMakeCredential);
    if (!fn) return BS_XC_NO_EXPORT;
    PVOID att = (PVOID)(ULONG_PTR)1;
    HRESULT hr = fn(any_hwnd(), prp, puser, &cose, pcd, popts, &att);
    if (!strcmp(kind, "browser") && att != NULL) return (int)BS_XC_NOT_RESET;
    return (int)hr;
}

static int run_get(const char *kind, DWORD ver, int mode, int S) {
    static const char *js = "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://example.com\"}";
    memcpy(g_json, js, strlen(js));
    for (int i = 0; i < 32; i++) g_credid[i] = (BYTE)(0xA0 + i);
    static const WCHAR bad_rp[2] = { 0xD800, 0 };   /* lone high surrogate */
    LPCWSTR rpid = L"example.com";
    BS_CLIENT_DATA cd = { 1, (DWORD)strlen(js), g_json, L"SHA-256" };
    const BS_CLIENT_DATA *pcd = &cd; const BS_GA_OPTIONS *popts = NULL;
    int is_opts = !strcmp(kind, "opts");
    /* Two independent local rejections so the call cannot reach the service even if one is accepted on some
     * build: (1) a lone-surrogate relying-party id, (2) a zero-length credential id in the allow list. */
    rpid = bad_rp;
    g_ex[0] = (BS_CRED_EX){ 1, 0, g_credid, L"public-key", 0 };
    g_exp[0] = &g_ex[0];
    g_list.cCredentials = 1; g_list.ppCredentials = g_exp;
    g_leg[0] = (BS_CRED){ 1, 0, g_credid, L"public-key" };

    g_go.dwTimeoutMilliseconds = 30000;
    g_go.pCancellationId = &g_cancel;

    if (!strcmp(kind, "cd")) { cd.dwVersion = ver; pcd = place(&cd, sizeof cd, S); g_go.dwVersion = 4; g_go.pAllowCredentialList = &g_list; popts = &g_go; }
    else if (is_opts) {
        g_go.dwVersion = ver;
        if (ver <= 3) { g_go.CredentialList.cCredentials = 1; g_go.CredentialList.pCredentials = g_leg; }
        else { g_go.pAllowCredentialList = &g_list; }
        popts = place(&g_go, sizeof g_go, S);
    }
    else if (!strcmp(kind, "cred")) {
        BS_CRED c = { ver, 0, g_credid, L"public-key" };
        g_go.dwVersion = 3; g_go.CredentialList.cCredentials = 1; g_go.CredentialList.pCredentials = place(&c, sizeof c, S); popts = &g_go;
    }
    else if (!strcmp(kind, "credex")) {
        g_ex[0] = (BS_CRED_EX){ ver, 0, g_credid, L"public-key", 0 };
        g_exp[0] = place(&g_ex[0], sizeof g_ex[0], S);
        g_list.cCredentials = 1; g_list.ppCredentials = g_exp;
        g_go.dwVersion = 4; g_go.pAllowCredentialList = &g_list; popts = &g_go;
    }
    else if (!strcmp(kind, "browser")) {
        static BS_CRED_EX ex2[2]; static BS_CRED_EX *exp2[2]; static BS_CRED_LIST l2;
        static LPCWSTR hints[1] = { L"client-device" }; static BOOL used_appid = 0x55;
        WebAuthNGetCancellationId_pfn gc = UN(WebAuthNGetCancellationId);
        if (gc) gc(&g_cancel);
        for (int i = 0; i < 2; i++) { ex2[i] = (BS_CRED_EX){ 1, i ? 32 : 0, g_credid, L"public-key", 0xF }; exp2[i] = &ex2[i]; }
        l2.cCredentials = 2; l2.ppCredentials = exp2;
        g_go.CredentialList.cCredentials = 1; g_go.CredentialList.pCredentials = g_leg;   /* legacy form, options v1..v3 */
        g_go.dwVersion = ver; g_go.dwTimeoutMilliseconds = 60000; g_go.dwUserVerificationRequirement = 2; g_go.dwAuthenticatorAttachment = 0;
        g_go.pwszU2fAppId = L"https://example.com/app-id"; g_go.pbU2fAppId = &used_appid;
        g_go.pAllowCredentialList = &l2; g_go.bBrowserInPrivateMode = 1;
        g_go.cCredentialHints = 1; g_go.ppwszCredentialHints = hints; g_go.pwszRemoteWebOrigin = L"https://example.com";
        popts = &g_go;
    }
    else return BS_XC_BAD_ARGS;

    WebAuthNAuthenticatorGetAssertion_pfn fn = UN(WebAuthNAuthenticatorGetAssertion);
    if (!fn) return BS_XC_NO_EXPORT;
    PVOID as = (PVOID)(ULONG_PTR)1;
    HRESULT hr = fn(any_hwnd(), rpid, pcd, popts, &as);
    if (!strcmp(kind, "browser") && as != NULL) return (int)BS_XC_NOT_RESET;
    return (int)hr;
}

/* child: bs_probe <api> <kind> <ver> <mode> <S> */
CHILD(bs_probe) {
    if (argc < 6) return (int)BS_XC_BAD_ARGS;
    char api = argv[1][0]; const char *kind = argv[2];
    DWORD ver = (DWORD)strtoul(argv[3], NULL, 10); int mode = atoi(argv[4]); int S = atoi(argv[5]);
    AddVectoredExceptionHandler(1, probe_veh);
    return api == 'm' ? run_make(kind, ver, mode, S) : run_get(kind, ver, mode, S);
}

/* ---- parent ---- */
DWORD bs_probe(char api, const char *kind, DWORD ver, int mode, int S) {
    char args[160];
    snprintf(args, sizeof args, "%c %s %lu %d %d", api, kind, (unsigned long)ver, mode, S);
    return t_run_child("bs_probe", args, 20000);
}

static int is_nores(DWORD rc) { return rc == 0xDEAD0000u || rc == 0xDEAD0001u || rc == BS_XC_BAD_ARGS || (BS_IS_FAULT(rc) && BS_FAULT_OFF(rc) == 0xFFFF) || (rc & 0xFFFF0000u) == 0xC0000000u; }

static struct memo { char api; char kind[12]; DWORD ver; int mode, maxS; int ext; DWORD hr; } g_memo[512];
static int g_nmemo;

int bs_extent(char api, const char *kind, DWORD ver, int mode, int maxS, DWORD *hr_full) {
    for (int i = 0; i < g_nmemo; i++)
        if (g_memo[i].api == api && !strcmp(g_memo[i].kind, kind) && g_memo[i].ver == ver && g_memo[i].mode == mode && g_memo[i].maxS == maxS) {
            if (hr_full) *hr_full = g_memo[i].hr;
            return g_memo[i].ext;
        }
    DWORD hr = 0; int res;
    DWORD rc = bs_probe(api, kind, ver, mode, maxS);
    if (rc == BS_XC_NO_EXPORT) { res = BS_X_NO_EXPORT; }
    else if (is_nores(rc)) { res = BS_X_NO_RESULT; hr = rc; }
    else if (BS_IS_FAULT(rc)) { res = BS_X_FAULT_AT_MAX; hr = rc; }
    else {
        hr = rc;
        int lo = 0, hi = maxS / 4, bad = 0;   /* smallest k such that S = 4k returns normally */
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            DWORD r = bs_probe(api, kind, ver, mode, mid * 4);
            if (is_nores(r)) { bad = 1; break; }
            if (BS_IS_FAULT(r)) lo = mid + 1; else hi = mid;
        }
        res = bad ? BS_X_NO_RESULT : lo * 4;
    }
    if (g_nmemo < 512) {
        struct memo *m = &g_memo[g_nmemo++];
        m->api = api; snprintf(m->kind, sizeof m->kind, "%s", kind); m->ver = ver; m->mode = mode; m->maxS = maxS; m->ext = res; m->hr = hr;
    }
    if (hr_full) *hr_full = hr;
    return res;
}
