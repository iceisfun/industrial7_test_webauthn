#include "ga.h"

UDECL(HRESULT, WebAuthNAuthenticatorGetAssertion, (HWND, LPCWSTR, const GA_CLIENT_DATA *, const GA_OPTIONS *, void **));

static const gacase *g_reg[1024];
static int g_nreg;
void ga_register(const gacase *c) { if (g_nreg < 1024) g_reg[g_nreg++] = c; }

/* ---- parent side ------------------------------------------------------- */
void ga_run(const gacase *c)
{
    if (!UN(WebAuthNAuthenticatorGetAssertion)) { t_skip("missing export: WebAuthNAuthenticatorGetAssertion"); return; }
    DWORD rc = t_run_child("get_assertion_validation_child", c->name, 10000);
    CHECKF(rc != 0xDEAD0001, "child timed out (call did not fail locally)");
    CHECKF(rc != 0xC0DE0004 && rc != 0xC0DE0005, "case %s refused by safety gate (rc 0x%08lx)", c->name, rc);
    CHECKF(rc == GA_OK, "case %s: child rc 0x%08lx (want HRESULT 0x%08lx, GA_OK=0x%08lx)", c->name, rc, c->hr, GA_OK);
}

/* ---- child side -------------------------------------------------------- */
static void *galloc(size_t sz)   /* zeroed block that ends exactly at a PAGE_NOACCESS page */
{
    const size_t page = 4096;
    size_t n = (sz + page - 1) / page;
    char *base = (char *)VirtualAlloc(NULL, (n + 1) * page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!base) return NULL;
    DWORD old;
    VirtualProtect(base + n * page, page, PAGE_NOACCESS, &old);
    return base + n * page - sz;
}

static const wchar_t *rp_string(int m, wchar_t *buf)
{
    switch (m) {
    case RP_NULL: return NULL;
    case RP_EMPTY: return L"";
    case RP_LONG: { int i; for (i = 0; i < 300; i++) buf[i] = L'a'; buf[300] = 0; return buf; }
    case RP_UNICODE: return L"bücher.example";
    case RP_URL: return L"https://example.com";
    case RP_LOCALHOST: return L"localhost";
    case RP_UPPER: return L"EXAMPLE.COM";
    case RP_PORT: return L"example.com:8443";
    case RP_SPACE: return L" ";
    case RP_EMOJI: return L"\xD83D\xDE00.example";
    case RP_DOT: return L".";
    case RP_IP: return L"192.0.2.1";
    case RP_LONE_HIGH: return L"\xD800";
    case RP_LONE_LOW: return L"\xDC00";
    case RP_TRAIL_HIGH: return L"example.com\xD800";
    case RP_LEAD_LOW: return L"\xDC00" L"example.com";
    case RP_TWO_HIGH: return L"\xD800\xD800";
    case RP_LOW_HIGH: return L"\xDC00\xD800";
    case RP_MID_HIGH: return L"exa\xD800mple.com";
    default: return L"example.com";
    }
}
static int rp_invalid_utf16(int m) { return m >= RP_LONE_HIGH; }

static const wchar_t *hash_string(int m)
{
    switch (m) {
    case H_EMPTY: return L"";
    case H_BOGUS: return L"not-a-hash";
    case H_SHA384: return L"SHA-384";
    case H_SHA512: return L"SHA-512";
    case H_SHA1: return L"SHA-1";
    case H_LOWER: return L"sha-256";
    case H_CNG: return L"SHA256";
    case H_MD5: return L"MD5";
    case H_LONG: return L"SHA-256-SHA-256-SHA-256-SHA-256-SHA-256-SHA-256-SHA-256-SHA-256";
    default: return L"SHA-256";
    }
}

static int kinds_fail(const unsigned char *k, int ex)
{
    for (int i = 0; i < 3; i++)
        if (k[i] == K_CB0 || k[i] == K_TYPE_NULL || k[i] == K_TYPE_EMPTY || (ex && k[i] == K_VER0)) return 1;
    return 0;
}
static int kinds_count(const unsigned char *k) { int n = 0; while (n < 3 && k[n]) n++; return n; }

static void fill_cred(GA_CRED_EX *e, int kind, DWORD tr, BYTE *id)
{
    e->dwVersion = 1; e->cbId = 16; e->pbId = id; e->pwszCredentialType = L"public-key"; e->dwTransports = tr;
    switch (kind) {
    case K_VER0: e->dwVersion = 0; break;
    case K_VERMAX: e->dwVersion = 0xFFFFFFFFu; break;
    case K_CB0: e->cbId = 0; break;
    case K_TYPE_NULL: e->pwszCredentialType = NULL; break;
    case K_TYPE_EMPTY: e->pwszCredentialType = L""; break;
    case K_TYPE_SCOPED: e->pwszCredentialType = L"ScopedCred"; break;
    case K_TYPE_BOGUS: e->pwszCredentialType = L"bogus-type"; break;
    case K_TYPE_UPPER: e->pwszCredentialType = L"PUBLIC-KEY"; break;
    }
}

static DWORD opt_size(DWORD ver)
{
    if (ver == 1) return 0x38;
    if (ver == 2) return 0x48;
    if (ver == 3) return 0x50;
    if (ver == 4) return 0x58;
    return 0x80;
}

CHILD(get_assertion_validation_child)
{
    const gacase *c = NULL;
    for (int i = 0; i < g_nreg; i++) if (argc > 1 && !strcmp(g_reg[i]->name, argv[1])) c = g_reg[i];
    if (!c) return (int)0xC0DE0003;
    WebAuthNAuthenticatorGetAssertion_pfn f = UN(WebAuthNAuthenticatorGetAssertion);
    if (!f) return (int)0xC0DE0002;

    DWORD ver = c->ov ? c->ov : 4;
    int struct_opts = (c->om == OM_STRUCT);
    if (c->om == OM_ZERO_VER) ver = 0;

    /* ---- safety gate: refuse unless the call provably fails locally ---- */
    int outer = (c->rp == RP_NULL) || (c->om == OM_ZERO_VER) ||
                c->cd == CD_NULL || c->cd == CD_VER0 || c->cd == CD_CB0 || c->cd == CD_PB_NULL ||
                c->cd == CD_HASH_NULL || c->cd == CD_ZEROED || c->cd == CD_CB0_PB_NULL;
    int ex_used = struct_opts && ver >= 4 && c->ex[0];
    int enc = rp_invalid_utf16(c->rp) ||
              (struct_opts && (ex_used ? kinds_fail(c->ex, 1) : kinds_fail(c->leg, 0)));
    if (!outer && !enc) return (int)0xC0DE0004;
    if ((outer && c->hr != E_GA_PARAM) || (!outer && c->hr != E_GA_DATA)) return (int)0xC0DE0005;

    /* ---- expected result adaptation: the request path needs a fresh activity GUID when no
     *      cancellation id is supplied; if the system cannot create one the call fails with that status ---- */
    DWORD want = c->hr;
    int need_uuid = !outer && !(struct_opts && ver > 2 && c->cancel);
    if (need_uuid) {
        typedef LONG (WINAPI *uuidcreate_fn)(GUID *);
        HMODULE rpc = LoadLibraryA("rpcrt4.dll");
        uuidcreate_fn uc = rpc ? (uuidcreate_fn)GetProcAddress(rpc, "UuidCreate") : NULL;
        GUID g;
        if (uc) { LONG st = uc(&g); if (st != 0) { want = 0x80070000u | ((DWORD)st & 0xFFFF); printf("  CHILD note: UuidCreate status %ld\n", (long)st); } }
    }

    /* ---- client data ---- */
    static const char json_ok[] = "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://example.com\"}";
    GA_CLIENT_DATA cdv; GA_CLIENT_DATA *cdp = &cdv;
    memset(&cdv, 0, sizeof cdv);
    size_t jl = sizeof json_ok - 1;
    BYTE *json = (BYTE *)galloc(jl);
    memcpy(json, json_ok, jl);
    cdv.dwVersion = 1; cdv.cbClientDataJSON = (DWORD)jl; cdv.pbClientDataJSON = json; cdv.pwszHashAlgId = hash_string(c->hash);
    switch (c->cd) {
    case CD_NULL: cdp = NULL; break;
    case CD_VER0: cdv.dwVersion = 0; break;
    case CD_VER2: cdv.dwVersion = 2; break;
    case CD_VERMAX: cdv.dwVersion = 0xFFFFFFFFu; break;
    case CD_CB0: cdv.cbClientDataJSON = 0; break;
    case CD_PB_NULL: cdv.pbClientDataJSON = NULL; break;
    case CD_HASH_NULL: cdv.pwszHashAlgId = NULL; break;
    case CD_ZEROED: memset(&cdv, 0, sizeof cdv); break;
    case CD_CB0_PB_NULL: cdv.cbClientDataJSON = 0; cdv.pbClientDataJSON = NULL; break;
    case CD_CB1: cdv.cbClientDataJSON = 1; cdv.pbClientDataJSON = (BYTE *)galloc(1); cdv.pbClientDataJSON[0] = '{'; break;
    case CD_EMPTY_OBJ: cdv.cbClientDataJSON = 2; cdv.pbClientDataJSON = (BYTE *)galloc(2); memcpy(cdv.pbClientDataJSON, "{}", 2); break;
    case CD_BIG: cdv.cbClientDataJSON = 1u << 20; cdv.pbClientDataJSON = (BYTE *)galloc(1u << 20); memset(cdv.pbClientDataJSON, 'x', 1u << 20); break;
    }

    /* ---- credentials ---- */
    static BYTE ids[3][16];
    for (int i = 0; i < 3; i++) memset(ids[i], 0xA0 + i, 16);
    GA_CRED leg[3]; GA_CRED_EX exs[3]; GA_CRED_EX *exp[3]; GA_CRED_LIST lst;
    memset(leg, 0, sizeof leg); memset(exs, 0, sizeof exs); memset(&lst, 0, sizeof lst);
    int nleg = kinds_count(c->leg), nex = kinds_count(c->ex);
    for (int i = 0; i < nleg; i++) {
        GA_CRED_EX t; fill_cred(&t, c->leg[i], 0, ids[i]);
        leg[i].dwVersion = t.dwVersion ? t.dwVersion : 0; leg[i].cbId = t.cbId; leg[i].pbId = t.pbId; leg[i].pwszCredentialType = t.pwszCredentialType;
    }
    for (int i = 0; i < nex; i++) { fill_cred(&exs[i], c->ex[i], c->tr, ids[i]); exp[i] = &exs[i]; }
    lst.cCredentials = nex; lst.ppCredentials = exp;

    /* ---- options ---- */
    static const GUID cancel_id = { 0x6f1d2c3a, 0x4b5e, 0x4c7d, { 0x8e, 0x9f, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65 } };
    BOOL bsent = 0x5A5A5A5A;
    GA_OPTIONS full; const GA_OPTIONS *optp = NULL;
    memset(&full, 0, sizeof full);
    if (c->om != OM_NONE) {
        full.dwVersion = ver; full.dwTimeoutMilliseconds = c->to;
        full.dwAuthenticatorAttachment = c->at; full.dwUserVerificationRequirement = c->uv; full.dwFlags = c->fl;
        if (nleg) { full.CredentialList.cCredentials = nleg; full.CredentialList.pCredentials = leg; }
        if (c->appid) full.pwszU2fAppId = L"https://example.com/appid.json";
        if (c->b) full.pbU2fAppId = &bsent;
        if (c->cancel) full.pCancellationId = (GUID *)&cancel_id;
        if (nex) full.pAllowCredentialList = &lst;
        DWORD sz = c->osz ? c->osz : (c->om == OM_ZERO_VER ? 0x58 : opt_size(ver));
        void *blk = galloc(sz);
        memcpy(blk, &full, sz < sizeof full ? sz : sizeof full);
        optp = (const GA_OPTIONS *)blk;
    }

    HWND hw = NULL;
    switch (c->hw) {
    case HW_BOGUS: hw = (HWND)(ULONG_PTR)0x12345678; break;
    case HW_DESKTOP: hw = GetDesktopWindow(); break;
    case HW_MINUS1: hw = (HWND)(LONG_PTR)-1; break;
    case HW_ODD: hw = (HWND)(ULONG_PTR)0x1; break;
    }

    wchar_t rpbuf[320];
    void *out = (void *)(ULONG_PTR)0xDEADBEEFDEADBEEFull;
    HRESULT hr = f(hw, rp_string(c->rp, rpbuf), cdp, optp, &out);
    printf("  CHILD %s hr=0x%08lx want=0x%08lx out=%p bool=0x%lx\n", c->name, (unsigned long)hr, (unsigned long)want, out, (unsigned long)bsent);

    if (out != NULL) return (int)0xBAD00001;
    if (c->b == B_UNCHANGED && bsent != 0x5A5A5A5A) return (int)0xBAD00002;
    if (c->b == B_ZEROED && bsent != 0) return (int)0xBAD00003;
    if ((DWORD)hr == want) return (int)GA_OK;
    return (int)hr;
}
