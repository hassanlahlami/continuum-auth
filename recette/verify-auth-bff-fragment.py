#!/usr/bin/env python3
"""DEV/RECETTE ONLY - verifies realms/continuum-auth-bff.fragment.json (ADR 0014 / D41) once MERGED into a realm
export (realms/merge-fragments.py), in a throwaway copy `verify-d41-bff` on the LOCAL sim Keycloak (banque-demo and
recette untouched). Drives the real browser login pages (Code+PKCE terminated server-side, like the BFF) and the
direct grant. Random secrets/passwords in memory only, never printed. Realm deleted at the end unless KEEP=1.

Usage: python -I recette/verify-auth-bff-fragment.py [REALM.json]
       (default REALM.json = ../Instructions/infra/simulation/keycloak/realms/banque-demo-realm.json)
"""
import base64, hashlib, hmac, html, http.cookiejar, importlib.util, json, os, re, secrets, struct, sys, time
import urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8180")
if not re.match(r"^http://(localhost|127\.0\.0\.1):\d+$", KC):
    sys.exit(f"refusing: {KC} is not a local sim Keycloak")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REALM_FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "..", "Instructions", "infra", "simulation", "keycloak", "realms", "banque-demo-realm.json")
REALM = "verify-d41-bff"
APP, ADMIN = "continuum-app-bff", "continuum-admin-bff"
APP_CB, ADMIN_CB = "http://localhost:4200/api/auth/callback", "http://localhost:4201/api/auth/callback"
TENANT, CUID = "11111111-1111-1111-1111-111111111111", "33333333-3333-3333-3333-333333333333"
SECRET = {APP: secrets.token_urlsafe(32), ADMIN: secrets.token_urlsafe(32)}
PASSWORD = "Ver1fy!" + secrets.token_urlsafe(16)
SEED = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(20))
fails = []


def check(cond, label):
    print(("   OK  " if cond else "   KO  ") + label)
    if not cond:
        fails.append(label)


def req(method, url, data=None, headers=None, opener=None):
    """dict data = form-encoded, unless headers carry admin Authorization (admin REST = JSON)."""
    body = None
    if isinstance(data, dict) and "Authorization" not in (headers or {}):
        body = urllib.parse.urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    elif data is not None:
        body = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        r = (opener or urllib.request.build_opener()).open(req)
        return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


def admin():
    s, _, b = req("POST", f"{KC}/realms/master/protocol/openid-connect/token", {
        "client_id": "admin-cli", "grant_type": "password", "username": os.environ.get("KC_ADMIN", "admin"),
        "password": os.environ.get("KC_ADMIN_PASSWORD", "dev-keycloak-admin")})
    return {"Authorization": "Bearer " + json.loads(b)["access_token"]}


def claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


USED = set()


def totp(offset=None):
    """offset None = a code not used yet (Keycloak refuses OTP reuse); look-ahead window 1 allows -1..+1."""
    if offset is None:
        for o in (0, 1, -1):
            code = totp(o)
            if code not in USED:
                USED.add(code); return code
        time.sleep(30); return totp()
    c = int(time.time()) // 30 + offset
    h = hmac.new(SEED.encode(), struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


# ---------- build the throwaway realm = realm export + fragment (through merge-fragments.py) ----------
spec = importlib.util.spec_from_file_location("merge_fragments", os.path.join(ROOT, "realms", "merge-fragments.py"))
mf = importlib.util.module_from_spec(spec); spec.loader.exec_module(mf)
realm = json.load(open(REALM_FILE, encoding="utf-8-sig"))
mf.merge(realm, json.load(open(os.path.join(ROOT, "realms", "continuum-auth-bff.fragment.json"), encoding="utf-8")), "bff")
realm["realm"] = REALM; realm.pop("id", None); realm["bruteForceProtected"] = False
realm["otpPolicyType"], realm["otpPolicyPeriod"], realm["otpPolicyLookAheadWindow"] = "totp", 30, 1
for c in realm["clients"]:
    if c["clientId"] in SECRET:
        assert c["secret"].startswith("${KC_"), "secret must stay an env placeholder in the fragment"
        c["secret"] = SECRET[c["clientId"]]
    elif isinstance(c.get("secret"), str) and c["secret"].startswith("${"):
        c["secret"] = secrets.token_urlsafe(24)  # other clients' env placeholders: irrelevant here
pw = {"type": "password", "value": PASSWORD, "temporary": False}
otp = {"type": "otp", "userLabel": "verify", "secretData": json.dumps({"value": SEED}),
       "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA1"})}
user = lambda u, creds: {"username": u, "enabled": True, "email": u + "@verify.invalid", "emailVerified": True,
                         "firstName": "Verify", "lastName": u, "credentials": creds}
realm.setdefault("users", []).extend([user("dsi.admin", [pw, otp]), user("auditor.nootp", [pw])])

A = admin()
print(f"0) reset realm {REALM}"); req("DELETE", f"{KC}/admin/realms/{REALM}", headers=A)
s, _, b = req("POST", f"{KC}/admin/realms", realm, A)
print(f"1) import merged realm -> {s}")
if s != 201:
    sys.exit("import failed: " + b[:400])
s, _, b = req("GET", f"{KC}/admin/realms/{REALM}/users/profile", headers=A)
prof = json.loads(b); prof["unmanagedAttributePolicy"] = "ENABLED"
req("PUT", f"{KC}/admin/realms/{REALM}/users/profile", prof, A)
for u in ("dsi.admin", "auditor.nootp"):
    _, _, b = req("GET", f"{KC}/admin/realms/{REALM}/users?username={u}&exact=true", headers=A)
    rep = json.loads(b)[0]; rep["attributes"] = {"tenant_id": [TENANT], "continuum_user_id": [CUID]}
    req("PUT", f"{KC}/admin/realms/{REALM}/users/{rep['id']}", rep, A)

print("2) realm structure")
_, _, b = req("GET", f"{KC}/admin/realms/{REALM}", headers=A); r = json.loads(b)
_, _, b = req("GET", f"{KC}/admin/realms/{REALM}/authentication/flows", headers=A)
aliases = {f["alias"]: f["id"] for f in json.loads(b)}
check({"browser", "direct grant", "continuum-browser-loa"} <= set(aliases), "built-in flows kept + continuum-browser-loa imported")
check(r.get("browserFlow") == "browser" and r.get("directGrantFlow") == "direct grant", "realm default bindings unchanged")
for cid in (APP, ADMIN):
    _, _, b = req("GET", f"{KC}/admin/realms/{REALM}/clients?clientId={cid}", headers=A); c = json.loads(b)[0]
    check(c.get("authenticationFlowBindingOverrides", {}).get("browser") == aliases.get("continuum-browser-loa"),
          f"{cid}: browser override -> continuum-browser-loa")

TE = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
AUTH = f"{KC}/realms/{REALM}/protocol/openid-connect/auth"


def dg(cid, username, extra=None, secret=None):
    d = {"grant_type": "password", "client_id": cid, "client_secret": secret or SECRET[cid], "username": username,
         "password": PASSWORD, "scope": "openid", **(extra or {})}
    return req("POST", TE, d)


class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if re.match(r"^http://localhost:\d+/api/auth/callback", newurl):
            raise urllib.error.HTTPError(newurl, code, "callback", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class LocalhostSecure(http.cookiejar.DefaultCookiePolicy):
    """Keycloak sets Secure cookies even on http://localhost; browsers treat localhost as a secure context."""
    def return_ok_secure(self, cookie, request):
        return True


def browser():
    jar = http.cookiejar.CookieJar(policy=LocalhostSecure())
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), Stop())


def form_action(page):
    m = re.search(r'<form[^>]*action="([^"]+)"', page)
    return html.unescape(m.group(1)) if m else None


def code_flow(op, cid, cb, username, acr_values=None, pkce=True, otp_offset=None):
    """Runs the login pages like a browser; returns (callback_params | None, last_page, verifier)."""
    verifier = secrets.token_urlsafe(48)
    q = {"client_id": cid, "response_type": "code", "redirect_uri": cb, "scope": "openid", "state": secrets.token_hex(8)}
    if pkce:
        q["code_challenge"] = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q["code_challenge_method"] = "S256"
    if acr_values:
        q["acr_values"] = acr_values
    page = None
    s, h, page = req("GET", AUTH + "?" + urllib.parse.urlencode(q), opener=op)
    for _ in range(4):
        if s in (301, 302, 303) and h.get("Location", "").startswith(cb):
            return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(h["Location"]).query)), page, verifier
        act = form_action(page or "")
        if not act:
            break
        if 'name="password"' in page:
            data = {"username": username, "password": PASSWORD, "credentialId": ""}
        elif 'name="otp"' in page:
            data = {"otp": totp(otp_offset)}
        else:
            break
        s, h, page = req("POST", act, data, opener=op)
    if s in (301, 302, 303) and h.get("Location", "").startswith(cb):
        return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(h["Location"]).query)), page, verifier
    return None, page, verifier


def exchange(cid, cb, code, verifier, secret=None):
    return req("POST", TE, {"grant_type": "authorization_code", "client_id": cid, "client_secret": secret or SECRET[cid],
                             "code": code, "redirect_uri": cb, "code_verifier": verifier})


def token_checks(prefix, body, aud, acr, azp):
    t = json.loads(body); at = t.get("access_token")
    if not at:
        return check(False, f"{prefix}: token issued ({t.get('error')})")
    c = claims(at)
    a = c.get("aud"); a = a if isinstance(a, list) else [a]
    check(aud in a, f"{prefix}: aud contains {aud} ({a})")
    check(c.get("acr") == acr, f"{prefix}: acr={c.get('acr')} (expected {acr})")
    check(c.get("azp") == azp and c.get("tenant_id") == TENANT and c.get("continuum_user_id") == CUID,
          f"{prefix}: azp/tenant_id/continuum_user_id")
    check("realm_access" not in c and "resource_access" not in c and bool(t.get("refresh_token")),
          f"{prefix}: no roles, refresh_token present")


print("3) continuum-app-bff - direct grant (REST login)")
s, _, b = dg(APP, "dsi.admin"); check(json.loads(b).get("error") == "invalid_grant", "OTP user without OTP refused")
s, _, b = dg(APP, "dsi.admin", {"otp": totp()}); token_checks("password+OTP", b, "continuum-app", "1", APP)
s, _, b = dg(APP, "auditor.nootp"); token_checks("no-OTP user, password only", b, "continuum-app", "1", APP)
s, _, _ = dg(APP, "auditor.nootp", secret="wrong"); check(s == 401, f"wrong client secret -> {s}")

print("4) continuum-app-bff - Code+PKCE terminated by the BFF callback, then step-up acr 2")
op = browser()
cb, page, v = code_flow(op, APP, APP_CB, "dsi.admin")
check(bool(cb and cb.get("code")), "LoA1 login (password only, no OTP asked) -> code at callback")
if cb and cb.get("code"):
    s, _, b = exchange(APP, APP_CB, cb["code"], "x" * 50); check(json.loads(b).get("error") == "invalid_grant", "wrong code_verifier refused")
cb, page, v = code_flow(op, APP, APP_CB, "dsi.admin")
if cb and cb.get("code"):
    s, _, b = exchange(APP, APP_CB, cb["code"], v, secret="wrong"); check(s == 401, f"code exchange with wrong secret -> {s}")
cb, page, v = code_flow(op, APP, APP_CB, "dsi.admin")
if cb and cb.get("code"):
    _, _, b = exchange(APP, APP_CB, cb["code"], v); token_checks("code flow LoA1", b, "continuum-app", "1", APP)
cb, page, v = code_flow(op, APP, APP_CB, "dsi.admin", acr_values="2")
check(bool(cb and cb.get("code")), "step-up acr_values=2 in same session (OTP only) -> code")
if cb and cb.get("code"):
    _, _, b = exchange(APP, APP_CB, cb["code"], v); token_checks("step-up", b, "continuum-app", "2", APP)
cb, page, v = code_flow(browser(), APP, APP_CB, "dsi.admin", pkce=False)
check(bool(cb and cb.get("error")) and not cb.get("code"), f"no PKCE -> error at callback ({cb and cb.get('error')})")
s, _, _ = req("GET", AUTH + "?" + urllib.parse.urlencode({"client_id": APP, "response_type": "code", "scope": "openid",
           "redirect_uri": "http://evil.invalid/api/auth/callback"}))
check(s == 400, f"unregistered redirect_uri -> {s}")

print("5) continuum-admin-bff - direct grant (acr 1, directive #4691) + Code+PKCE always acr 2")
s, _, b = dg(ADMIN, "dsi.admin"); check(json.loads(b).get("error") == "invalid_grant", "admin DG: OTP user without OTP refused")
s, _, b = dg(ADMIN, "dsi.admin", {"otp": totp()}); token_checks("admin DG password+OTP", b, "continuum-admin", "1", ADMIN)
s, _, _ = dg(ADMIN, "dsi.admin", {"otp": totp()}, secret="wrong"); check(s == 401, f"admin DG wrong client secret -> {s}")
op = browser()
cb, page, v = code_flow(op, ADMIN, ADMIN_CB, "dsi.admin")
check(bool(cb and cb.get("code")), "login without acr_values -> password + OTP -> code")
if cb and cb.get("code"):
    _, _, b = exchange(ADMIN, ADMIN_CB, cb["code"], v); token_checks("admin code flow", b, "continuum-admin", "2", ADMIN)
    s, _, b = exchange(ADMIN, ADMIN_CB, cb["code"], v); check(s == 400, f"code replay refused -> {s}")
# ADR 0014 addendum b: /authorize?app=admin and /step-up?app=admin&acr=2 send acr_values=2 to the admin client; the
# BFF refreshes transparently, so the refreshed token must keep aud=continuum-admin and acr=2.
for cbu in (ADMIN_CB, "http://localhost:4202/api/auth/callback"):
    cb, page, v = code_flow(browser(), ADMIN, cbu, "dsi.admin", acr_values="2")
    check(bool(cb and cb.get("code")), f"addendum b: acr_values=2 via {cbu} -> password + OTP -> code")
    if cb and cb.get("code"):
        _, _, b = exchange(ADMIN, cbu, cb["code"], v); token_checks("addendum b step-up", b, "continuum-admin", "2", ADMIN)
        rt = json.loads(b).get("refresh_token")
        _, _, b = req("POST", TE, {"grant_type": "refresh_token", "client_id": ADMIN, "client_secret": SECRET[ADMIN],
                                   "refresh_token": rt})
        token_checks("addendum b refreshed", b, "continuum-admin", "2", ADMIN)
cb, page, v = code_flow(browser(), ADMIN, ADMIN_CB, "dsi.admin", otp_offset=-20)
check(not (cb and cb.get("code")), "wrong OTP -> no code")
cb, page, v = code_flow(browser(), ADMIN, ADMIN_CB, "auditor.nootp")
check(not (cb and cb.get("code")) and "totp" in (page or "").lower(), "user without OTP -> OTP enrolment page, no code")
s, _, _ = req("GET", AUTH + "?" + urllib.parse.urlencode({"client_id": ADMIN, "response_type": "code", "scope": "openid",
           "redirect_uri": APP_CB}))
check(s == 400, f"app callback on admin client -> {s}")

if os.environ.get("KEEP") == "1":
    print(f"realm {REALM} kept (KEEP=1)")
else:
    req("DELETE", f"{KC}/admin/realms/{REALM}", headers=admin())
print("ALL OK" if not fails else f"FAILED ({len(fails)})")
sys.exit(1 if fails else 0)
