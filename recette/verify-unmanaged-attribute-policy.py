#!/usr/bin/env python3
"""DEV/RECETTE ONLY - proves that a user cannot self-edit the tenant binding attributes (tenant_id,
continuum_user_id) through the account REST API, and that continuum-admin tokens still carry them (§4.5).

Creates a throwaway user (random password, in memory only, never printed) in REALM, then:
  1. user token (direct grant, admin-cli of REALM) -> POST /realms/REALM/account/ with forged tenant_id /
     continuum_user_id -> admin read-back: attributes must be unchanged;
  2. browser Code+PKCE login on continuum-admin -> access token must carry the original tenant_id /
     continuum_user_id, aud continuum-admin and acr.
The user is deleted at the end. EXPECT=vulnerable inverts check 1 (control run against an ENABLED realm).

Usage: KC_REALM=recette python -I recette/verify-unmanaged-attribute-policy.py
"""
import base64, hashlib, html, http.cookiejar, json, os, re, secrets, sys
import urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8180")
if not re.match(r"^http://(localhost|127\.0\.0\.1):\d+$", KC):
    sys.exit(f"refusing: {KC} is not a local sim Keycloak")
REALM = os.environ.get("KC_REALM", "recette")
EXPECT = os.environ.get("EXPECT", "protected")
CLIENT, REDIRECT = "continuum-admin", "http://localhost:4201/"
TENANT, CUID = "11111111-1111-1111-1111-111111111111", "44444444-4444-4444-4444-444444444444"
FORGED = "99999999-9999-9999-9999-999999999999"
USERNAME, PASSWORD = "probe.unmanaged", "Pr0be!" + secrets.token_urlsafe(16)
fails = []


def check(cond, label):
    print(("   OK  " if cond else "   KO  ") + label)
    if not cond:
        fails.append(label)


class Stop(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(REDIRECT):
            raise urllib.error.HTTPError(newurl, code, "callback", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class LocalhostSecure(http.cookiejar.DefaultCookiePolicy):
    """Keycloak sets Secure cookies even on http://localhost; browsers treat localhost as a secure context."""
    def return_ok_secure(self, cookie, request):
        return True


def req(method, url, data=None, headers=None, opener=None, form=False):
    headers = dict(headers or {})
    body = None
    if data is not None:
        body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    r = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        resp = (opener or urllib.request.build_opener()).open(r)
        return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


def admin():
    _, _, b = req("POST", f"{KC}/realms/master/protocol/openid-connect/token", {
        "client_id": "admin-cli", "grant_type": "password", "username": os.environ.get("KC_ADMIN", "admin"),
        "password": os.environ.get("KC_ADMIN_PASSWORD", "dev-keycloak-admin")}, form=True)
    return {"Authorization": "Bearer " + json.loads(b)["access_token"]}


def claims(token):
    p = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def attrs(uid):
    _, _, b = req("GET", f"{KC}/admin/realms/{REALM}/users/{uid}", headers=admin())
    a = json.loads(b).get("attributes") or {}
    return a.get("tenant_id"), a.get("continuum_user_id")


ADM = f"{KC}/admin/realms/{REALM}"
_, _, b = req("GET", f"{ADM}/users/profile", headers=admin())
print(f"0) realm {REALM}: unmanagedAttributePolicy = {json.loads(b).get('unmanagedAttributePolicy')}")
_, _, b = req("GET", f"{ADM}/users?username={USERNAME}&exact=true", headers=admin())
for u in json.loads(b):
    req("DELETE", f"{ADM}/users/{u['id']}", headers=admin())
s, h, _ = req("POST", f"{ADM}/users", {
    "username": USERNAME, "enabled": True, "emailVerified": True, "firstName": "Probe", "lastName": "Unmanaged",
    "email": USERNAME + "@verify.invalid", "attributes": {"tenant_id": [TENANT], "continuum_user_id": [CUID]},
    "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}]}, admin())
if s != 201:
    sys.exit(f"create probe user -> {s}")
UID = h["Location"].rsplit("/", 1)[1]
try:
    print("1) account REST self-edit of tenant_id / continuum_user_id")
    s, _, b = req("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", {
        "client_id": "admin-cli", "grant_type": "password", "username": USERNAME, "password": PASSWORD}, form=True)
    if s != 200:
        sys.exit(f"user direct grant -> {s} {b[:200]}")
    U = {"Authorization": "Bearer " + json.loads(b)["access_token"], "Accept": "application/json"}
    s, _, b = req("GET", f"{KC}/realms/{REALM}/account/", headers=U)
    rep = json.loads(b)
    print(f"   GET account -> {s}; attributes visible to the user: {sorted((rep.get('attributes') or {}).keys())}")
    rep["attributes"] = {**(rep.get("attributes") or {}), "tenant_id": [FORGED], "continuum_user_id": [FORGED]}
    s, _, b = req("POST", f"{KC}/realms/{REALM}/account/", rep, U)
    print(f"   POST account (forged) -> {s} {b[:160]}")
    after = attrs(UID)
    if EXPECT == "vulnerable":
        check(after == ([FORGED], [FORGED]), "control: self-edit took effect (realm is vulnerable)")
    else:
        check(after == ([TENANT], [CUID]), f"self-edit had no effect (admin read-back {after})")

    print(f"2) {CLIENT} Code+PKCE login -> claims")
    jar = http.cookiejar.CookieJar(policy=LocalhostSecure())
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), Stop())
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"client_id": CLIENT, "response_type": "code", "scope": "openid",
                                "redirect_uri": REDIRECT, "state": secrets.token_hex(8),
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    s, _, page = req("GET", f"{KC}/realms/{REALM}/protocol/openid-connect/auth?{q}", opener=op)
    action = html.unescape(re.search(r'action="([^"]+)"', page).group(1))
    s, h, page = req("POST", action, {"username": USERNAME, "password": PASSWORD, "credentialId": ""}, opener=op, form=True)
    loc = (h or {}).get("Location", "") if s in (301, 302, 303) else ""
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        sys.exit(f"login did not reach {REDIRECT} (status {s}): {re.sub(r'<[^>]+>', ' ', page)[:300]}")
    s, _, b = req("POST", f"{KC}/realms/{REALM}/protocol/openid-connect/token", {
        "client_id": CLIENT, "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
        "code_verifier": verifier}, form=True)
    c = claims(json.loads(b)["access_token"])
    aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
    check(c.get("tenant_id") == TENANT, f"tenant_id claim = original ({c.get('tenant_id')})")
    check(c.get("continuum_user_id") == CUID, f"continuum_user_id claim = original ({c.get('continuum_user_id')})")
    check(CLIENT in aud, f"aud contains {CLIENT}")
    check(c.get("acr") is not None, f"acr present ({c.get('acr')})")
finally:
    req("DELETE", f"{ADM}/users/{UID}", headers=admin())
    print("3) probe user deleted")

print("RESULT:", "PASS" if not fails else f"FAIL ({len(fails)}): {fails}")
sys.exit(1 if fails else 0)
