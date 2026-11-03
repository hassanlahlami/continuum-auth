#!/usr/bin/env python3
"""Apply the realm security baseline (realms/continuum-realm-security.fragment.json) to realms of the LOCAL sim
Keycloak through the admin REST API, then verify it end to end. Idempotent.

Applied: brute-force detection settings (PUT /admin/realms/{realm}, partial representation) and the CONFIGURE_TOTP
required action (enabled, defaultAction as in the fragment; registered first if missing).
Verified with a throwaway user (random password, never printed, always deleted) through the realm's public
`admin-cli` client (direct grant):
  1. realm representation and required action match the fragment;
  2. OTP required action enforced: user with requiredActions=[CONFIGURE_TOTP] + correct password -> invalid_grant
     "Account is not fully set up";
  3. brute force: failureFactor wrong passwords -> attack-detection reports the user disabled, and the CORRECT
     password is then rejected; the lockout is cleared afterwards.

Usage: KC_ADMIN_PASSWORD=... python -I recette/setup-realm-security.py [--verify-only] REALM [REALM...]
"""
import json, os, re, secrets, sys, time
import urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8180")
if not re.match(r"^http://(localhost|127\.0\.0\.1):\d+$", KC):
    sys.exit(f"refusing: {KC} is not a local sim Keycloak")
HERE = os.path.dirname(os.path.abspath(__file__))
FRAGMENT = json.load(open(os.path.join(os.path.dirname(HERE), "realms", "continuum-realm-security.fragment.json"), encoding="utf-8"))
REALM_SETTINGS = {k: v for k, v in FRAGMENT.items() if k not in ("_comment", "requiredActions")}
ACTIONS = FRAGMENT["requiredActions"]
args = [a for a in sys.argv[1:] if not a.startswith("--")]
VERIFY_ONLY = "--verify-only" in sys.argv
if not args:
    sys.exit(__doc__)
fails = []


def check(cond, label):
    print(("   OK  " if cond else "   KO  ") + label)
    if not cond:
        fails.append(label)


def req(method, url, data=None, headers=None, form=False):
    body, h = None, dict(headers or {})
    if data is not None and form:
        body, h["Content-Type"] = urllib.parse.urlencode(data).encode(), "application/x-www-form-urlencoded"
    elif data is not None:
        body, h["Content-Type"] = json.dumps(data).encode(), "application/json"
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, method=method, headers=h))
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def ok(s, b, what):
    if s >= 300:
        sys.exit(f"{what} -> {s}: {b[:300]}")
    return json.loads(b) if b.strip() else None


s, b = req("POST", f"{KC}/realms/master/protocol/openid-connect/token", {
    "client_id": "admin-cli", "grant_type": "password", "username": os.environ.get("KC_ADMIN", "admin"),
    "password": os.environ.get("KC_ADMIN_PASSWORD") or sys.exit("set KC_ADMIN_PASSWORD")}, form=True)
A = {"Authorization": "Bearer " + ok(s, b, "admin token")["access_token"]}


def apply(realm):
    R = f"{KC}/admin/realms/{realm}"
    ok(*req("PUT", R, {"realm": realm, **REALM_SETTINGS}, A), f"{realm} brute-force settings")
    print(f"   = {realm} brute-force settings")
    current = {a["alias"]: a for a in ok(*req("GET", f"{R}/authentication/required-actions", headers=A), "required actions")}
    for want in ACTIONS:
        alias = want["alias"]
        if alias not in current:
            unreg = ok(*req("GET", f"{R}/authentication/unregistered-required-actions", headers=A), "unregistered actions")
            match = [u for u in unreg if u["providerId"] == alias]
            match or sys.exit(f"{realm}: required action provider {alias} not available")
            ok(*req("POST", f"{R}/authentication/register-required-action", {"providerId": alias, "name": match[0]["name"]}, A), f"register {alias}")
            current[alias] = ok(*req("GET", f"{R}/authentication/required-actions/{alias}", headers=A), alias)
        ok(*req("PUT", f"{R}/authentication/required-actions/{alias}", {**current[alias], **want}, A), f"update {alias}")
        print(f"   = {realm} required action {alias} {want}")


def grant(realm, user, pwd):
    s, b = req("POST", f"{KC}/realms/{realm}/protocol/openid-connect/token",
               {"client_id": "admin-cli", "grant_type": "password", "username": user, "password": pwd}, form=True)
    return s, json.loads(b) if b.strip().startswith("{") else {}


def set_actions(R, uid, actions):
    # full representation: a partial PUT may drop profile attributes and add VERIFY_PROFILE
    rep = ok(*req("GET", f"{R}/users/{uid}", headers=A), "get user")
    ok(*req("PUT", f"{R}/users/{uid}", {**rep, "requiredActions": actions}, A), f"set requiredActions {actions}")


def verify(realm):
    R = f"{KC}/admin/realms/{realm}"
    rep = ok(*req("GET", R, headers=A), realm)
    for k, v in REALM_SETTINGS.items():
        check(rep.get(k) == v, f"{realm} {k} = {v} (got {rep.get(k)})")
    for want in ACTIONS:
        s, b = req("GET", f"{R}/authentication/required-actions/{want['alias']}", headers=A)
        got = json.loads(b) if s == 200 else {}
        check(all(got.get(k) == v for k, v in want.items() if k != "alias"), f"{realm} required action {want}")

    user, pwd = "zz-security-check-" + secrets.token_hex(4), secrets.token_urlsafe(18) + "aA1!"
    s, b = req("POST", f"{R}/users", {"username": user, "enabled": True, "emailVerified": True,
                                      "firstName": "Security", "lastName": "Check", "email": user + "@example.invalid",
                                      "credentials": [{"type": "password", "value": pwd, "temporary": False}]}, A)
    ok(s, b, f"{realm} create throwaway user")
    uid = ok(*req("GET", f"{R}/users?exact=true&username={user}", headers=A), "lookup")[0]["id"]
    try:
        s, t = grant(realm, user, pwd)
        check(s == 200, f"{realm} baseline: correct password -> 200 (got {s} {t.get('error_description')})")

        set_actions(R, uid, ["CONFIGURE_TOTP"])
        s, t = grant(realm, user, pwd)
        check(s == 400 and t.get("error") == "invalid_grant" and "not fully set up" in (t.get("error_description") or ""),
              f"{realm} OTP required action enforced -> {s} {t.get('error_description')}")
        set_actions(R, uid, [])

        # attempts spaced beyond quickLoginCheckMilliSeconds so the failureFactor rule (not quick-login) is exercised
        ff, gap = REALM_SETTINGS["failureFactor"], REALM_SETTINGS["quickLoginCheckMilliSeconds"] / 1000 + 0.3
        attack = lambda: ok(*req("GET", f"{R}/attack-detection/brute-force/users/{uid}", headers=A), "attack detection")
        for i in range(ff):
            time.sleep(gap)
            grant(realm, user, "wrong-" + secrets.token_hex(6))
            if i == ff - 2:
                st = attack()
                check(st.get("disabled") is False, f"{realm} brute force: {st.get('numFailures')} failures -> still enabled")
        st = attack()
        check(st.get("disabled") is True and st.get("numFailures") == ff,
              f"{realm} brute force: {st.get('numFailures')} failures -> disabled={st.get('disabled')}")
        s, t = grant(realm, user, pwd)
        check(s in (400, 401) and t.get("error") == "invalid_grant", f"{realm} locked user, correct password -> {s} {t.get('error')}")
        ok(*req("DELETE", f"{R}/attack-detection/brute-force/users/{uid}", headers=A), "clear lockout")
        s, t = grant(realm, user, pwd)
        check(s == 200, f"{realm} lockout cleared, correct password -> {s}")
    finally:
        req("DELETE", f"{R}/attack-detection/brute-force/users/{uid}", headers=A)
        s, _ = req("DELETE", f"{R}/users/{uid}", headers=A)
        print(f"   throwaway user deleted -> {s}")


for realm in args:
    print(f"== {realm}")
    if not VERIFY_ONLY:
        apply(realm)
    verify(realm)
print("FAILED: " + "; ".join(fails) if fails else "ALL OK")
sys.exit(1 if fails else 0)
