#!/usr/bin/env python3
"""Spike ADR 0014 avenant (c): password journeys on the simulation Keycloak (sim :8180).

Checks, for both BFF confidential clients (continuum-app-bff, continuum-admin-bff):
  1. AIA kc_action=UPDATE_PASSWORD (Code + PKCE S256): password changed, kc_action_status=success,
     code exchangeable with the client secret.
  2. AIA cancel: kc_action_status=cancelled, password unchanged.
  3. Case sensitivity: kc_action=update_password (lower case).
  4. AIA without PKCE (client enforces S256).
  5. Forgot password: resetPasswordAllowed + SMTP (mailpit) -> reset link on the login page,
     e-mail received, link followed, new password accepted, back to the BFF callback.

Sim only: creates a throwaway local user and temporarily sets resetPasswordAllowed/smtpServer on the
realm; everything is restored/deleted in `finally`. No change to realm exports.

Usage: python spike-adr0014c-password-flows.py [--kc http://localhost:8180] [--realm banque-demo]
       [--mailpit http://localhost:8025] [--smtp-host mailpit]
"""
import argparse
import base64
import hmac
import struct
import hashlib
import html
import re
import secrets
import sys
import time
import urllib.parse as up

import requests

p = argparse.ArgumentParser()
p.add_argument("--kc", default="http://localhost:8180")
p.add_argument("--realm", default="banque-demo")
p.add_argument("--mailpit", default="http://localhost:8025")
p.add_argument("--smtp-host", default="mailpit")
p.add_argument("--admin-user", default="admin")
p.add_argument("--admin-password", default="dev-keycloak-admin")
a = p.parse_args()

KC, REALM = a.kc.rstrip("/"), a.realm
OIDC = f"{KC}/realms/{REALM}/protocol/openid-connect"
ADM = f"{KC}/admin/realms/{REALM}"
USER = "adr14c-probe"
EMAIL = "adr14c-probe@banque-demo.local"
CLIENTS = ["continuum-app-bff", "continuum-admin-bff"]
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


_tok = {"v": None, "at": 0.0}


def H():
    """Fresh admin token (master access tokens live 60 s; the run takes minutes because of TOTP periods)."""
    if time.time() - _tok["at"] > 30:
        _tok["v"], _tok["at"] = admin_headers(), time.time()
    return _tok["v"]


def admin_headers():
    r = requests.post(f"{KC}/realms/master/protocol/openid-connect/token",
                      data={"client_id": "admin-cli", "grant_type": "password",
                            "username": a.admin_user, "password": a.admin_password})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}



def client(cid):
    c = requests.get(f"{ADM}/clients", params={"clientId": cid}, headers=H()).json()[0]
    sec = requests.get(f"{ADM}/clients/{c['id']}/client-secret", headers=H()).json()["value"]
    return c, sec


class Browser(requests.Session):
    """Keycloak 26 sets Secure cookies; browsers send them to http://localhost, requests does not."""

    def request(self, *args, **kwargs):
        r = super().request(*args, **kwargs)
        for ck in self.cookies:
            ck.secure = False
        return r


def pkce():
    v = secrets.token_urlsafe(48)
    ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    return v, ch


def form_action(page, form_id):
    m = re.search(r'<form[^>]*id="%s"[^>]*>' % re.escape(form_id), page)
    if not m:
        return None
    act = re.search(r'action="([^"]+)"', m.group(0))
    return up.urljoin(KC, html.unescape(act.group(1))) if act else None


def follow(s, resp, stop_prefix):
    """Follow redirects while they stay on Keycloak; stop at the BFF callback (not running)."""
    while resp.status_code in (301, 302, 303, 307):
        loc = resp.headers["Location"]
        if loc.startswith(stop_prefix):
            return resp, loc
        resp = s.get(up.urljoin(resp.url, loc), allow_redirects=False)
    return resp, None


def diag(r, cb):
    ids = re.findall(r'<form[^>]*id="([^"]+)"', r.text)
    err = re.findall(r'class="[^"]*(?:kc-feedback-text|alert)[^"]*"[^>]*>([^<]{0,160})', r.text)
    t = re.search(r"<title>([^<]*)", r.text)
    return f"http={r.status_code} cb={cb} title={t and t.group(1).strip()!r} forms={ids} msg={[e.strip() for e in err if e.strip()]}"


def direct_grant(cid, sec, pw, expect_ok=True):
    """Once TOTP is enrolled the direct-grant flow (conditional OTP) needs `totp`; a wrong password fails
    before the OTP step, so the code is not consumed for expected failures."""
    d = {"grant_type": "password", "client_id": cid, "client_secret": sec, "username": USER, "password": pw}
    if TOTP["first"]:
        # Observed on 26.3.5: the reset-credentials "Reset OTP" step forces a re-enrolment but keeps the old
        # OTP credential, and the direct-grant OTP check uses the first one -> answer with the first secret.
        d["totp"] = totp_code(TOTP["first"], consume=expect_ok)
    r = requests.post(f"{OIDC}/token", data=d)
    if (r.status_code == 200) != expect_ok:
        print(f"   info: direct grant expect_ok={expect_ok} -> {r.status_code} {r.text[:160]}")
    return r.status_code == 200


def pw_ok(cid, sec, new, old):
    ok_new = direct_grant(cid, sec, new)
    return ok_new and not direct_grant(cid, sec, old, expect_ok=False)


def start_auth(s, c, kc_action=None, with_pkce=True):
    redirect = c["redirectUris"][0]
    q = {"client_id": c["clientId"], "redirect_uri": redirect, "response_type": "code",
         "scope": "openid", "state": secrets.token_urlsafe(8)}
    v = None
    if with_pkce:
        v, ch = pkce()
        q.update(code_challenge=ch, code_challenge_method="S256")
    if kc_action:
        q["kc_action"] = kc_action
    r = s.get(f"{OIDC}/auth", params=q, allow_redirects=False)
    r, cb = follow(s, r, redirect)
    return r, cb, v, redirect


TOTP = {"secret": None, "first": None, "last": None}


def totp_code(secret, consume=True):
    """RFC 6238 (realm otpPolicy: HmacSHA1, 6 digits, 30 s); waits for a fresh period (codes not reusable)."""
    while consume and int(time.time() // 30) == TOTP["last"]:
        time.sleep(1)
    step = int(time.time() // 30)
    if consume:
        TOTP["last"] = step
    key = secret.encode()  # Keycloak form field totpSecret = raw key (totpSecretEncoded is its base32)
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def second_factor(s, r, cb, redirect):
    """acr=2 clients (continuum-admin-bff, LoA flow): enrol TOTP on first login, then answer the OTP form."""
    for _ in range(3):
        if cb:
            break
        act = form_action(r.text, "kc-totp-settings-form")
        if act:
            TOTP["secret"] = re.search(r'name="totpSecret"[^>]*value="([^"]+)"', r.text).group(1)
            TOTP["first"] = TOTP["first"] or TOTP["secret"]
            r = s.post(act, data={"totp": totp_code(TOTP["secret"]), "totpSecret": TOTP["secret"],
                                  "userLabel": f"probe-{secrets.token_hex(3)}", "mode": ""}, allow_redirects=False)
            r, cb = follow(s, r, redirect)
            continue
        act = form_action(r.text, "kc-otp-login-form")
        if act and TOTP["secret"]:
            r = s.post(act, data={"otp": totp_code(TOTP["secret"])}, allow_redirects=False)
            r, cb = follow(s, r, redirect)
            continue
        break
    return r, cb


def login(s, page_resp, pw, redirect):
    act = form_action(page_resp.text, "kc-form-login")
    if not act:
        return page_resp, None
    r = s.post(act, data={"username": USER, "password": pw, "credentialId": ""}, allow_redirects=False)
    r, cb = follow(s, r, redirect)
    return second_factor(s, r, cb, redirect)


def exchange(c, sec, cb, v, redirect):
    code = up.parse_qs(up.urlparse(cb).query).get("code", [None])[0]
    if not code:
        return False
    d = {"grant_type": "authorization_code", "client_id": c["clientId"], "client_secret": sec,
         "code": code, "redirect_uri": redirect}
    if v:
        d["code_verifier"] = v
    return requests.post(f"{OIDC}/token", data=d).status_code == 200


def qs(cb):
    return {k: v[0] for k, v in up.parse_qs(up.urlparse(cb or "").query).items()}


realm_before = requests.get(ADM, headers=H()).json()
for old in requests.get(f"{ADM}/users", params={"username": USER, "exact": "true"}, headers=H()).json():
    requests.delete(f"{ADM}/users/{old['id']}", headers=H())  # leftover from an interrupted run
uid = None
pw_seq = iter(f"Probe-{i}-{secrets.token_hex(4)}Aa!" for i in range(20))
cur = next(pw_seq)
try:
    # --- setup: throwaway local user + realm reset/SMTP (sim only) --------------------------
    r = requests.post(f"{ADM}/users", headers=H(), json={
        "username": USER, "email": EMAIL, "emailVerified": True, "enabled": True,
        "firstName": "ADR14c", "lastName": "Probe",
        "credentials": [{"type": "password", "value": cur, "temporary": False}]})
    assert r.status_code == 201, r.text
    uid = r.headers["Location"].rsplit("/", 1)[1]
    requests.put(ADM, headers=H(), json={"resetPasswordAllowed": True, "smtpServer": {
        "host": a.smtp_host, "port": "1025", "from": "noreply@banque-demo.local",
        "fromDisplayName": "Continuum (sim)", "auth": "false", "ssl": "false", "starttls": "false"}}
                 ).raise_for_status()

    for cid in CLIENTS:
        c, sec = client(cid)
        print(f"\n== {cid}")
        # 1. AIA success
        s = Browser()
        r, cb, v, red = start_auth(s, c, "UPDATE_PASSWORD")
        r, cb = login(s, r, cur, red)
        act = form_action(r.text, "kc-passwd-update-form") if cb is None else None
        check(f"{cid}: AIA shows the update-password form after login", bool(act), diag(r, cb))
        if not act:
            continue
        new = next(pw_seq)
        r = s.post(act, data={"password-new": new, "password-confirm": new}, allow_redirects=False)
        r, cb = follow(s, r, red)
        st = qs(cb)
        check(f"{cid}: AIA returns kc_action_status=success to BFF callback",
              st.get("kc_action_status") == "success", f"callback params={sorted(st)}")
        check(f"{cid}: AIA code exchangeable (secret + verifier)", exchange(c, sec, cb, v, red))
        check(f"{cid}: new password accepted, old rejected",
              pw_ok(cid, sec, new, cur))
        cur = new

        # 2. AIA cancel (existing SSO session: no login form)
        r, cb, v, red = start_auth(s, c, "UPDATE_PASSWORD")
        act = form_action(r.text, "kc-passwd-update-form")
        check(f"{cid}: AIA with live SSO session skips login, shows form", bool(act) and cb is None)
        r = s.post(act, data={"cancel-aia": "true"}, allow_redirects=False)
        r, cb = follow(s, r, red)
        st = qs(cb)
        check(f"{cid}: cancel returns kc_action_status=cancelled, password unchanged",
              st.get("kc_action_status") == "cancelled" and direct_grant(cid, sec, cur),
              f"status={st.get('kc_action_status')}")

        # 3. lower-case kc_action
        r, cb, v, red = start_auth(s, c, "update_password")
        st = qs(cb)
        has_form = bool(form_action(r.text, "kc-passwd-update-form"))
        print(f"   info: kc_action=update_password -> form={has_form}, callback params={st}")
        check(f"{cid}: lower-case kc_action does NOT trigger the action (case-sensitive)",
              not has_form)

        # 4. AIA without PKCE
        s2 = Browser()
        r, cb, v, red = start_auth(s2, c, "UPDATE_PASSWORD", with_pkce=False)
        st = qs(cb)
        print(f"   info: no PKCE -> status={r.status_code}, callback params={st}")
        check(f"{cid}: AIA without PKCE refused (client enforces S256)",
              st.get("error") == "invalid_request" or (cb is None and "kc-form-login" not in r.text))

    # 5. Forgot password (app client, fresh browser)
    c, sec = client("continuum-app-bff")
    print("\n== forgot password (continuum-app-bff)")
    requests.delete(f"{a.mailpit}/api/v1/messages")
    s = Browser()
    r, cb, v, red = start_auth(s, c)
    m = re.search(r'href="([^"]*login-actions/reset-credentials[^"]*)"', r.text)
    check("login page shows the reset-credentials link", bool(m))
    r = s.get(up.urljoin(KC, html.unescape(m.group(1))), allow_redirects=False)
    r, _ = follow(s, r, red)
    act = form_action(r.text, "kc-reset-password-form")
    check("reset-credentials form displayed", bool(act))
    r = s.post(act, data={"username": USER}, allow_redirects=False)
    r, _ = follow(s, r, red)
    msg = None
    for _ in range(20):
        lst = requests.get(f"{a.mailpit}/api/v1/messages").json().get("messages", [])
        msg = next((x for x in lst if any(t["Address"] == EMAIL for t in x["To"])), None)
        if msg:
            break
        time.sleep(0.5)
    check("reset e-mail delivered to SMTP sim (mailpit)", bool(msg),
          msg and f"subject={msg['Subject']!r}")
    body = requests.get(f"{a.mailpit}/api/v1/message/{msg['ID']}").json()["Text"]
    link = re.search(r"(http\S+login-actions/action-token\?\S+)", body).group(1)
    r = s.get(link, allow_redirects=False)
    r, cb = follow(s, r, red)
    proceed = re.search(r'href="([^"]*login-actions/action-token[^"]*)"', r.text)
    if not form_action(r.text, "kc-passwd-update-form") and proceed:
        r = s.get(up.urljoin(KC, html.unescape(proceed.group(1))), allow_redirects=False)
        r, cb = follow(s, r, red)
    otp_asked = bool(form_action(r.text, "kc-otp-login-form"))
    r, cb = second_factor(s, r, cb, red)  # reset-credentials flow: conditional OTP if enrolled
    act = form_action(r.text, "kc-passwd-update-form")
    check("e-mail link opens the update-password form", bool(act),
          f"OTP asked before (TOTP enrolled: {bool(TOTP['secret'])}) = {otp_asked}; " + diag(r, cb))
    new = next(pw_seq)
    r = s.post(act, data={"password-new": new, "password-confirm": new}, allow_redirects=False)
    r, cb = follow(s, r, red)
    check("after reset, flow ends at BFF callback with a code",
          bool(cb) and "code" in qs(cb), f"callback params={sorted(qs(cb))}")
    check("reset code exchangeable", exchange(c, sec, cb, v, red))
    creds = requests.get(f"{ADM}/users/{uid}/credentials", headers=H()).json()
    print(f"   info: credentials after reset: {[(x['type'], x.get('userLabel')) for x in creds]}")
    check("reset password accepted, previous rejected",
          pw_ok(c["clientId"], sec, new, cur))
    cur = new
finally:
    if uid:
        requests.delete(f"{ADM}/users/{uid}", headers=H())
    requests.put(ADM, headers=H(), json={"resetPasswordAllowed": realm_before.get("resetPasswordAllowed", False),
                                       "smtpServer": realm_before.get("smtpServer") or {}})
    after = requests.get(ADM, headers=H()).json()
    print(f"\ncleanup: user deleted, realm restored resetPasswordAllowed={after.get('resetPasswordAllowed')}"
          f" smtpServer={after.get('smtpServer')}")

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
sys.exit(1 if failed else 0)
