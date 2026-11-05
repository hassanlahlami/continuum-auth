#!/usr/bin/env python3
"""Enrolls (or re-checks) a known TOTP credential for a SIMULATION user, so live E2E tests can pass acr=2.

DEV / SIMULATION ONLY. Hard-refuses any Keycloak other than localhost and any realm other than banque-demo
(never recette, never production). No admin API: it drives the standard browser flow of the admin BFF client
(Code + PKCE, acr_values=2): username/password, then Keycloak's own CONFIGURE_TOTP required action, whose page
carries the generated secret. The secret is written to --out (a file OUTSIDE any git repo), never printed.

If the user already has an OTP credential, the script only verifies a login with the secret already in --out.
Verification: a second login answered with a computed code must reach the redirect URI; with --client-secret-env
set, the code is exchanged and the access token must carry acr=2.

Usage:
  SIM_USER_PASSWORD=... python -I scripts/sim-enroll-totp.py --out ../.claude-team/secrets/admin-web-sim-dsi-admin.env
Options: --user (dsi.admin), --client (continuum-admin-bff), --redirect (http://localhost:4202/api/auth/callback),
         --kc (http://localhost:8180), --client-secret-env NAME (env var holding the client secret, optional).
"""
import argparse, base64, hashlib, hmac, html.parser, http.cookiejar, json, os, secrets, struct, sys, time
import urllib.error, urllib.parse, urllib.request

REALM = "banque-demo"                      # the only realm this script may touch
ALLOWED_HOSTS = {"localhost", "127.0.0.1"}


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._cur = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": html.unescape(a.get("action") or ""), "id": a.get("id"), "inputs": {}}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None and a.get("name"):
            if a.get("type") in ("checkbox", "radio") and "checked" not in a:
                return
            self._cur["inputs"][a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def totp(raw_secret: bytes, at=None, period=30, digits=6):
    counter = int((time.time() if at is None else at) // period)
    mac = hmac.new(raw_secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)).zfill(digits)


def fresh_window():
    """otpPolicyCodeReusable=false: never reuse a code, so wait for a window not used by a previous call."""
    left = 30 - (time.time() % 30)
    if left < 5 or fresh_window.last == int(time.time() // 30):
        time.sleep(left + 1)
    fresh_window.last = int(time.time() // 30)
fresh_window.last = None


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def go(self, url, data=None):
        """Returns (status, location, body) without following redirects."""
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        for c in self.jar:          # Keycloak marks its cookies Secure even on the plain-http simulation
            c.secure = False
        try:
            with self.op.open(urllib.request.Request(url, data=body), timeout=20) as r:
                return r.status, None, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode("utf-8", "replace")

    def follow(self, url, data=None, stop_prefix=None):
        status, loc, body = self.go(url, data)
        while status in (301, 302, 303) and loc and not (stop_prefix and loc.startswith(stop_prefix)):
            status, loc, body = self.go(urllib.parse.urljoin(url, loc))
        return status, loc, body


def forms(body):
    p = Forms()
    p.feed(body)
    return p.forms


def fail(msg):
    sys.exit(f"FAIL: {msg}")


def login(args, password, otp_secret=None):
    """Runs one authorization-code login; returns (browser, final_location, enrolled_raw_secret_or_None, verifier)."""
    b = Browser()
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"client_id": args.client, "response_type": "code", "scope": "openid",
                                "redirect_uri": args.redirect, "acr_values": "2", "state": secrets.token_hex(8),
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    status, loc, body = b.follow(f"{args.kc}/realms/{REALM}/protocol/openid-connect/auth?{q}", stop_prefix=args.redirect)
    enrolled = None
    for _ in range(6):
        if loc and loc.startswith(args.redirect):
            return b, loc, enrolled, verifier
        fs = [f for f in forms(body) if f["action"]]
        if status != 200 or not fs:
            fail(f"unexpected Keycloak page (HTTP {status})")
        f = fs[0]
        fields = dict(f["inputs"])
        if "password" in fields and "username" in fields:
            fields.update(username=args.user, password=password)
        elif "totpSecret" in fields:                       # CONFIGURE_TOTP required action
            enrolled = fields["totpSecret"].encode()
            fresh_window()
            fields.update(totp=totp(enrolled), userLabel="sim-e2e")
        elif "otp" in fields:                              # OTP form (already enrolled)
            if otp_secret is None:
                fail(f"{args.user} already has an OTP credential but --out holds no secret: delete the user's OTP "
                     "credential in the sim admin console, then rerun")
            fresh_window()
            fields["otp"] = totp(otp_secret)
        else:
            fail(f"unknown form on Keycloak page: {sorted(fields)}")
        status, loc, body = b.follow(f["action"], fields, stop_prefix=args.redirect)
    fail("too many Keycloak pages")


def exchange(args, loc, verifier, client_secret):
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [None])[0]
    if not code:
        fail("redirect without code")
    data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": args.redirect,
                                   "client_id": args.client, "client_secret": client_secret,
                                   "code_verifier": verifier}).encode()
    with urllib.request.urlopen(f"{args.kc}/realms/{REALM}/protocol/openid-connect/token", data, timeout=20) as r:
        at = json.load(r)["access_token"]
    payload = at.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("acr")


def read_out(path):
    vals = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line and not line.startswith("#"):
                k, v = line.rstrip("\n").split("=", 1)
                vals[k] = v
    return vals


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kc", default="http://localhost:8180")
    ap.add_argument("--user", default="dsi.admin")
    ap.add_argument("--client", default="continuum-admin-bff")
    ap.add_argument("--redirect", default="http://localhost:4202/api/auth/callback")
    ap.add_argument("--client-secret-env", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    host = urllib.parse.urlparse(args.kc).hostname
    if host not in ALLOWED_HOSTS:
        fail(f"refusing Keycloak host {host!r}: simulation on localhost only")
    password = os.environ.get("SIM_USER_PASSWORD")
    if not password:
        fail("SIM_USER_PASSWORD is not set")
    out = os.path.abspath(args.out)
    probe = os.path.dirname(out)
    while probe and probe != os.path.dirname(probe):
        if os.path.isdir(os.path.join(probe, ".git")):
            fail(f"--out is inside a git repository ({probe}): secrets never go in git")
        probe = os.path.dirname(probe)

    prev = read_out(out)
    known = prev.get("SIM_TOTP_SECRET_RAW")
    _, loc, enrolled, _ = login(args, password, known.encode() if known else None)
    raw = enrolled or (known.encode() if known else None)
    if enrolled:
        b32 = base64.b32encode(enrolled).decode().rstrip("=")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"# sim Keycloak ({args.kc}, realm {REALM}) - {args.user} with TOTP for live E2E (acr=2). DEV ONLY.\n"
                     "# Written by continuum-auth/scripts/sim-enroll-totp.py. Never paste values in chat, never commit.\n"
                     "# TOTP: SHA1, 6 digits, 30 s; Keycloak refuses a code reused in the same window (otpPolicyCodeReusable=false).\n"
                     "# otplib: authenticator.generate(SIM_TOTP_SECRET_BASE32)\n"
                     "# Keycloak pages (driven by cy.request Code+PKCE, no cy.origin; HSTS ignored over http): inputs name=username, name=password, then name=otp; submit name=login.\n"
                     f"SIM_KC_URL={args.kc}\nSIM_KC_REALM={REALM}\nSIM_USERNAME={args.user}\n"
                     f"SIM_USER_PASSWORD={password}\nSIM_TOTP_SECRET_BASE32={b32}\n"
                     f"SIM_TOTP_SECRET_RAW={enrolled.decode()}\n")
        print(f"enrolled a TOTP for {args.user}; secret written to {out}")
    else:
        print(f"{args.user} already enrolled; login with the stored secret OK")

    # verification: a fresh login answered with a computed code (next window, codes are not reusable)
    _, loc, again, verifier = login(args, password, raw)
    if again:
        fail("Keycloak asked to enroll again: the OTP credential was not stored")
    print("verify: login with computed TOTP reached the redirect URI")
    if args.client_secret_env:
        cs = os.environ.get(args.client_secret_env)
        if not cs:
            fail(f"{args.client_secret_env} is not set")
        acr = exchange(args, loc, verifier, cs)
        if str(acr) != "2":
            fail(f"access token acr={acr!r}, expected 2")
        print("verify: access token acr=2")


if __name__ == "__main__":
    main()
