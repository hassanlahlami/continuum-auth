#!/usr/bin/env python3
"""DEV/RECETTE ONLY - provisions realms/continuum-auth-bff.fragment.json (ADR 0014 / D41) into LIVE realm(s) of the
LOCAL sim Keycloak through the admin REST API: flow `continuum-browser-loa` (+ sub-flows, LoA configs) and the
confidential BFF clients `continuum-app-bff` / `continuum-admin-bff` (flags, attributes, redirect URIs, browser flow
override, default/optional scopes, protocol mappers), EXACTLY as the fragment (single source of truth, nothing
re-declared here). Idempotent: re-running with an unchanged fragment changes nothing; a drifted flow is rebuilt.

Secrets: KC_APP_BFF_SECRET / KC_ADMIN_BFF_SECRET from the environment, else from recette/.env.local (gitignored),
else generated (secrets.token_urlsafe) and appended to recette/.env.local. Never printed. The backend reads the same
names (application.yml continuum.auth.bff.apps.*.client-secret).

Then checks the live result (--verify-only skips provisioning): structure == fragment, secret accepted / wrong
secret rejected, direct grant enabled/refused as in the fragment, authorize endpoint enforces PKCE + redirect URIs, and, if
VERIFY_USER / VERIFY_PASSWORD are set (user without OTP), a real app-BFF direct grant (acr=1, aud continuum-app).

Usage: KC_ADMIN_PASSWORD=... python -I recette/setup-auth-bff-clients.py [--verify-only] REALM [REALM...]
"""
import base64, copy, json, os, re, secrets, sys
import urllib.error, urllib.parse, urllib.request

KC = os.environ.get("KC_URL", "http://localhost:8180")
if not re.match(r"^http://(localhost|127\.0\.0\.1):\d+$", KC):
    sys.exit(f"refusing: {KC} is not a local sim Keycloak")
HERE = os.path.dirname(os.path.abspath(__file__))
FRAGMENT = json.load(open(os.path.join(os.path.dirname(HERE), "realms", "continuum-auth-bff.fragment.json"), encoding="utf-8"))
ENV_LOCAL = os.path.join(HERE, ".env.local")
SECRET_VAR = {"continuum-app-bff": "KC_APP_BFF_SECRET", "continuum-admin-bff": "KC_ADMIN_BFF_SECRET"}
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

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        r = urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, data=body, method=method, headers=h))
        return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")


def ok(s, b, what):
    if s >= 300:
        sys.exit(f"{what} -> {s}: {b[:300]}")
    return json.loads(b) if b.strip() else None


# ---------- secrets ----------
def load_env_local():
    env = {}
    if os.path.exists(ENV_LOCAL):
        for line in open(ENV_LOCAL, encoding="utf-8"):
            m = re.match(r"^\s*([A-Z0-9_]+)=(.*)$", line.rstrip("\r\n"))
            if m:
                env[m.group(1)] = m.group(2)
    return env


local = load_env_local()
SECRETS = {}
for cid, var in SECRET_VAR.items():
    val = os.environ.get(var) or local.get(var)
    if not val and not VERIFY_ONLY:
        val = secrets.token_urlsafe(32)
        with open(ENV_LOCAL, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"{var}={val}\n")
        print(f"   + {var} generated -> recette/.env.local")
    if not val:
        sys.exit(f"{var} not set (env or recette/.env.local)")
    SECRETS[cid] = val

s, _, b = req("POST", f"{KC}/realms/master/protocol/openid-connect/token", {
    "client_id": "admin-cli", "grant_type": "password", "username": os.environ.get("KC_ADMIN", "admin"),
    "password": os.environ.get("KC_ADMIN_PASSWORD") or sys.exit("set KC_ADMIN_PASSWORD")}, form=True)
A = {"Authorization": "Bearer " + ok(s, b, "admin token")["access_token"]}
q = lambda alias: urllib.parse.quote(alias, safe="")

FLOWS = {f["alias"]: f for f in FRAGMENT["authenticationFlows"]}
FLOW_BY_ID = {f["id"]: f["alias"] for f in FRAGMENT["authenticationFlows"]}
CONFIGS = {c["alias"]: c["config"] for c in FRAGMENT["authenticatorConfig"]}
TOP = [f for f in FRAGMENT["authenticationFlows"] if f["topLevel"]]


def expected(alias, level=0):
    """Flattened fragment flow, same order/shape as GET .../executions."""
    out = []
    for e in sorted(FLOWS[alias]["authenticationExecutions"], key=lambda e: e["priority"]):
        if e["authenticatorFlow"]:
            out.append((level, "flow:" + e["flowAlias"], e["requirement"], None))
            out += expected(e["flowAlias"], level + 1)
        else:
            cfg = e.get("authenticatorConfig")
            out.append((level, e["authenticator"], e["requirement"], (cfg, CONFIGS[cfg]) if cfg else None))
    return out


def actual(R, alias):
    s, _, b = req("GET", f"{R}/authentication/flows/{q(alias)}/executions", headers=A)
    out = []
    for e in ok(s, b, "executions"):
        kind = "flow:" + e["displayName"] if e.get("authenticationFlow") else e.get("providerId")
        cfg = None
        if e.get("authenticationConfig"):
            c = ok(*req("GET", f"{R}/authentication/config/{e['authenticationConfig']}", headers=A)[::2], "config")
            cfg = (c["alias"], c["config"])
        out.append((e["level"], kind, e["requirement"], cfg))
    return out


def build(R, parent, level_alias):
    for i, e in enumerate(sorted(FLOWS[level_alias]["authenticationExecutions"], key=lambda e: e["priority"])):
        if e["authenticatorFlow"]:
            sub = FLOWS[e["flowAlias"]]
            ok(*req("POST", f"{R}/authentication/flows/{q(parent)}/executions/flow", {
                "alias": sub["alias"], "type": sub["providerId"], "provider": "registration-page-form",
                "description": sub.get("description", "")}, A)[::2], "add sub-flow " + sub["alias"])
        else:
            ok(*req("POST", f"{R}/authentication/flows/{q(parent)}/executions/execution",
                    {"provider": e["authenticator"]}, A)[::2], "add execution " + e["authenticator"])
        execs = [x for x in ok(*req("GET", f"{R}/authentication/flows/{q(parent)}/executions", headers=A)[::2], "list")
                 if x["level"] == 0]
        x = execs[i]
        x["requirement"] = e["requirement"]
        ok(*req("PUT", f"{R}/authentication/flows/{q(parent)}/executions", x, A)[::2], "requirement")
        if e.get("authenticatorConfig"):
            ok(*req("POST", f"{R}/authentication/executions/{x['id']}/config",
                    {"alias": e["authenticatorConfig"], "config": CONFIGS[e["authenticatorConfig"]]}, A)[::2], "config")
        if e["authenticatorFlow"]:
            build(R, e["flowAlias"], e["flowAlias"])


def find_client(R, cid):
    L = ok(*req("GET", f"{R}/clients?clientId={q(cid)}", headers=A)[::2], "client lookup")
    return L[0] if L else None


def flow_ids(R):
    return {f["alias"]: f["id"] for f in ok(*req("GET", f"{R}/authentication/flows", headers=A)[::2], "flows")}


def provision(realm):
    R = f"{KC}/admin/realms/{realm}"
    for top in TOP:
        alias = top["alias"]
        ids = flow_ids(R)
        if alias in ids and actual(R, alias) == expected(alias):
            print(f"   = flow {alias}")
            continue
        if alias in ids:  # drifted: unbind our clients, delete, rebuild
            for cid in SECRET_VAR:
                c = find_client(R, cid)
                if c and ids[alias] in c.get("authenticationFlowBindingOverrides", {}).values():
                    # Keycloak ignores an empty map: an override is removed only by an empty value.
                    c["authenticationFlowBindingOverrides"] = {k: "" for k in c["authenticationFlowBindingOverrides"]}
                    ok(*req("PUT", f"{R}/clients/{c['id']}", c, A)[::2], "unbind " + cid)
            ok(*req("DELETE", f"{R}/authentication/flows/{ids[alias]}", headers=A)[::2], "delete flow")
            print(f"   ~ flow {alias} drifted -> rebuilt")
        ok(*req("POST", f"{R}/authentication/flows", {"alias": alias, "description": top.get("description", ""),
                "providerId": top["providerId"], "topLevel": True, "builtIn": False}, A)[::2], "create flow")
        build(R, alias, alias)
        print(f"   + flow {alias}")
    ids = flow_ids(R)
    scopes = {s["name"]: s["id"] for s in ok(*req("GET", f"{R}/client-scopes", headers=A)[::2], "scopes")}
    for frag in FRAGMENT["clients"]:
        cid = frag["clientId"]
        rep = copy.deepcopy(frag)
        mappers = rep.pop("protocolMappers", [])
        rep["secret"] = SECRETS[cid]
        rep["authenticationFlowBindingOverrides"] = {k: ids[FLOW_BY_ID[v]] for k, v in rep["authenticationFlowBindingOverrides"].items()}
        cur = find_client(R, cid)
        if not cur:
            ok(*req("POST", f"{R}/clients", rep, A)[::2], "create " + cid)
            cur = find_client(R, cid)
            print(f"   + client {cid}")
        else:
            stale = {k: "" for k in cur.get("authenticationFlowBindingOverrides", {})}  # "" = remove (see above)
            merged = {**cur, **rep, "attributes": {**cur.get("attributes", {}), **rep["attributes"]},
                      "authenticationFlowBindingOverrides": {**stale, **rep["authenticationFlowBindingOverrides"]}}
            merged.pop("protocolMappers", None)
            ok(*req("PUT", f"{R}/clients/{cur['id']}", merged, A)[::2], "update " + cid)
            print(f"   = client {cid} (updated to fragment)")
        C = f"{R}/clients/{cur['id']}"
        for kind, want in (("default", rep["defaultClientScopes"]), ("optional", rep["optionalClientScopes"])):
            have = {s["name"]: s["id"] for s in ok(*req("GET", f"{C}/{kind}-client-scopes", headers=A)[::2], "scopes")}
            for name in set(have) - set(want):
                ok(*req("DELETE", f"{C}/{kind}-client-scopes/{have[name]}", headers=A)[::2], "rm scope")
            for name in set(want) - set(have):
                ok(*req("PUT", f"{C}/{kind}-client-scopes/{scopes[name]}", headers=A)[::2], "add scope " + name)
        have = {m["name"]: m for m in ok(*req("GET", f"{C}/protocol-mappers/models", headers=A)[::2], "mappers")}
        for name in set(have) - {m["name"] for m in mappers}:
            ok(*req("DELETE", f"{C}/protocol-mappers/models/{have[name]['id']}", headers=A)[::2], "rm mapper")
        for m in mappers:
            if m["name"] in have:
                ok(*req("PUT", f"{C}/protocol-mappers/models/{have[m['name']]['id']}", {**m, "id": have[m["name"]]["id"]}, A)[::2], "mapper")
            else:
                ok(*req("POST", f"{C}/protocol-mappers/models", m, A)[::2], "mapper " + m["name"])


def verify(realm):
    R = f"{KC}/admin/realms/{realm}"
    TE = f"{KC}/realms/{realm}/protocol/openid-connect/token"
    AU = f"{KC}/realms/{realm}/protocol/openid-connect/auth"
    rr = ok(*req("GET", R, headers=A)[::2], "realm")
    check(rr.get("browserFlow") == "browser" and rr.get("directGrantFlow") == "direct grant", "realm default flow bindings untouched")
    for top in TOP:
        check(actual(R, top["alias"]) == expected(top["alias"]), f"flow {top['alias']} == fragment")
    ids = flow_ids(R)
    for frag in FRAGMENT["clients"]:
        cid = frag["clientId"]
        c = find_client(R, cid)
        if not c:
            check(False, f"{cid} exists"); continue
        C = f"{R}/clients/{c['id']}"
        flags = ("enabled", "publicClient", "clientAuthenticatorType", "standardFlowEnabled", "implicitFlowEnabled",
                 "directAccessGrantsEnabled", "serviceAccountsEnabled", "frontchannelLogout", "fullScopeAllowed")
        check(all(c.get(k) == frag[k] for k in flags), f"{cid} flags (confidential, grants) == fragment")
        check(sorted(c["redirectUris"]) == sorted(frag["redirectUris"]) and c.get("webOrigins", []) == frag["webOrigins"],
              f"{cid} redirect URIs / no web origins == fragment")
        check(all(c["attributes"].get(k) == v for k, v in frag["attributes"].items()), f"{cid} attributes (PKCE S256, acr, lifespans) == fragment")
        check(c.get("authenticationFlowBindingOverrides") == {k: ids[FLOW_BY_ID[v]] for k, v in frag["authenticationFlowBindingOverrides"].items()},
              f"{cid} browser override -> continuum-browser-loa")
        for kind in ("default", "optional"):
            have = sorted(s["name"] for s in ok(*req("GET", f"{C}/{kind}-client-scopes", headers=A)[::2], "scopes"))
            check(have == sorted(frag[f"{kind}ClientScopes"]), f"{cid} {kind} scopes == fragment")
        have = {m["name"]: (m["protocolMapper"], m["config"]) for m in ok(*req("GET", f"{C}/protocol-mappers/models", headers=A)[::2], "m")}
        # Keycloak adds its own defaults (introspection/userinfo.token.claim): fragment config must be a subset.
        want = {m["name"]: m for m in frag["protocolMappers"]}
        check(set(have) == set(want) and all(have[n][0] == want[n]["protocolMapper"] and want[n]["config"].items() <= have[n][1].items()
                                             for n in want), f"{cid} mappers == fragment (no acr mapper)")
        # client authentication (no user needed: a bogus user gives invalid_grant only once the client is authenticated)
        dg = {"grant_type": "password", "client_id": cid, "username": "no-such-user-" + secrets.token_hex(4), "password": "x"}
        s, _, b = req("POST", TE, {**dg, "client_secret": "wrong-" + secrets.token_hex(8)}, form=True)
        check(s == 401 and json.loads(b).get("error") == "unauthorized_client", f"{cid} wrong secret rejected")
        s, _, b = req("POST", TE, {**dg, "client_secret": SECRETS[cid]}, form=True)
        err = json.loads(b).get("error")
        if frag["directAccessGrantsEnabled"]:
            check(s == 401 and err == "invalid_grant", f"{cid} secret accepted, direct grant enabled (bogus user -> invalid_grant)")
        else:
            check(s == 400 and err == "unauthorized_client", f"{cid} secret accepted, direct grant refused (unauthorized_client)")
        s, _, b = req("POST", TE, {"grant_type": "client_credentials", "client_id": cid, "client_secret": SECRETS[cid]}, form=True)
        check(s >= 400, f"{cid} client_credentials refused (no service account)")
        cb = frag["redirectUris"][0]
        base = {"client_id": cid, "response_type": "code", "scope": "openid", "redirect_uri": cb, "state": "s"}
        s, h, _ = req("GET", AU + "?" + urllib.parse.urlencode(base))
        check(s == 302 and "code_challenge" in urllib.parse.unquote(h.get("Location", "")) and "error" in h.get("Location", ""),
              f"{cid} authorize without PKCE refused")
        pk = {**base, "code_challenge": base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode(), "code_challenge_method": "S256"}
        s, _, b = req("GET", AU + "?" + urllib.parse.urlencode(pk))
        check(s == 200 and 'name="password"' in b, f"{cid} authorize with PKCE S256 -> login page")
        s, _, _ = req("GET", AU + "?" + urllib.parse.urlencode({**pk, "redirect_uri": "http://localhost:9999/api/auth/callback"}))
        check(s == 400, f"{cid} unknown redirect_uri refused")
    u, p = os.environ.get("VERIFY_USER"), os.environ.get("VERIFY_PASSWORD")
    if u and p:
        s, _, b = req("POST", TE, {"grant_type": "password", "client_id": "continuum-app-bff", "client_secret": SECRETS["continuum-app-bff"],
                                   "username": u, "password": p, "scope": "openid"}, form=True)
        if s != 200:
            check(False, f"app-bff direct grant {u} -> {s} {b[:120]}")
        else:
            t = json.loads(b)["access_token"].split(".")[1]
            cl = json.loads(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
            aud = cl.get("aud") if isinstance(cl.get("aud"), list) else [cl.get("aud")]
            check(cl.get("azp") == "continuum-app-bff" and "continuum-app" in aud and cl.get("acr") == "1"
                  and cl.get("tenant_id") and cl.get("continuum_user_id"),
                  f"app-bff direct grant {u}: azp, aud continuum-app, acr=1, tenant_id/continuum_user_id")
    else:
        print("   --  real-user direct grant skipped (set VERIFY_USER / VERIFY_PASSWORD)")


for realm in args:
    if not VERIFY_ONLY:
        print(f"== provision {realm}")
        provision(realm)
    print(f"== verify {realm}")
    verify(realm)
print(f"\n{'FAILED: ' + str(len(fails)) if fails else 'ALL CHECKS PASSED'}")
sys.exit(1 if fails else 0)
