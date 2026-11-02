#!/usr/bin/env bash
# DEV/RECETTE ONLY. Checks continuum-admin-e2e-dg: direct grant for dsi.admin returns the approved claims,
# no extra scopes, and the client cannot do authorization-code or client-credentials. Prints no secret.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"; CLIENT=continuum-admin-e2e-dg
set -a; . "$(dirname "$0")/.env.local"; set +a
: "${RECETTE_E2E_DG_CLIENT_SECRET:?run setup-recette-e2e-direct-grant.sh first}"; : "${RECETTE_DSI_ADMIN_PASSWORD:?}"
TE="$KC/realms/$REALM/protocol/openid-connect/token"; fail=0
ok() { echo "   OK  $1"; }; ko() { echo "   KO  $1"; fail=1; }

echo "1) password grant dsi.admin"
resp="$(curl -s -d grant_type=password -d client_id=$CLIENT --data-urlencode "client_secret=$RECETTE_E2E_DG_CLIENT_SECRET" \
  -d username=dsi.admin --data-urlencode "password=$RECETTE_DSI_ADMIN_PASSWORD" -d scope=openid "$TE")"
echo "$resp" | python -c '
import sys,json,base64
r=json.load(sys.stdin); t=r.get("access_token")
if not t: print("   KO  no token:", r.get("error"), r.get("error_description")); sys.exit(1)
p=t.split(".")[1]; c=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))
exp={"tenant_id":"11111111-1111-1111-1111-111111111111","continuum_user_id":"33333333-3333-3333-3333-333333333333","acr":"2","azp":"continuum-admin-e2e-dg"}
bad=0
for k,v in exp.items():
  print("   %s  %s=%s" % ("OK" if c.get(k)==v else "KO", k, c.get(k))); bad|=c.get(k)!=v
aud=c.get("aud"); aud=aud if isinstance(aud,list) else [aud]
print("   %s  aud contains continuum-admin (%s)" % ("OK" if "continuum-admin" in aud else "KO", aud)); bad|="continuum-admin" not in aud
sc=set(c.get("scope","").split()); print("   %s  scope=%s" % ("OK" if sc<={"openid","profile","email"} and "openid" in sc else "KO", sorted(sc))); bad|=not(sc<={"openid","profile","email"})
print("   %s  no realm/client roles in token" % ("OK" if "realm_access" not in c and "resource_access" not in c else "KO")); bad|=("realm_access" in c or "resource_access" in c)
print("   %s  id_token present" % ("OK" if r.get("id_token") else "KO")); bad|=not r.get("id_token")
sys.exit(1 if bad else 0)' || fail=1

echo "2) negative checks"
code="$(curl -s -o /dev/null -w '%{http_code}' -d grant_type=password -d client_id=$CLIENT -d client_secret=wrong -d username=dsi.admin --data-urlencode "password=$RECETTE_DSI_ADMIN_PASSWORD" "$TE")"
[ "$code" = 401 ] && ok "wrong secret -> 401" || ko "wrong secret -> $code"
code="$(curl -s -o /dev/null -w '%{http_code}' -d grant_type=client_credentials -d client_id=$CLIENT --data-urlencode "client_secret=$RECETTE_E2E_DG_CLIENT_SECRET" "$TE")"
[ "$code" != 200 ] && ok "client_credentials refused ($code)" || ko "client_credentials -> 200"
code="$(curl -s -o /dev/null -w '%{http_code}' "$KC/realms/$REALM/protocol/openid-connect/auth?client_id=$CLIENT&response_type=code&redirect_uri=http://localhost:4202/&scope=openid")"
[ "$code" != 200 ] && ok "authorization code flow refused ($code)" || ko "auth endpoint -> 200"
[ $fail = 0 ] && echo "ALL OK" || { echo "FAILED"; exit 1; }
