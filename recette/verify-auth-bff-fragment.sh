#!/usr/bin/env bash
# DEV/SPIKE ONLY — checks realms/continuum-auth-bff.fragment.json (ADR 0014 / D41 draft) in an isolated throwaway
# realm `spike-d41-bff` on the LOCAL sim Keycloak (banque-demo / recette untouched): direct grant works only with
# the client secret, OTP is enforced for users that have one, claims tenant_id/continuum_user_id present, acr=1,
# no roles, no other grant. Random secrets in memory only, never printed. Realm deleted at the end unless KEEP=1.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM=spike-d41-bff; CLIENT=continuum-auth-bff
case "$KC" in http://localhost:*|http://127.0.0.1:*) ;; *) echo "refusing: $KC is not a local sim Keycloak" >&2; exit 1;; esac
FRAG="$(cd "$(dirname "$0")/.." && pwd)/realms/continuum-auth-bff.fragment.json"
admin_token() { curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" -d password="${KC_ADMIN_PASSWORD:-dev-keycloak-admin}" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])"; }
relogin() { auth=(-H "Authorization: Bearer $(admin_token)"); }
relogin; J=(-H "Content-Type: application/json")
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }
export SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export PASSWORD="$(python -c 'import secrets;print("Sp1ke!"+secrets.token_urlsafe(16))')"
export SEED="$(python -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(20)))')"
fail=0; ok() { echo "   OK  $1"; }; ko() { echo "   KO  $1"; fail=1; }

echo "0) reset realm $REALM"; api delete-realm -X DELETE "${auth[@]}" "$KC/admin/realms/$REALM"
echo "1) import realm = fragment + 2 users"
FRAG="$FRAG" python - > /tmp/spike-d41-bff.json <<'PY'
import json, os
frag = json.load(open(os.environ["FRAG"], encoding="utf-8"))
for c in frag["clients"]:
    assert c["secret"] == "${KC_AUTH_BFF_SECRET}"; c["secret"] = os.environ["SECRET"]
otp = {"type":"otp","userLabel":"spike","secretData":json.dumps({"value":os.environ["SEED"]}),
       "credentialData":json.dumps({"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"})}
pw = {"type":"password","value":os.environ["PASSWORD"],"temporary":False}
user = lambda u, creds: {"username":u,"enabled":True,"email":u+"@spike.invalid","emailVerified":True,"firstName":"Spike","lastName":u,"credentials":creds}
print(json.dumps({"realm":"spike-d41-bff","enabled":True,"sslRequired":"external","bruteForceProtected":False,
  "otpPolicyType":"totp","otpPolicyPeriod":30,"otpPolicyLookAheadWindow":1,
  "clients":frag["clients"],"users":[user("dsi.admin",[pw,otp]),user("auditor.nootp",[pw])]}))
PY
api import-realm -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms" --data-binary @/tmp/spike-d41-bff.json; rm -f /tmp/spike-d41-bff.json
echo "2) user profile: allow tenant_id/continuum_user_id, set them on dsi.admin"
curl -s "${auth[@]}" "$KC/admin/realms/$REALM/users/profile" | python -c "import sys,json;p=json.load(sys.stdin);p['unmanagedAttributePolicy']='ENABLED';print(json.dumps(p))" > /tmp/spike-d41-up.json
api user-profile -X PUT "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/users/profile" --data-binary @/tmp/spike-d41-up.json; rm -f /tmp/spike-d41-up.json
UID_="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/users?username=dsi.admin&exact=true" | python -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")"
curl -s "${auth[@]}" "$KC/admin/realms/$REALM/users/$UID_" | python -c "import sys,json;u=json.load(sys.stdin);u['attributes']={'tenant_id':['11111111-1111-1111-1111-111111111111'],'continuum_user_id':['33333333-3333-3333-3333-333333333333']};print(json.dumps(u))" > /tmp/spike-d41-u.json
api user-attrs -X PUT "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/users/$UID_" --data-binary @/tmp/spike-d41-u.json; rm -f /tmp/spike-d41-u.json

totp() { python -c "
import hmac,hashlib,struct,time,os,sys
k=os.environ['SEED'].encode(); c=int(time.time())//30+int(sys.argv[1])
h=hmac.new(k,struct.pack('>Q',c),hashlib.sha1).digest(); o=h[-1]&15
print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))" "$1"; }
TE="$KC/realms/$REALM/protocol/openid-connect/token"
dg() { curl -s -d grant_type=password -d client_id=$CLIENT --data-urlencode "client_secret=${CS:-$SECRET}" -d username="$1" \
  --data-urlencode "password=$PASSWORD" -d scope=openid "${@:2}" "$TE"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "3) checks"
e="$(dg dsi.admin | python -c "import sys,json;print(json.load(sys.stdin).get('error'))")"
[ "$e" = invalid_grant ] && ok "dsi.admin password without OTP refused ($e)" || ko "dsi.admin without OTP -> $e"
e="$(dg dsi.admin -d otp=000000 | python -c "import sys,json;print(json.load(sys.stdin).get('error'))")"
[ "$e" = invalid_grant ] && ok "dsi.admin wrong OTP refused ($e)" || ko "dsi.admin wrong OTP -> $e"
dg dsi.admin -d otp="$(totp 0)" | python -c '
import sys,json,base64
r=json.load(sys.stdin); t=r.get("access_token")
if not t: print("   KO  dsi.admin password+OTP: no token", r.get("error")); sys.exit(1)
p=t.split(".")[1]; c=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))); bad=0
for k,v in {"tenant_id":"11111111-1111-1111-1111-111111111111","continuum_user_id":"33333333-3333-3333-3333-333333333333","azp":"continuum-auth-bff","acr":"1"}.items():
  print("   %s  %s=%s" % ("OK" if c.get(k)==v else "KO", k, c.get(k))); bad|=c.get(k)!=v
sc=set(c.get("scope","").split()); g=sc<={"openid","profile","email"} and "openid" in sc; print("   %s  scope=%s" % ("OK" if g else "KO", sorted(sc))); bad|=not g
g="realm_access" not in c and "resource_access" not in c; print("   %s  no realm/client roles" % ("OK" if g else "KO")); bad|=not g
g=bool(r.get("refresh_token")); print("   %s  refresh_token present (server-side only)" % ("OK" if g else "KO")); bad|=not g
sys.exit(bad)' || fail=1
t="$(dg auditor.nootp | python -c "import sys,json;print('token' if json.load(sys.stdin).get('access_token') else 'none')")"
[ "$t" = token ] && ok "user without OTP credential: password grant OK (conditional OTP)" || ko "user without OTP -> $t"
c="$(CS=wrong code -d grant_type=password -d client_id=$CLIENT -d client_secret=wrong -d username=auditor.nootp --data-urlencode "password=$PASSWORD" "$TE")"
[ "$c" = 401 ] && ok "wrong client secret -> 401" || ko "wrong client secret -> $c"
c="$(code -d grant_type=password -d client_id=$CLIENT -d username=auditor.nootp --data-urlencode "password=$PASSWORD" "$TE")"
[ "$c" = 401 ] && ok "no client secret -> 401" || ko "no client secret -> $c"
c="$(code -d grant_type=client_credentials -d client_id=$CLIENT --data-urlencode "client_secret=$SECRET" "$TE")"
[ "$c" != 200 ] && ok "client_credentials refused ($c)" || ko "client_credentials -> 200"
c="$(code "$KC/realms/$REALM/protocol/openid-connect/auth?client_id=$CLIENT&response_type=code&redirect_uri=http://localhost:4202/&scope=openid")"
[ "$c" != 200 ] && ok "authorization code flow refused ($c)" || ko "auth endpoint -> 200"

relogin
if [ "${KEEP:-0}" = 1 ]; then echo "realm $REALM kept (KEEP=1)"; else api delete-realm -X DELETE "${auth[@]}" "$KC/admin/realms/$REALM"; fi
[ $fail = 0 ] && echo "ALL OK" || { echo "FAILED"; exit 1; }
