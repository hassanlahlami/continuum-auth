#!/usr/bin/env bash
# DEV/SPIKE ONLY — ADR 0014 / D41: can a confidential client's direct grant + OTP deliver acr>=2 for dsi.admin?
# Creates an isolated throwaway realm `spike-d41` on the LOCAL sim Keycloak (no shared realm/user touched),
# with dsi.admin (password + TOTP), a confidential client continuum-auth-bff whose direct_grant flow is overridden
# by a Level-of-Authentication flow (LoA1 = password, LoA2 = OTP), then runs the scenarios and prints the acr claim.
# Secrets (client secret, password, OTP seed) are random, kept in memory only, never printed. Realm deleted at the end
# unless KEEP=1. No real acr is faked: no hardcoded-claim mapper on this client.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM=spike-d41; CLIENT=continuum-auth-bff
case "$KC" in http://localhost:*|http://127.0.0.1:*) ;; *) echo "refusing: $KC is not a local sim Keycloak" >&2; exit 1;; esac
export PYTHONIOENCODING=utf-8
admin_token() { curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" -d password="${KC_ADMIN_PASSWORD:-dev-keycloak-admin}" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])"; }
relogin() { auth=(-H "Authorization: Bearer $(admin_token)"); }   # admin-cli tokens live 60 s
relogin; J=(-H "Content-Type: application/json")
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }

SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
PASSWORD="$(python -c 'import secrets;print("Sp1ke!"+secrets.token_urlsafe(16))')"
SEED="$(python -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(20)))')"
export SECRET PASSWORD SEED

echo "0) reset realm $REALM"
api delete-realm -X DELETE "${auth[@]}" "$KC/admin/realms/$REALM"

echo "1) import realm (LoA flow + user with OTP credential + confidential client)"
python - > /tmp/spike-d41-realm.json <<'PY'
import json, os
otp_data = json.dumps({"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"})
realm = {
 "realm":"spike-d41","enabled":True,"sslRequired":"external",
 "bruteForceProtected":False,  # off: quick-login lockout would mask the scenarios (not under test here)
 
 "otpPolicyType":"totp","otpPolicyAlgorithm":"HmacSHA1","otpPolicyDigits":6,"otpPolicyPeriod":30,"otpPolicyLookAheadWindow":1,
 "attributes":{"acr.loa.map":json.dumps({"1":1,"2":2})},
 "authenticationFlows":[
  {"alias":"continuum direct grant loa","description":"D41: LoA1 = password, LoA2 = OTP (direct grant)","providerId":"basic-flow","topLevel":True,"builtIn":False,
   "authenticationExecutions":[
    {"authenticator":"direct-grant-validate-username","requirement":"REQUIRED","priority":10,"authenticatorFlow":False,"userSetupAllowed":False},
    {"flowAlias":"continuum direct grant loa1","requirement":"CONDITIONAL","priority":20,"authenticatorFlow":True,"userSetupAllowed":False},
    {"flowAlias":"continuum direct grant loa2","requirement":"CONDITIONAL","priority":30,"authenticatorFlow":True,"userSetupAllowed":False}]},
  {"alias":"continuum direct grant loa1","providerId":"basic-flow","topLevel":False,"builtIn":False,
   "authenticationExecutions":[
    {"authenticator":"conditional-level-of-authentication","authenticatorConfig":"dg-loa1","requirement":"REQUIRED","priority":10,"authenticatorFlow":False,"userSetupAllowed":False},
    {"authenticator":"direct-grant-validate-password","requirement":"REQUIRED","priority":20,"authenticatorFlow":False,"userSetupAllowed":False}]},
  {"alias":"continuum direct grant loa2","providerId":"basic-flow","topLevel":False,"builtIn":False,
   "authenticationExecutions":[
    {"authenticator":"conditional-level-of-authentication","authenticatorConfig":"dg-loa2","requirement":"REQUIRED","priority":10,"authenticatorFlow":False,"userSetupAllowed":False},
    {"authenticator":"direct-grant-validate-otp","requirement":"REQUIRED","priority":20,"authenticatorFlow":False,"userSetupAllowed":False}]},
  {"alias":"continuum direct grant otp","description":"D41: password + OTP always required (no LoA conditions)","providerId":"basic-flow","topLevel":True,"builtIn":False,
   "authenticationExecutions":[
    {"authenticator":"direct-grant-validate-username","requirement":"REQUIRED","priority":10,"authenticatorFlow":False,"userSetupAllowed":False},
    {"authenticator":"direct-grant-validate-password","requirement":"REQUIRED","priority":20,"authenticatorFlow":False,"userSetupAllowed":False},
    {"authenticator":"direct-grant-validate-otp","requirement":"REQUIRED","priority":30,"authenticatorFlow":False,"userSetupAllowed":False}]}],
 "authenticatorConfig":[
  {"alias":"dg-loa1","config":{"loa-condition-level":"1","loa-max-age":"36000"}},
  {"alias":"dg-loa2","config":{"loa-condition-level":"2","loa-max-age":"0"}}],
 "clients":[{"clientId":"continuum-auth-bff","enabled":True,"publicClient":False,"clientAuthenticatorType":"client-secret",
   "secret":os.environ["SECRET"],"standardFlowEnabled":False,"implicitFlowEnabled":False,"directAccessGrantsEnabled":True,
   "serviceAccountsEnabled":False,"fullScopeAllowed":False,"redirectUris":[],"webOrigins":[],
   "attributes":{"client.session.idle.timeout":"900","access.token.lifespan":"300"}}],
 "users":[{"username":"dsi.admin","enabled":True,"email":"dsi.admin@spike.invalid","emailVerified":True,"firstName":"DSI","lastName":"Admin",
   "credentials":[{"type":"password","value":os.environ["PASSWORD"],"temporary":False},
                  {"type":"otp","userLabel":"spike","secretData":json.dumps({"value":os.environ["SEED"]}),"credentialData":otp_data}]}]}
print(json.dumps(realm))
PY
api import-realm -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms" --data-binary @/tmp/spike-d41-realm.json
rm -f /tmp/spike-d41-realm.json

echo "2) bind flow to client only (authenticationFlowBindingOverrides.direct_grant)"
FID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/authentication/flows" | python -c "import sys,json;print([f['id'] for f in json.load(sys.stdin) if f['alias']=='continuum direct grant loa'][0])")"
CID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | python -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")"
set_client() { # $1 = python expression mutating c
  relogin
  curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID" | FID="$FID" python -c "import sys,json,os;c=json.load(sys.stdin);$1;print(json.dumps(c))" > /tmp/spike-d41-client.json
  api update-client -X PUT "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients/$CID" --data-binary @/tmp/spike-d41-client.json; rm -f /tmp/spike-d41-client.json; }
set_client "c['authenticationFlowBindingOverrides']={'direct_grant':os.environ['FID']}"

# TOTP for time-step offset $1 (KC accepts offsets -1..+1 with lookAround 1; each code usable once)
totp() { python -c "
import hmac,hashlib,struct,time,os,sys
k=os.environ['SEED'].encode(); c=int(time.time())//30+int(sys.argv[1])
h=hmac.new(k,struct.pack('>Q',c),hashlib.sha1).digest(); o=h[-1]&15
print('%06d'%((struct.unpack('>I',h[o:o+4])[0]&0x7fffffff)%1000000))" "$1"; }
TE="$KC/realms/$REALM/protocol/openid-connect/token"
grant() { # $1 label, rest = extra curl -d args
  local label="$1"; shift
  curl -s -d grant_type=password -d client_id=$CLIENT --data-urlencode "client_secret=$SECRET" -d username=dsi.admin \
    --data-urlencode "password=$PASSWORD" -d scope=openid "$@" "$TE" | python -c '
import sys,json,base64
r=json.load(sys.stdin); t=r.get("access_token"); lab=sys.argv[1]
if not t: print("   %-46s -> error=%s (%s)" % (lab, r.get("error"), r.get("error_description"))); sys.exit(0)
def claims(tok):
  p=tok.split(".")[1]; return json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))
a=claims(t); i=claims(r["id_token"]) if r.get("id_token") else {}
print("   %-46s -> access.acr=%s id.acr=%s amr=%s" % (lab, a.get("acr"), i.get("acr"), a.get("amr")))' "$label"; }

echo "3) scenarios (client override only, no client acr defaults)"
grant "A password only"
grant "B password + acr_values=2 (no otp)" -d acr_values=2
grant "C password + otp + acr_values=2" -d otp="$(totp -1)" -d acr_values=2
grant "D password + otp (no acr_values)" -d otp="$(totp 0)"
grant "E password + otp + claims acr essential 2" -d otp="$(totp 1)" --data-urlencode 'claims={"id_token":{"acr":{"essential":true,"values":["2"]}}}'

echo "4) client default.acr.values=2 + minimum.acr.value=2"
set_client "c.setdefault('attributes',{}).update({'default.acr.values':'2','minimum.acr.value':'2'})"
sleep 31
grant "F password only (client default acr 2)"
grant "G password + otp (client default acr 2)" -d otp="$(totp -1)"
grant "H password + wrong otp (client default acr 2)" -d otp=000000
PW=wrong-password grant "I wrong password (LoA flow)"

echo "5) rebind client to 'continuum direct grant otp' (OTP always required), client acr attrs removed"
FID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/authentication/flows" | python -c "import sys,json;print([f['id'] for f in json.load(sys.stdin) if f['alias']=='continuum direct grant otp'][0])")"
set_client "c['authenticationFlowBindingOverrides']={'direct_grant':os.environ['FID']};[c['attributes'].pop(k,None) for k in ('default.acr.values','minimum.acr.value')]"
sleep 31
grant "J password only"
grant "K password + wrong otp" -d otp=000000
grant "L password + otp" -d otp="$(totp -1)"
grant "M password + otp + acr_values=2" -d otp="$(totp 0)" -d acr_values=2

relogin
if [ "${KEEP:-0}" = 1 ]; then echo "realm $REALM kept (KEEP=1)"; else api delete-realm -X DELETE "${auth[@]}" "$KC/admin/realms/$REALM"; fi
