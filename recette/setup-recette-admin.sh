#!/usr/bin/env bash
# Recette realm (non-prod, sim Keycloak): continuum-admin SPA client + local dsi.admin user + acr>=2 flow.
# Idempotent. The dsi.admin password is read from RECETTE_DSI_ADMIN_PASSWORD (never committed/printed).
# acr=2 is a hard-coded claim mapper (same as banque-demo, DEV/RECETTE ONLY): simulates the MFA step-up
# required by the backend (§4.3.3). In production the acr comes from a real step-up (OTP/WebAuthn).
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"
: "${RECETTE_DSI_ADMIN_PASSWORD:?set RECETTE_DSI_ADMIN_PASSWORD}"
TENANT_ID="11111111-1111-1111-1111-111111111111"; ADMIN_UUID="33333333-3333-3333-3333-333333333333"
TOKEN="$(curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" -d password="${KC_ADMIN_PASSWORD:-dev-keycloak-admin}" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")"
auth=(-H "Authorization: Bearer $TOKEN"); J=(-H "Content-Type: application/json")
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }

echo "1) unmanaged attributes ENABLED"
api profile -X PUT "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/users/profile" \
  -d '{"unmanagedAttributePolicy":"ENABLED","attributes":[{"name":"username","permissions":{"view":["admin","user"],"edit":["admin","user"]}},{"name":"email","permissions":{"view":["admin","user"],"edit":["admin","user"]}},{"name":"firstName","permissions":{"view":["admin","user"],"edit":["admin","user"]}},{"name":"lastName","permissions":{"view":["admin","user"],"edit":["admin","user"]}}]}'

echo "2) client continuum-admin"
CID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=continuum-admin" | python -c "import sys,json;L=json.load(sys.stdin);print(L[0]['id'] if L else '')")"
if [ -z "$CID" ]; then
  api create-client -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients" -d '{"clientId":"continuum-admin","name":"Continuum - Admin Systeme (recette)","enabled":true,"publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":false,"implicitFlowEnabled":false,"redirectUris":["http://localhost:4201/*","http://localhost:4202/*"],"webOrigins":["http://localhost:4201","http://localhost:4202"],"attributes":{"pkce.code.challenge.method":"S256","post.logout.redirect.uris":"http://localhost:4201/*##http://localhost:4202/*","client.session.idle.timeout":"900"}}'
  CID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=continuum-admin" | python -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")"
fi
existing="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/protocol-mappers/models" | python -c "import sys,json;print(' '.join(m['name'] for m in json.load(sys.stdin)))")"
add_mapper() { case " $existing " in *" $1 "*) echo "   = $1";; *) api "+ $1" -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients/$CID/protocol-mappers/models" -d "$2";; esac; }
add_mapper aud-continuum-admin '{"name":"aud-continuum-admin","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"continuum-admin","id.token.claim":"false","access.token.claim":"true"}}'
add_mapper tenant_id '{"name":"tenant_id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"tenant_id","claim.name":"tenant_id","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true"}}'
add_mapper continuum_user_id '{"name":"continuum_user_id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"continuum_user_id","claim.name":"continuum_user_id","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true"}}'
add_mapper acr-step-up-recette '{"name":"acr-step-up-recette","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"acr","claim.value":"2","jsonType.label":"String","id.token.claim":"false","access.token.claim":"true"}}'

echo "3) user dsi.admin"
UID_="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/users?username=dsi.admin&exact=true" | python -c "import sys,json;L=json.load(sys.stdin);print(L[0]['id'] if L else '')")"
if [ -z "$UID_" ]; then
  body="$(TENANT_ID=$TENANT_ID CUID=$ADMIN_UUID PW="$RECETTE_DSI_ADMIN_PASSWORD" python -c "import json,os;print(json.dumps({'username':'dsi.admin','enabled':True,'emailVerified':True,'firstName':'DSI','lastName':'Admin','email':'dsi.admin@recette.local','attributes':{'tenant_id':[os.environ['TENANT_ID']],'continuum_user_id':[os.environ['CUID']]},'credentials':[{'type':'password','value':os.environ['PW'],'temporary':False}]}))")"
  api create-user -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/users" -d "$body"
else echo "   = dsi.admin"; fi
