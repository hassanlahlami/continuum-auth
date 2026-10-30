#!/usr/bin/env bash
# Recette realm (non-prod, sim Keycloak): continuum-backend service-account client for directory sync.
# Confidential, client_credentials only (no browser/direct-grant flows), no realm roles, and ONLY the
# realm-management client roles view-users + query-users + query-groups (read users/groups of this realm).
# Idempotent. The generated secret is written to recette/.env.local (gitignored), never printed/committed.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"; CLIENT="continuum-backend"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOKEN="$(curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" -d password="${KC_ADMIN_PASSWORD:-dev-keycloak-admin}" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")"
auth=(-H "Authorization: Bearer $TOKEN"); J=(-H "Content-Type: application/json")
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }
jq1() { python -c "import sys,json;L=json.load(sys.stdin);print($1)"; }

echo "1) client $CLIENT"
CID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq1 "L[0]['id'] if L else ''")"
BODY='{"clientId":"continuum-backend","name":"Continuum - Backend service (recette)","enabled":true,"publicClient":false,"serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false,"implicitFlowEnabled":false,"clientAuthenticatorType":"client-secret","fullScopeAllowed":true}'
if [ -z "$CID" ]; then
  api create-client -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients" -d "$BODY"
  CID="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | jq1 "L[0]['id']")"
else
  api update-client -X PUT "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients/$CID" -d "$BODY"
fi

echo "2) service-account roles (realm-management: view-users, query-users, query-groups)"
SA="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/service-account-user" | python -c "import sys,json;print(json.load(sys.stdin)['id'])")"
RM="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=realm-management" | jq1 "L[0]['id']")"
ROLES="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$RM/roles" | python -c "import sys,json;print(json.dumps([r for r in json.load(sys.stdin) if r['name'] in ('view-users','query-users','query-groups')]))")"
api grant-roles -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/users/$SA/role-mappings/clients/$RM" -d "$ROLES"

echo "3) secret -> recette/.env.local"
SECRET="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/client-secret" | python -c "import sys,json;print(json.load(sys.stdin)['value'])")"
touch "$HERE/.env.local"; grep -v '^CONTINUUM_BACKEND_CLIENT_SECRET=' "$HERE/.env.local" > "$HERE/.env.tmp" || true
echo "CONTINUUM_BACKEND_CLIENT_SECRET=$SECRET" >> "$HERE/.env.tmp"; mv "$HERE/.env.tmp" "$HERE/.env.local"
echo "   written"
