#!/usr/bin/env bash
# Recette realm (non-prod, sim Keycloak): backend service clients, provisioned EXACTLY as the realm fragments
#   realms/continuum-admin-service.fragment.json  -> continuum-admin-service / realm role continuum-user-admin = {manage-users}
#   realms/continuum-directory-sync.fragment.json -> continuum-directory-sync / realm role continuum-directory-sync = {manage-users, view-realm}
# Both: confidential, client_credentials only, fullScopeAllowed=false + scope mapping on their realm role.
# No manage-realm, no clients access. Also deletes the superseded read-only continuum-backend client.
# Signed off by tech-lead (chat #3909, 2026-11-02). Idempotent.
# Secrets go to recette/.env.local (gitignored), never printed/committed. KC_DIRECTORY_SYNC_SECRET (fragment) and
# CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET (backend) are written with the same value.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"
: "${KC_ADMIN_PASSWORD:?set KC_ADMIN_PASSWORD (master admin of the sim Keycloak)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOKEN="$(curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" --data-urlencode password="$KC_ADMIN_PASSWORD" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")"
auth=(-H "Authorization: Bearer $TOKEN"); J=(-H "Content-Type: application/json")
A="$KC/admin/realms/$REALM"
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }
get() { curl -s "${auth[@]}" "$A/$1"; }
py() { python -c "import sys,json;L=json.load(sys.stdin);$1"; }

RM="$(get "clients?clientId=realm-management" | py "print(L[0]['id'])")"
RM_ROLES="$(get "clients/$RM/roles")"
rm_roles() { echo "$RM_ROLES" | python -c "import sys,json;W=sys.argv[1].split(',');print(json.dumps([r for r in json.load(sys.stdin) if r['name'] in W]))" "$1"; }

# provision <clientId> <display name> <realm role> <comma-separated realm-management roles> <role description>
provision() {
  local CLIENT="$1" NAME="$2" ROLE="$3" WANT="$4" DESC="$5"
  echo "== $CLIENT"
  echo "1) realm role $ROLE = {$WANT}"
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" "$A/roles/$ROLE")" != 200 ]; then
    api create-role -X POST "${auth[@]}" "${J[@]}" "$A/roles" -d "{\"name\":\"$ROLE\",\"description\":\"$DESC\"}"
  fi
  local EXTRA; EXTRA="$(get "roles/$ROLE/composites" | python -c "import sys,json;W=sys.argv[1].split(',');print(json.dumps([r for r in json.load(sys.stdin) if not (r.get('clientRole') and r['name'] in W)]))" "$WANT")"
  [ "$EXTRA" != "[]" ] && api remove-extra-composites -X DELETE "${auth[@]}" "${J[@]}" "$A/roles/$ROLE/composites" -d "$EXTRA"
  api set-composites -X POST "${auth[@]}" "${J[@]}" "$A/roles/$ROLE/composites" -d "$(rm_roles "$WANT")"
  local ROLE_REP; ROLE_REP="$(get "roles/$ROLE")"

  echo "2) client (confidential, client_credentials only, fullScopeAllowed=false)"
  local BODY="{\"clientId\":\"$CLIENT\",\"name\":\"$NAME\",\"enabled\":true,\"protocol\":\"openid-connect\",\"publicClient\":false,\"clientAuthenticatorType\":\"client-secret\",\"serviceAccountsEnabled\":true,\"standardFlowEnabled\":false,\"implicitFlowEnabled\":false,\"directAccessGrantsEnabled\":false,\"fullScopeAllowed\":false}"
  local CID; CID="$(get "clients?clientId=$CLIENT" | py "print(L[0]['id'] if L else '')")"
  if [ -z "$CID" ]; then
    api create-client -X POST "${auth[@]}" "${J[@]}" "$A/clients" -d "$BODY"
    CID="$(get "clients?clientId=$CLIENT" | py "print(L[0]['id'])")"
  else
    api update-client -X PUT "${auth[@]}" "${J[@]}" "$A/clients/$CID" -d "$BODY"
  fi

  echo "3) scope mapping + service-account realm role (only $ROLE)"
  api scope-mapping -X POST "${auth[@]}" "${J[@]}" "$A/clients/$CID/scope-mappings/realm" -d "[$ROLE_REP]"
  local SA; SA="$(get "clients/$CID/service-account-user" | py "print(L['id'])")"
  local SA_EXTRA; SA_EXTRA="$(get "users/$SA/role-mappings/realm" | python -c "import sys,json;print(json.dumps([r for r in json.load(sys.stdin) if r['name']!=sys.argv[1] and not r['name'].startswith('default-roles-')]))" "$ROLE")"
  [ "$SA_EXTRA" != "[]" ] && api remove-extra-sa-roles -X DELETE "${auth[@]}" "${J[@]}" "$A/users/$SA/role-mappings/realm" -d "$SA_EXTRA"
  local SA_CLIENT; SA_CLIENT="$(get "users/$SA/role-mappings/clients/$RM")"
  [ "$SA_CLIENT" != "[]" ] && api remove-direct-rm-roles -X DELETE "${auth[@]}" "${J[@]}" "$A/users/$SA/role-mappings/clients/$RM" -d "$SA_CLIENT"
  api grant-role -X POST "${auth[@]}" "${J[@]}" "$A/users/$SA/role-mappings/realm" -d "[$ROLE_REP]"
  SECRET="$(get "clients/$CID/client-secret" | py "print(L['value'])")"
}

put_env() { # put_env KEY VALUE -> recette/.env.local
  touch "$HERE/.env.local"; grep -v "^$1=" "$HERE/.env.local" > "$HERE/.env.tmp" || true
  echo "$1=$2" >> "$HERE/.env.tmp"; mv "$HERE/.env.tmp" "$HERE/.env.local"
}

provision continuum-admin-service "Continuum backend admin service" continuum-user-admin "manage-users" \
  "D40: reset MFA credentials and close sessions of users (admin REST). Composite of manage-users only."
put_env KC_ADMIN_SERVICE_SECRET "$SECRET"

provision continuum-directory-sync "Continuum backend directory sync" continuum-directory-sync "manage-users,view-realm" \
  "Trigger user-federation sync and resolve the LDAP component by name. Composite of manage-users + view-realm only."
put_env KC_DIRECTORY_SYNC_SECRET "$SECRET"
put_env CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET "$SECRET"
unset SECRET
echo "   secrets -> recette/.env.local (KC_ADMIN_SERVICE_SECRET, KC_DIRECTORY_SYNC_SECRET = CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET)"

echo "== superseded read-only client continuum-backend"
OLD="$(get "clients?clientId=continuum-backend" | py "print(L[0]['id'] if L else '')")"
if [ -n "$OLD" ]; then api delete-client -X DELETE "${auth[@]}" "$A/clients/$OLD"; else echo "   absent"; fi
grep -v '^CONTINUUM_BACKEND_CLIENT_SECRET=' "$HERE/.env.local" > "$HERE/.env.tmp" || true; mv "$HERE/.env.tmp" "$HERE/.env.local"

cat <<EOF
Backend env for recette (non-secret part; secrets from recette/.env.local):
  CONTINUUM_KC_ADMIN_BASE_URL=$KC          (empty = 503 on admin calls)
  CONTINUUM_KC_ADMIN_REALM=$REALM
  CONTINUUM_KC_ADMIN_CLIENT_ID=continuum-admin-service
  CONTINUUM_DIRECTORY_SYNC_CLIENT_ID=continuum-directory-sync
  CONTINUUM_DIRECTORY_SYNC_ENABLED=true + CONTINUUM_DIRECTORY_SYNC_SOURCE=<source code>   (only if the sync job must run)
Then run recette/verify-recette-backend-roles.sh
EOF
