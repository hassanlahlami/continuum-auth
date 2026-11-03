#!/usr/bin/env bash
# Live checks for setup-recette-backend-roles.sh, using ONLY the service-account tokens (no master admin).
# Expected: token roles = exactly the composite; user lookup 200, credentials 200, logout 204 (admin-service);
# components?name 200 (directory-sync); manage-realm (create realm role) 403 and clients list 403 for both.
# CHECK_USER is a recette user whose sessions may be closed (default dsi.admin). Exit 1 on any mismatch.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"; U="${CHECK_USER:-dsi.admin}"
HERE="$(cd "$(dirname "$0")" && pwd)"; set -a; . "$HERE/.env.local"; set +a
A="$KC/admin/realms/$REALM"; FAIL=0
tok() { curl -s -d grant_type=client_credentials -d client_id="$1" --data-urlencode client_secret="$2" \
  "$KC/realms/$REALM/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])"; }
roles() { python - "$1" <<'PY'
import sys,json,base64
p=sys.argv[1].split('.')[1]; c=json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4)))
print(sorted(c.get('resource_access',{}).get('realm-management',{}).get('roles',[])))
PY
}
check() { # check <label> <expected code> <token> curl-args...
  local got; got="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $3" "${@:4}")"
  if [ "$got" = "$2" ]; then echo "   OK   $1 -> $got"; else echo "   FAIL $1 -> $got (expected $2)"; FAIL=1; fi
}
expect_roles() { local r; r="$(roles "$1")"; if [ "$r" = "$2" ]; then echo "   OK   realm-management roles $r"; else echo "   FAIL roles $r (expected $2)"; FAIL=1; fi; }

echo "== continuum-admin-service"
T="$(tok continuum-admin-service "$KC_ADMIN_SERVICE_SECRET")"
expect_roles "$T" "['manage-users']"
UID_="$(curl -s -H "Authorization: Bearer $T" "$A/users?username=$U&exact=true" | python -c "import sys,json;L=json.load(sys.stdin);print(L[0]['id'] if L else '')")"
[ -n "$UID_" ] && echo "   OK   username lookup $U" || { echo "   FAIL username lookup $U"; FAIL=1; }
check "users/{id}/credentials" 200 "$T" "$A/users/$UID_/credentials"
check "users/{id}/logout" 204 "$T" -X POST "$A/users/$UID_/logout"
check "manage-realm (POST roles)" 403 "$T" -X POST -H "Content-Type: application/json" "$A/roles" -d '{"name":"zz-verify-should-403"}'
check "clients list" 403 "$T" "$A/clients"

echo "== continuum-directory-sync"
T="$(tok continuum-directory-sync "$CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET")"
[ "$KC_DIRECTORY_SYNC_SECRET" = "$CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET" ] && echo "   OK   KC_DIRECTORY_SYNC_SECRET == CONTINUUM_DIRECTORY_SYNC_CLIENT_SECRET" || { echo "   FAIL secret env mismatch"; FAIL=1; }
expect_roles "$T" "['manage-users', 'view-realm']"
check "components?name (view-realm)" 200 "$T" "$A/components?type=org.keycloak.storage.UserStorageProvider&name=${LDAP_COMPONENT_NAME:-ldap}"
check "manage-realm (POST roles)" 403 "$T" -X POST -H "Content-Type: application/json" "$A/roles" -d '{"name":"zz-verify-should-403"}'
check "clients list" 403 "$T" "$A/clients"

echo "== superseded continuum-backend client"
check "client_credentials continuum-backend rejected" 401 "" -d grant_type=client_credentials -d client_id=continuum-backend -d client_secret=x "$KC/realms/$REALM/protocol/openid-connect/token"
exit $FAIL
