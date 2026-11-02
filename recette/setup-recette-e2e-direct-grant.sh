#!/usr/bin/env bash
# DEV/RECETTE ONLY — NEVER SHIPPED TO PROD (D41 / ADR 0014: BFF is the target, direct grant is spike/e2e only).
# Creates the confidential client `continuum-admin-e2e-dg` on the recette realm of the sim Keycloak so that
# admin-web Cypress e2e can obtain tokens with cy.request (Resource Owner Password grant) instead of cy.origin.
# Conditions (meeting 2026-11-02 D41): scopes openid/profile/email only; mappers tenant_id, continuum_user_id,
# acr (hard-coded "2", same simulation as continuum-admin); no HSTS change committed.
# Idempotent. The client secret is regenerated only on creation and written to recette/.env.local
# (git-ignored) as RECETTE_E2E_DG_CLIENT_SECRET — never printed.
set -euo pipefail
KC="${KC_URL:-http://localhost:8180}"; REALM="${KC_REALM:-recette}"; CLIENT=continuum-admin-e2e-dg
case "$KC" in http://localhost:*|http://127.0.0.1:*) ;; *) echo "refusing: $KC is not a local sim Keycloak" >&2; exit 1;; esac
[ "$REALM" = recette ] || { echo "refusing: realm must be recette" >&2; exit 1; }
ENV_FILE="$(dirname "$0")/.env.local"
TOKEN="$(curl -s -d client_id=admin-cli -d username="${KC_ADMIN:-admin}" -d password="${KC_ADMIN_PASSWORD:-dev-keycloak-admin}" \
  -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")"
auth=(-H "Authorization: Bearer $TOKEN"); J=(-H "Content-Type: application/json")
api() { curl -s -o /dev/null -w "   $1 -> %{http_code}\n" "${@:2}"; }
cid() { curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients?clientId=$CLIENT" | python -c "import sys,json;L=json.load(sys.stdin);print(L[0]['id'] if L else '')"; }

echo "1) client $CLIENT"
CID="$(cid)"
if [ -z "$CID" ]; then
  api create-client -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients" -d '{"clientId":"'"$CLIENT"'","name":"Continuum - admin-web e2e direct grant (DEV/RECETTE ONLY)","description":"D41 spike/e2e only - never in prod","enabled":true,"publicClient":false,"clientAuthenticatorType":"client-secret","standardFlowEnabled":false,"implicitFlowEnabled":false,"directAccessGrantsEnabled":true,"serviceAccountsEnabled":false,"fullScopeAllowed":false,"redirectUris":[],"webOrigins":[],"defaultClientScopes":["basic","profile","email"],"optionalClientScopes":[],"attributes":{"client.session.idle.timeout":"900","access.token.lifespan":"300"}}'
  CID="$(cid)"
  SECRET="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/client-secret" | python -c "import sys,json;print(json.load(sys.stdin)['value'])")"
  touch "$ENV_FILE"; grep -v '^RECETTE_E2E_DG_CLIENT_SECRET=' "$ENV_FILE" > "$ENV_FILE.tmp" || true
  echo "RECETTE_E2E_DG_CLIENT_SECRET=$SECRET" >> "$ENV_FILE.tmp"; mv "$ENV_FILE.tmp" "$ENV_FILE"
  echo "   secret -> $ENV_FILE (RECETTE_E2E_DG_CLIENT_SECRET)"
else echo "   = $CLIENT"; fi

echo "2) default scopes: exactly basic/profile/email (openid implicit)"
scopes="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/client-scopes" | python -c "import sys,json;print(' '.join(s['name']+'='+s['id'] for s in json.load(sys.stdin)))")"
sid() { for kv in $scopes; do [ "${kv%%=*}" = "$1" ] && echo "${kv#*=}"; done; }
for kind in default-client-scopes optional-client-scopes; do
  for s in $(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/$kind" | python -c "import sys,json;print(' '.join(s['name'] for s in json.load(sys.stdin)))"); do
    case "$kind:$s" in default-client-scopes:basic|default-client-scopes:profile|default-client-scopes:email) ;;
      *) api "- $kind $s" -X DELETE "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/$kind/$(sid "$s")";; esac
  done
done
for s in basic profile email; do api "+ default $s" -X PUT "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/default-client-scopes/$(sid "$s")"; done

echo "3) mappers"
existing="$(curl -s "${auth[@]}" "$KC/admin/realms/$REALM/clients/$CID/protocol-mappers/models" | python -c "import sys,json;print(' '.join(m['name'] for m in json.load(sys.stdin)))")"
add_mapper() { case " $existing " in *" $1 "*) echo "   = $1";; *) api "+ $1" -X POST "${auth[@]}" "${J[@]}" "$KC/admin/realms/$REALM/clients/$CID/protocol-mappers/models" -d "$2";; esac; }
add_mapper aud-continuum-admin '{"name":"aud-continuum-admin","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.client.audience":"continuum-admin","id.token.claim":"false","access.token.claim":"true"}}'
add_mapper tenant_id '{"name":"tenant_id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"tenant_id","claim.name":"tenant_id","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true"}}'
add_mapper continuum_user_id '{"name":"continuum_user_id","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"continuum_user_id","claim.name":"continuum_user_id","jsonType.label":"String","id.token.claim":"true","access.token.claim":"true"}}'
add_mapper acr-step-up-recette '{"name":"acr-step-up-recette","protocol":"openid-connect","protocolMapper":"oidc-hardcoded-claim-mapper","config":{"claim.name":"acr","claim.value":"2","jsonType.label":"String","id.token.claim":"false","access.token.claim":"true"}}'
