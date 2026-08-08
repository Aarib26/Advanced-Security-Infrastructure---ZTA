#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/resolve_keycloak.sh"
: "${KC_BOOTSTRAP_ADMIN_USERNAME:?Set KC_BOOTSTRAP_ADMIN_USERNAME}"
: "${KC_BOOTSTRAP_ADMIN_PASSWORD:?Set KC_BOOTSTRAP_ADMIN_PASSWORD}"
CLIENT_ID="freeradius-nac"

echo "== Resolving Keycloak at ${KEYCLOAK_URL} (realm: ${KEYCLOAK_REALM}) =="
ADMIN_TOKEN=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "username=${KC_BOOTSTRAP_ADMIN_USERNAME}" \
  -d "password=${KC_BOOTSTRAP_ADMIN_PASSWORD}" -d "grant_type=password" \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
[[ -z "$ADMIN_TOKEN" ]] && { echo "ERROR: failed to get admin token" >&2; exit 1; }

EXISTING=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${CLIENT_ID}")

if [[ "$EXISTING" != "[]" ]]; then
  echo "== Client already exists — printing secret =="
  CLIENT_UUID=$(echo "$EXISTING" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
else
  echo "== Creating client '${CLIENT_ID}' =="
  curl -sf -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
    -d '{"clientId":"'"${CLIENT_ID}"'","protocol":"openid-connect","publicClient":false,"standardFlowEnabled":false,"implicitFlowEnabled":false,"directAccessGrantsEnabled":true,"serviceAccountsEnabled":false,"description":"NAC (FreeRADIUS 802.1X) identity federation — ROPC grant only"}'
  CLIENT_UUID=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${CLIENT_ID}" \
    | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

SECRET=$(curl -sf -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/client-secret" \
  | grep -o '"value":"[^"]*"' | cut -d'"' -f4)

echo ""
echo "client_id:     ${CLIENT_ID}"
echo "client_secret: ${SECRET}"
echo "^ copy this secret, you need it in step 4"
