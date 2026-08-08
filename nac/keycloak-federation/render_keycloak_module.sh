#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/resolve_keycloak.sh"

: "${KEYCLOAK_NAC_CLIENT_SECRET:?Set KEYCLOAK_NAC_CLIENT_SECRET}"

OUT=/etc/freeradius/3.0/mods-available/keycloak-nac

if [[ -n "${KEYCLOAK_CA_FILE:-}" ]]; then
    TLS_BLOCK="
        tls {
            ca_file = ${KEYCLOAK_CA_FILE}
        }"
else
    TLS_BLOCK=""
fi

REST_TIMEOUT="${KEYCLOAK_REST_TIMEOUT:-15}"

sudo tee "$OUT" > /dev/null << MODEOF
# Auto-rendered by render_keycloak_module.sh — do not hand-edit.
rest keycloak_nac {
    connect_uri = "${KEYCLOAK_URL}"
    connect_timeout = ${REST_TIMEOUT}

    authenticate {
        uri = "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token"
        method = 'post'
        body = 'post'
        data = 'grant_type=password&client_id=freeradius-nac&client_secret=${KEYCLOAK_NAC_CLIENT_SECRET}&username=%{User-Name}&password=%{User-Password}'
        timeout = ${REST_TIMEOUT}${TLS_BLOCK}
    }
}
MODEOF

echo "Rendered ${OUT} with KEYCLOAK_URL=${KEYCLOAK_URL}, KEYCLOAK_REALM=${KEYCLOAK_REALM}, timeout=${REST_TIMEOUT}s"
