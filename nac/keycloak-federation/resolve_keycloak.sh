#!/usr/bin/env bash
set -euo pipefail

resolve_keycloak_url() {
    if [[ -n "${KEYCLOAK_URL:-}" ]]; then
        echo "${KEYCLOAK_URL}"
        return 0
    fi
    if curl -sf -o /dev/null --max-time 15 "http://127.0.0.1:8081/realms/master"; then
        echo "http://127.0.0.1:8081"
        return 0
    fi
    local ts_status
    if ts_status=$(tailscale status --json 2>/dev/null); then
        local magicdns_suffix
        magicdns_suffix=$(echo "$ts_status" | grep -o '"MagicDNSSuffix":"[^"]*"' | cut -d'"' -f4 || true)
        if [[ -n "$magicdns_suffix" ]]; then
            local host_hint="${KEYCLOAK_HOST_HINT:-ztauser}"
            echo "https://${host_hint}.${magicdns_suffix}:8444"
            return 0
        fi
    fi
    echo "ERROR: could not resolve Keycloak URL — set KEYCLOAK_URL explicitly" >&2
    return 1
}

resolve_keycloak_realm() {
    echo "${KEYCLOAK_REALM:-zta}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "KEYCLOAK_URL=$(resolve_keycloak_url)"
    echo "KEYCLOAK_REALM=$(resolve_keycloak_realm)"
else
    export KEYCLOAK_URL="$(resolve_keycloak_url)"
    export KEYCLOAK_REALM="$(resolve_keycloak_realm)"
fi
