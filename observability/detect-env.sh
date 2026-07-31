#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"

echo "== ZTA observability layer :: environment detection =="

UPLINK_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
if [ -z "$UPLINK_IF" ]; then
  echo "ERROR: could not detect a default-route interface. Is networking up?"
  exit 1
fi
echo "Uplink interface:      $UPLINK_IF"

TS_IF=""
TS_IP=""
if command -v tailscale >/dev/null 2>&1; then
  TS_IP=$(tailscale ip -4 2>/dev/null || true)
  if [ -n "$TS_IP" ]; then
    TS_IF=$(ip -br addr show | awk -v ip="$TS_IP" '$0 ~ ip {print $1; exit}')
  fi
fi
echo "Tailscale interface:   ${TS_IF:-<not present on this host>}"
echo "Tailscale IP:          ${TS_IP:-<not present>}"

UPLINK_CIDR=$(ip -o -4 addr show dev "$UPLINK_IF" | awk '{print $4}' | head -1)
echo "Uplink CIDR:            ${UPLINK_CIDR:-<none found>}"

CILIUM_HOST_IP=""
CILIUM_PRESENT="false"
if ip -br addr show 2>/dev/null | grep -q 'cilium_host'; then
  CILIUM_PRESENT="true"
  CILIUM_HOST_IP=$(ip -br addr show | awk '/cilium_host@/ {print $3}' | cut -d/ -f1)
fi
echo "Cilium present:         $CILIUM_PRESENT"
echo "Cilium host IP:         ${CILIUM_HOST_IP:-n/a}"

touch "$ENV_FILE"

set_kv () {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
  else
    echo "${key}=${val}" >> "$ENV_FILE"
  fi
}

set_kv "OBS_UPLINK_IF" "$UPLINK_IF"
set_kv "OBS_UPLINK_CIDR" "${UPLINK_CIDR:-}"
set_kv "OBS_TAILSCALE_IF" "${TS_IF:-}"
set_kv "OBS_TAILSCALE_IP" "${TS_IP:-}"
set_kv "OBS_CILIUM_PRESENT" "$CILIUM_PRESENT"
set_kv "OBS_CILIUM_HOST_IP" "${CILIUM_HOST_IP:-}"
set_kv "OBS_NODE_HOSTNAME" "$(hostname)"

echo ""
echo "== Written to $ENV_FILE =="
grep '^OBS_' "$ENV_FILE"
