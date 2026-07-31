#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"
SURICATA_YAML="${SURICATA_YAML:-suricata/suricata/suricata.yaml}"
ZEEK_NODE_CFG="${ZEEK_NODE_CFG:-zeek/node.cfg}"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Run detect-env.sh first."
  exit 1
fi

set -a; source "$ENV_FILE"; set +a

if [ -z "${OBS_UPLINK_IF:-}" ]; then
  echo "ERROR: OBS_UPLINK_IF not set in $ENV_FILE. Run detect-env.sh first."
  exit 1
fi

if ! command -v yq >/dev/null 2>&1; then
  echo "yq not found — installing a local static binary to ./bin/yq"
  mkdir -p ./bin
  curl -sL "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64" -o ./bin/yq
  chmod +x ./bin/yq
  export PATH="$PWD/bin:$PATH"
fi

echo "== Rendering suricata.yaml =="
if [ -f "$SURICATA_YAML" ]; then
  cp "$SURICATA_YAML" "${SURICATA_YAML}.bak.$(date +%s)"

  yq -i "
    .af-packet[0].interface = \"${OBS_UPLINK_IF}\" |
    .af-packet[0].cluster-id = 99 |
    .af-packet[0].cluster-type = \"cluster_flow\" |
    .af-packet[0].defrag = true |
    .af-packet[0].threads = \"auto\"
  " "$SURICATA_YAML"

  if [ "${OBS_CILIUM_PRESENT:-false}" = "true" ] && [ -n "${OBS_CILIUM_HOST_IP:-}" ]; then
    yq -i "
      .af-packet[1].interface = \"cilium_host\" |
      .af-packet[1].cluster-id = 98 |
      .af-packet[1].cluster-type = \"cluster_flow\" |
      .af-packet[1].defrag = true |
      .af-packet[1].threads = \"auto\"
    " "$SURICATA_YAML"
  else
    yq -i 'del(.af-packet[1])' "$SURICATA_YAML" 2>/dev/null || true
  fi

  HOME_NET_PARTS=()
  [ -n "${OBS_TAILSCALE_IP:-}" ] && HOME_NET_PARTS+=("${OBS_TAILSCALE_IP}/32")
  [ -n "${OBS_CILIUM_HOST_IP:-}" ] && HOME_NET_PARTS+=("${OBS_CILIUM_HOST_IP}/32")
  [ -n "${OBS_UPLINK_CIDR:-}" ] && HOME_NET_PARTS+=("${OBS_UPLINK_CIDR}")
  HOME_NET_PARTS+=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")

  HOME_NET_STR="[$(IFS=,; echo "${HOME_NET_PARTS[*]}")]"
  yq -i ".vars.\"address-groups\".HOME_NET = \"${HOME_NET_STR}\"" "$SURICATA_YAML"

  echo "  af-packet + HOME_NET updated. Backup saved alongside original."
  echo "  HOME_NET = ${HOME_NET_STR}"
else
  echo "  SKIP: $SURICATA_YAML not found (set SURICATA_YAML=path to override)"
fi

echo ""
echo "== Rendering zeek/node.cfg =="
if [ -f "$ZEEK_NODE_CFG" ]; then
  cp "$ZEEK_NODE_CFG" "${ZEEK_NODE_CFG}.bak.$(date +%s)"

  ZEEK_IF="${OBS_UPLINK_IF}"

  if grep -q '^interface=' "$ZEEK_NODE_CFG"; then
    sed -i "s|^interface=.*|interface=${ZEEK_IF}|" "$ZEEK_NODE_CFG"
  else
    echo "interface=${ZEEK_IF}" >> "$ZEEK_NODE_CFG"
  fi
  echo "  interface set to: ${ZEEK_IF}"
else
  echo "  SKIP: $ZEEK_NODE_CFG not found (set ZEEK_NODE_CFG=path to override)"
fi

echo ""
echo "== Done. =="
