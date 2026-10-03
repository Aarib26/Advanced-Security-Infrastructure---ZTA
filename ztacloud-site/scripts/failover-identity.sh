#!/usr/bin/env bash
set -euo pipefail
CLOUD_TS_IP="100.111.196.121"
CLOUD_USER="ztacloud"
SSH_KEY="$HOME/.ssh/zta_gcp"
POMERIUM_CONFIG="$HOME/oral_arch/pomerium/config.yaml"
echo "=== ZTA Identity Failover Script ==="
echo "[1/4] Promoting PostgreSQL replica on ztacloud..."
ssh -i "$SSH_KEY" "${CLOUD_USER}@${CLOUD_TS_IP}" "sudo pg_ctlcluster 15 main promote"
sleep 3
echo "[2/4] Starting Keycloak warm standby on ztacloud..."
ssh -i "$SSH_KEY" "${CLOUD_USER}@${CLOUD_TS_IP}" "sudo systemctl start zta-keycloak-standby"
echo "[3/4] Waiting for Keycloak on ztacloud..."
TIMEOUT=180; ELAPSED=0
until curl -sf "http://${CLOUD_TS_IP}:8081/realms/master" > /dev/null 2>&1; do
  sleep 5; ELAPSED=$((ELAPSED + 5))
  echo "      ...waiting (${ELAPSED}s / ${TIMEOUT}s)"
  [ "$ELAPSED" -ge "$TIMEOUT" ] && echo "ERROR: timeout" && exit 1
done
echo "[4/4] Redirecting Pomerium to ztacloud Keycloak..."
cp "$POMERIUM_CONFIG" "${POMERIUM_CONFIG}.failover-backup-$(date +%Y%m%d-%H%M%S)"
sed -i "s|idp_provider_url:.*|idp_provider_url: http://${CLOUD_TS_IP}:8081/realms/zta|g" "$POMERIUM_CONFIG"
docker restart pomerium
echo "=== Failover complete === RTO: $(date)"
