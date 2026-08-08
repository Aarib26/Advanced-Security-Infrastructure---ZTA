#!/bin/bash
# ZTA full-arch startup — one command, no further interaction.
set -uo pipefail

LOG="/tmp/zta-startup-$(date +%s).log"
echo "Full startup log: $LOG"
exec > >(tee -a "$LOG") 2>&1

STEP_START=$(date +%s)
step() {
    local now=$(date +%s)
    echo ""
    echo "=== [$(( now - STEP_START ))s elapsed] $1 ==="
}

fail_soft() {
    echo "WARN: $1 — continuing, check manually if final status looks wrong"
}

if ! sudo -n true 2>/dev/null; then
    echo "ERROR: sudo credentials not cached. Run: sudo -v && bash $0"
    exit 1
fi

step "k3s node ready"
kubectl wait --for=condition=Ready node --all --timeout=180s || fail_soft "node not ready in time"

step "Cilium agent ready"
kubectl wait --for=condition=Ready pod -n kube-system -l k8s-app=cilium --timeout=180s || fail_soft "cilium agent not ready in time"
CILIUM_POD=$(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$CILIUM_POD" ]; then
    kubectl exec -n kube-system "$CILIUM_POD" -- cilium-dbg status --brief || fail_soft "cilium status check failed"
fi

step "Cilium network policies applied"
(cd ~/oral_arch/cilium && kubectl apply -f .) || fail_soft "cilium policy apply had errors"

step "zta-demo pods ready"
kubectl wait --for=condition=Ready pod --all -n zta-demo --timeout=120s || fail_soft "some zta-demo pods not ready"

step "Keycloak up"
(cd ~/oral_arch/keycloak && docker compose --env-file ../.env up -d) || fail_soft "keycloak compose up failed"

step "Pomerium up"
(cd ~/oral_arch/pomerium && docker compose --env-file ../.env up -d) || fail_soft "pomerium compose up failed"

step "ELK up"
(cd ~/oral_arch/elk && docker compose --env-file ../.env up -d) || fail_soft "elk compose up failed"
step "Waiting for Elasticsearch to accept connections"
ES_READY=0
for i in $(seq 1 60); do
    if curl -s -u elastic:"${ELASTIC_PASSWORD:-ztaelk26}" http://localhost:9200 > /dev/null 2>&1; then
        ES_READY=1
        break
    fi
    sleep 5
done
if [ "$ES_READY" -eq 1 ]; then
    echo "Elasticsearch is up after $((i*5))s"
else
    fail_soft "Elasticsearch did not respond after 300s"
fi

step "Restarting Filebeat"
sudo systemctl restart filebeat || fail_soft "filebeat restart failed"

step "Restarting threat hunter"
sudo systemctl restart zta-threat-hunter.service || fail_soft "ML service restart failed"

TOTAL=$(( $(date +%s) - STEP_START ))
echo ""
echo "=================== FINAL STATUS (total: ${TOTAL}s) ==================="
sudo systemctl status filebeat \
    zta-threat-hunter.service --no-pager | grep -E "●|Active"
echo "---"
docker compose -f ~/oral_arch/elk/docker-compose.yml ps
echo "---"
docker compose -f ~/oral_arch/keycloak/docker-compose.yml ps
echo "---"
docker compose -f ~/oral_arch/pomerium/docker-compose.yml ps
echo "---"
kubectl get pods -A | grep -E "cilium|zta-demo"
echo "======================================================================"
echo "Done. Full log saved at: $LOG"
echo "If anything shows inactive/failed above, check the WARN lines earlier in this log."
