#!/bin/bash
# ================================================================
# ZTA Traffic Generator — Run for 30-40 min before recording
# Generates baseline + anomalous traffic across all layers
# ================================================================

set -e

# ── Resolve pod names and IPs ────────────────────────────────────
FRONTEND=$(kubectl get po -n zta-demo -l app=frontend -o jsonpath='{.items[0].metadata.name}')
BACKEND=$(kubectl get po -n zta-demo -l app=backend -o jsonpath='{.items[0].metadata.name}')
DATABASE=$(kubectl get po -n zta-demo -l app=database -o jsonpath='{.items[0].metadata.name}')
ATTACKER=$(kubectl get po -n zta-demo -l app=attacker -o jsonpath='{.items[0].metadata.name}')
BACKEND_IP=$(kubectl get svc -n zta-demo backend -o jsonpath='{.spec.clusterIP}' 2>/dev/null || \
             kubectl get svc -n zta-demo -l app=backend -o jsonpath='{.items[0].spec.clusterIP}')
FRONTEND_IP=$(kubectl get svc -n zta-demo frontend -o jsonpath='{.spec.clusterIP}' 2>/dev/null || \
              kubectl get svc -n zta-demo -l app=frontend -o jsonpath='{.items[0].spec.clusterIP}')
DATABASE_IP=$(kubectl get svc -n zta-demo database -o jsonpath='{.spec.clusterIP}' 2>/dev/null || \
              kubectl get svc -n zta-demo -l app=database -o jsonpath='{.items[0].spec.clusterIP}')

echo "========================================"
echo "  ZTA Traffic Generator"
echo "========================================"
echo "  Frontend pod:  $FRONTEND"
echo "  Backend pod:   $BACKEND"
echo "  Database pod:  $DATABASE"
echo "  Attacker pod:  $ATTACKER"
echo "  Backend SVC:   $BACKEND_IP"
echo "  Frontend SVC:  $FRONTEND_IP"
echo "  Database SVC:  $DATABASE_IP"
echo "========================================"
echo "  Running for 40 minutes. Ctrl+C to stop."
echo "  Anomalous bursts every 5 minutes."
echo "========================================"
echo ""

START=$(date +%s)
ROUND=0
ANOMALY_ROUND=0

generate_baseline() {
  local r=$1
  echo "[$(date +%H:%M:%S)] Round $r — baseline traffic"

  # Legitimate app flows (green in Hubble)
  kubectl exec -n zta-demo $FRONTEND -- \
    wget -qO- http://$BACKEND_IP/api 2>/dev/null || true
  sleep 0.5

  kubectl exec -n zta-demo $BACKEND -- \
    wget -qO- http://$DATABASE_IP 2>/dev/null || true
  sleep 0.5

  # Frontend doing multiple requests (simulates real user)
  for i in 1 2 3; do
    kubectl exec -n zta-demo $FRONTEND -- \
      wget -qO- http://$BACKEND_IP/ 2>/dev/null || true
    sleep 0.3
  done

  # Attacker hitting allowed routes (will be blocked by Cilium — generates drops)
  kubectl exec -n zta-demo $ATTACKER -- \
    wget -qO- --timeout=2 http://$BACKEND_IP 2>/dev/null || true
  kubectl exec -n zta-demo $ATTACKER -- \
    wget -qO- --timeout=2 http://$DATABASE_IP 2>/dev/null || true
  sleep 0.5

  # HTTP traffic on host that Suricata picks up (zta-logs)
  curl -s -m 3 http://localhost:30080/ > /dev/null 2>&1 || true
  curl -s -m 3 http://localhost:30080/api > /dev/null 2>&1 || true

  # ztacloud traffic (generates ztacloud events in ELK tagged deployment_site=ztacloud)
  curl -s -m 5 http://100.111.196.121:8080/ > /dev/null 2>&1 || true
  curl -s -m 5 http://100.111.196.121:8080/health > /dev/null 2>&1 || true
}

generate_anomalous_burst() {
  local burst=$1
  echo ""
  echo "=========================================="
  echo "[$(date +%H:%M:%S)] ANOMALOUS BURST #$burst — high-rate attack simulation"
  echo "=========================================="

  # High-rate connection attempts from attacker pod (triggers ML anomaly + Suricata)
  for i in $(seq 1 60); do
    kubectl exec -n zta-demo $ATTACKER -- \
      wget -qO- --timeout=1 http://$BACKEND_IP 2>/dev/null || true
    kubectl exec -n zta-demo $ATTACKER -- \
      wget -qO- --timeout=1 http://$DATABASE_IP 2>/dev/null || true
    kubectl exec -n zta-demo $ATTACKER -- \
      wget -qO- --timeout=1 http://$FRONTEND_IP 2>/dev/null || true
  done

  # Simulate port scan pattern (fast connection attempts to multiple ports via host curl)
  for port in 22 80 443 8080 8443 5432 6379 27017 9200 5601; do
    curl -s -m 1 http://127.0.0.1:$port/ > /dev/null 2>&1 || true
  done

  # High-rate HTTP requests to local app (Suricata sees this on enp0s3)
  for i in $(seq 1 50); do
    curl -s -m 2 http://localhost:30080/ > /dev/null 2>&1 || true
    curl -s -m 2 http://localhost:30080/api > /dev/null 2>&1 || true
  done

  # RADIUS bad auth attempt (generates NAC rejection event)
  radtest attacker WrongPassword123 127.0.0.1 0 testing123 > /dev/null 2>&1 || true
  radtest scanner BadCred 127.0.0.1 0 testing123 > /dev/null 2>&1 || true

  echo "[$(date +%H:%M:%S)] Burst complete. Threat hunter will detect this in next 60s cycle."
  echo ""
}

generate_nac_traffic() {
  echo "[$(date +%H:%M:%S)] NAC events — auth accepted + rejected"
  radtest alice Alice123! 127.0.0.1 0 testing123 > /dev/null 2>&1 || true
  radtest bob Bob123! 127.0.0.1 0 testing123 > /dev/null 2>&1 || true
  radtest attacker WrongPass 127.0.0.1 0 testing123 > /dev/null 2>&1 || true
}

generate_ztacloud_burst() {
  echo "[$(date +%H:%M:%S)] ztacloud traffic burst — inflating deployment_site=ztacloud count"
  for i in $(seq 1 30); do
    curl -s -m 3 http://100.111.196.121:8080/ > /dev/null 2>&1 || true
    curl -s -m 3 http://100.111.196.121:8080/health > /dev/null 2>&1 || true
    sleep 0.2
  done
}

# ── Main loop ────────────────────────────────────────────────────
while true; do
  NOW=$(date +%s)
  ELAPSED=$(( NOW - START ))

  # Stop after 40 minutes
  if [ $ELAPSED -gt 2400 ]; then
    echo ""
    echo "[$(date +%H:%M:%S)] 40 minutes done. Stopping."
    echo "Check ELK now — fresh data ready for recording."
    break
  fi

  ROUND=$(( ROUND + 1 ))
  generate_baseline $ROUND

  # Every 10 rounds (~5 min): anomalous burst
  if (( ROUND % 10 == 0 )); then
    ANOMALY_ROUND=$(( ANOMALY_ROUND + 1 ))
    generate_anomalous_burst $ANOMALY_ROUND
    generate_ztacloud_burst
  fi

  # Every 5 rounds: NAC events
  if (( ROUND % 5 == 0 )); then
    generate_nac_traffic
  fi

  # Show elapsed progress every 20 rounds
  if (( ROUND % 20 == 0 )); then
    MINS=$(( ELAPSED / 60 ))
    echo ""
    echo "[$(date +%H:%M:%S)] Progress: ${MINS}m elapsed | ${ANOMALY_ROUND} anomalous bursts fired"
    echo ""
  fi

  sleep 5
done
