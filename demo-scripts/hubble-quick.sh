#!/bin/bash
# Get pod names and IPs
FE=$(kubectl get po -n zta-demo -l app=frontend -o jsonpath='{.items[0].metadata.name}')
BE=$(kubectl get po -n zta-demo -l app=backend -o jsonpath='{.items[0].metadata.name}')
AT=$(kubectl get po -n zta-demo -l app=attacker -o jsonpath='{.items[0].metadata.name}')
BE_IP=$(kubectl get svc -n zta-demo -l app=backend -o jsonpath='{.items[0].spec.clusterIP}')
DB_IP=$(kubectl get svc -n zta-demo -l app=database -o jsonpath='{.items[0].spec.clusterIP}')

echo "Sending traffic — watch Hubble UI at http://100.96.17.20:12000"
echo "CTRL+C to stop"
echo ""

while true; do
  # ALLOWED — shows green in Hubble
  kubectl exec -n zta-demo $FE -- wget -qO/dev/null http://$BE_IP/ 2>/dev/null \
    && echo "[$(date +%H:%M:%S)] GREEN  frontend → backend (allowed)" \
    || echo "[$(date +%H:%M:%S)] GREEN  frontend → backend (sent)"

  kubectl exec -n zta-demo $BE -- wget -qO/dev/null http://$DB_IP/ 2>/dev/null \
    && echo "[$(date +%H:%M:%S)] GREEN  backend  → database (allowed)" \
    || echo "[$(date +%H:%M:%S)] GREEN  backend  → database (sent)"

  # BLOCKED — shows red in Hubble
  kubectl exec -n zta-demo $AT -- wget -qO/dev/null --timeout=2 http://$BE_IP/ 2>/dev/null \
    && echo "[$(date +%H:%M:%S)] RED    attacker → backend  (SHOULD BE BLOCKED)" \
    || echo "[$(date +%H:%M:%S)] RED    attacker → backend  (blocked ✓)"

  kubectl exec -n zta-demo $AT -- wget -qO/dev/null --timeout=2 http://$DB_IP/ 2>/dev/null \
    && echo "[$(date +%H:%M:%S)] RED    attacker → database (SHOULD BE BLOCKED)" \
    || echo "[$(date +%H:%M:%S)] RED    attacker → database (blocked ✓)"

  echo "---"
  sleep 3
done
