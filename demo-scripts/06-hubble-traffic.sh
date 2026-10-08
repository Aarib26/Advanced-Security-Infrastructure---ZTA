#!/bin/bash
echo "========================================"
echo "  Hubble Traffic Generator"
echo "  Shows allowed vs blocked pod traffic"
echo "========================================"
echo ""
echo "Open Hubble UI in browser, then press Enter"
read -r

FRONTEND=$(kubectl get po -n zta-demo -l app=frontend -o jsonpath='{.items[0].metadata.name}')
BACKEND=$(kubectl get po -n zta-demo -l app=backend -o jsonpath='{.items[0].metadata.name}')
ATTACKER=$(kubectl get po -n zta-demo -l app=attacker -o jsonpath='{.items[0].metadata.name}')
BACKEND_IP=$(kubectl get svc -n zta-demo -l app=backend -o jsonpath='{.items[0].spec.clusterIP}')
DATABASE_IP=$(kubectl get svc -n zta-demo -l app=database -o jsonpath='{.items[0].spec.clusterIP}')

echo "frontend=$FRONTEND backend=$BACKEND attacker=$ATTACKER"
echo "backend_ip=$BACKEND_IP database_ip=$DATABASE_IP"
echo ""

for i in $(seq 1 15); do
  echo "--- Round $i/15 ---"

  kubectl exec -n zta-demo $FRONTEND -- \
    wget -qO- http://$BACKEND_IP/api 2>/dev/null \
    && echo "  GREEN frontend->backend: allowed" \
    || echo "  GREEN frontend->backend: sent"
  sleep 1

  kubectl exec -n zta-demo $BACKEND -- \
    wget -qO- http://$DATABASE_IP 2>/dev/null \
    && echo "  GREEN backend->database: allowed" \
    || echo "  GREEN backend->database: sent"
  sleep 1

  kubectl exec -n zta-demo $ATTACKER -- \
    wget -qO- --timeout=2 http://$BACKEND_IP 2>/dev/null \
    && echo "  RED attacker->backend: UNEXPECTED - check policies" \
    || echo "  RED attacker->backend: blocked by Cilium"
  sleep 1

  kubectl exec -n zta-demo $ATTACKER -- \
    wget -qO- --timeout=2 http://$DATABASE_IP 2>/dev/null \
    && echo "  RED attacker->database: UNEXPECTED - check policies" \
    || echo "  RED attacker->database: blocked by Cilium"
  sleep 2
done

echo ""
echo "Done. Hubble UI should show green arrows and red blocked arrows."
