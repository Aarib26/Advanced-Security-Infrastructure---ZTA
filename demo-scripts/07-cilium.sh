#!/bin/bash
echo "========================================"
echo "  DEMO 5: Microsegmentation + Auto-Block"
echo "========================================"
echo ""
echo "--- Active Cilium network policies ---"
kubectl get ciliumnetworkpolicy -A | head -20

echo ""
echo "--- Auto-generated block policies (threat_hunter) ---"
kubectl get ciliumnetworkpolicy -A | grep "zta-block"

echo ""
echo "--- Latest automated response actions ---"
tail -20 ~/zta-response-actions.log 2>/dev/null || \
  find ~/oral_arch ~/zta-* -maxdepth 3 -name "zta-response-actions.log" 2>/dev/null -exec tail -20 {} \;

echo ""
echo "--- Threat hunter service status ---"
sudo systemctl status zta-threat-hunter --no-pager | head -10
