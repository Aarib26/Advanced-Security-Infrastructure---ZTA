#!/bin/bash
echo "========================================"
echo "       ZTA PRE-RECORDING CHECK"
echo "========================================"

echo ""
echo "--- K8s pods ---"
kubectl get po -n zta-demo | grep Running | wc -l | xargs -I{} echo "{} pods running"

echo ""
echo "--- Docker containers ---"
docker ps --format "{{.Names}}: {{.Status}}" | sort

echo ""
echo "--- Critical systemd services ---"
for svc in zta-threat-hunter zeek_anomaly_detector suricata filebeat freeradius; do
  status=$(sudo systemctl is-active $svc 2>/dev/null)
  echo "  $svc: $status"
done

echo ""
echo "--- ELK today ---"
DATE=$(date +%Y.%m.%d)
ALERTS=$(curl -su elastic:ztaelk26 "http://localhost:9200/zta-alerts-$DATE/_count" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('count','?'))")
ML=$(curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_count" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('count','?'))")
CLOUD=$(curl -su elastic:ztaelk26 "http://localhost:9200/zta-logs-*/_search" -H 'Content-Type: application/json' -d '{"query":{"term":{"fields.deployment_site":"ztacloud"}},"size":0}' 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['hits']['total']['value'])")
echo "  Suricata alerts today: $ALERTS"
echo "  ML anomalies total:    $ML"
echo "  ztacloud events total: $CLOUD"

echo ""
echo "--- Tailscale mesh ---"
tailscale status | grep -E "ztauser|ztacloud"

echo ""
echo "========================================"
echo "  ALL GOOD — READY TO RECORD"
echo "========================================"
