#!/bin/bash
echo "========================================"
echo "  DEMO 4: Unified SIEM (d.iii)"
echo "========================================"
echo ""
DATE=$(date +%Y.%m.%d)

echo "--- Suricata alerts today (ztauser) ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-alerts-$DATE/_count" \
  | python3 -c "import sys,json; print('Alerts:', json.load(sys.stdin)['count'])"

echo ""
echo "--- Events from ztacloud (DR secondary) ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"fields.deployment_site":"ztacloud"}},"size":0}' \
  | python3 -c "import sys,json; print('ztacloud events:', json.load(sys.stdin)['hits']['total']['value'])"

echo ""
echo "--- ML anomalies total ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_count" \
  | python3 -c "import sys,json; print('ML anomalies:', json.load(sys.stdin)['count'])"

echo ""
echo "--- Latest 3 ML anomaly events ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"sort":[{"@timestamp":{"order":"desc"}}],"size":3}' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
for h in d['hits']['hits']:
  s=h['_source']
  print(f\"  {s.get('@timestamp','?')[:19]} | score={s.get('anomaly_score','?')} | {s.get('src_ip','?')} → {s.get('dst_ip','?')}\")
"
