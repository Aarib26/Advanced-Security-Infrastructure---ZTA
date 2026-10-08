# 11-suricata-zeek.sh
#!/bin/bash
echo "========================================"
echo "  DEMO 11: Suricata + Zeek Threat Detection"
echo "========================================"
echo ""
echo "--- Service status ---"
sudo systemctl status suricata --no-pager | head -8
echo ""
sudo systemctl status zeek_anomaly_detector --no-pager | head -8

echo ""
echo "--- Suricata recent alerts (fast.log) ---"
sudo tail -10 /var/log/suricata/fast.log 2>/dev/null || \
  sudo tail -10 /var/log/suricata/suricata.log 2>/dev/null

echo ""
echo "--- Zeek anomaly detector recent output ---"
sudo journalctl -u zeek_anomaly_detector --no-pager -n 15

echo ""
echo "--- Triggering a port scan to generate live alert ---"
echo "Running nmap against localhost..."
nmap -sS -p 22,80,443,8080,9200 127.0.0.1 -Pn -q &
NMAP_PID=$!
sleep 3
kill $NMAP_PID 2>/dev/null

echo ""
echo "--- Suricata alerts from last 60 seconds ---"
DATE=$(date +%Y.%m.%d)
curl -su elastic:ztaelk26 "http://localhost:9200/zta-alerts-$DATE/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "sort":[{"@timestamp":{"order":"desc"}}],
    "size":5,
    "query":{"range":{"@timestamp":{"gte":"now-60s"}}}
  }' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
hits=d['hits']['hits']
if not hits:
    print('  (no new alerts yet — may take a few seconds to index)')
for h in hits:
    s=h['_source']
    sig=s.get('alert',{}).get('signature','?')
    src=s.get('src_ip','?')
    ts=s.get('@timestamp','?')[:19]
    print(f'  {ts} | {src} | {sig}')
"

echo ""
echo "--- Total alerts today ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-alerts-$DATE/_count" \
  | python3 -c "import sys,json; print('Total alerts today:', json.load(sys.stdin)['count'])"

echo ""
echo "========================================"
echo "  Suricata + Zeek: LIVE ✓"
echo "========================================"
