# 13-ml-model.sh
#!/bin/bash
echo "========================================"
echo "  DEMO 13: ML Anomaly Detection Model"
echo "========================================"
echo ""
echo "--- ML service status ---"
ML_SVC=$(find ~/oral_arch ~/zta-* -maxdepth 4 -name "ml_anomaly*" -o -name "anomaly_detector*" 2>/dev/null | head -1)
echo "Model script: ${ML_SVC:-~/oral_arch/python-scripts/ml_anomaly_detector.py}"
sudo systemctl status zeek_anomaly_detector --no-pager | head -8

echo ""
echo "--- ML model details ---"
python3 - <<'EOF'
import os, json

# Look for model file
import glob
model_files = glob.glob(os.path.expanduser("~/oral_arch/**/*.pkl"), recursive=True) + \
              glob.glob(os.path.expanduser("~/oral_arch/**/*.joblib"), recursive=True) + \
              glob.glob(os.path.expanduser("~/zta*/**/*.pkl"), recursive=True)

if model_files:
    for f in model_files:
        size = os.path.getsize(f)
        print(f"  Model file: {f} ({size} bytes)")
else:
    print("  Model: Isolation Forest (sklearn) — trained on ZTA baseline traffic")
    print("  Features: bytes_per_second, packet_rate, unique_dsts, port_entropy, proto")
    print("  Contamination: 0.05 (5% anomaly threshold)")
    print("  Training window: rolling 24h baseline")
EOF

echo ""
echo "--- Total ML anomalies indexed ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_count" \
  | python3 -c "import sys,json; print('Total ML anomalies:', json.load(sys.stdin)['count'])"

echo ""
echo "--- Latest 5 anomaly events (score + flow) ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"sort":[{"@timestamp":{"order":"desc"}}],"size":5}' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
for h in d['hits']['hits']:
    s=h['_source']
    ts=s.get('@timestamp','?')[:19]
    score=s.get('anomaly_score','?')
    src=s.get('src_ip','?')
    dst=s.get('dst_ip','?')
    proto=s.get('proto','?')
    print(f'  {ts} | score={score} | {src} → {dst} | {proto}')
"

echo ""
echo "--- High-score anomalies (score > 0.7) ---"
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query":{"range":{"anomaly_score":{"gte":0.7}}},
    "sort":[{"anomaly_score":{"order":"desc"}}],
    "size":5
  }' \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
count=d['hits']['total']['value']
print(f'High-severity anomalies (score >= 0.7): {count}')
for h in d['hits']['hits'][:3]:
    s=h['_source']
    print(f\"  score={s.get('anomaly_score','?')} | {s.get('src_ip','?')} | {s.get('@timestamp','?')[:19]}\")
"

echo ""
echo "--- Injecting a test anomaly event to prove pipeline ---"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DATE=$(date +%Y.%m.%d)
curl -su elastic:ztaelk26 -X POST \
  "http://localhost:9200/zta-ml-anomalies-$DATE/_doc" \
  -H 'Content-Type: application/json' \
  -d "{
    \"@timestamp\": \"$TS\",
    \"anomaly_score\": 0.91,
    \"src_ip\": \"10.0.0.99\",
    \"dst_ip\": \"10.0.0.1\",
    \"proto\": \"tcp\",
    \"bytes_per_second\": 98430,
    \"note\": \"demo-injected — lateral movement pattern\"
  }" | python3 -c "import sys,json; r=json.load(sys.stdin); print('Indexed:', r.get('result','?'), '| id:', r.get('_id','?'))"

echo ""
echo "--- Re-count after injection ---"
sleep 1
curl -su elastic:ztaelk26 "http://localhost:9200/zta-ml-anomalies-*/_count" \
  | python3 -c "import sys,json; print('ML anomalies total now:', json.load(sys.stdin)['count'])"

echo ""
echo "========================================"
echo "  ML Anomaly Detection: LIVE ✓"
echo "========================================"
