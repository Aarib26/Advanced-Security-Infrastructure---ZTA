#!/bin/bash
# lateral_sweep.sh — ZTA Lateral Movement Sweep
#
# Detects east-west traffic anomalies in the zta-demo namespace by comparing
# recent Zeek conn.log entries (from Elasticsearch) against the active Cilium
# CNP allow matrix.  Violations are logged to zta-response-actions.log,
# indexed to the zta-hunt-* ES index, and optionally trigger an automated
# Ansible block — identical pipeline to threat_hunter.py.
#
# Primary data source : Elasticsearch (zta-logs-* index, log_type=zeek)
# Fallback            : Direct Zeek conn.log file read (/opt/zeek/logs/)
#
# Usage:
#   ./lateral_sweep.sh                      # one-shot, last 5 min
#   ./lateral_sweep.sh --lookback=10        # extend lookback window (minutes)
#   ./lateral_sweep.sh --auto-respond       # block confirmed violations via Ansible
#   ./lateral_sweep.sh --loop               # run continuously (every SWEEP_INTERVAL s)
#
# Required env vars (no hardcoded defaults — set before running):
#   ES_USER    Elasticsearch username
#   ES_PASS    Elasticsearch password
#
# Optional env vars:
#   ES_HOST          (default: 127.0.0.1)
#   ES_PORT          (default: 9200)
#   NAMESPACE        (default: zta-demo)
#   LOOKBACK_MINUTES (default: 5)
#   SWEEP_INTERVAL   (default: 300 — only used with --loop)
#   ANSIBLE_DIR      (default: <script-dir>/ansible)
#   RESPONSE_LOG     (default: ~/oral_arch/zta-response-actions.log)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Config (all overridable via environment) ---
ES_HOST="${ES_HOST:-127.0.0.1}"
ES_PORT="${ES_PORT:-9200}"
ES_USER="${ES_USER:-}"
ES_PASS="${ES_PASS:-}"
NAMESPACE="${NAMESPACE:-zta-demo}"
LOOKBACK_MINUTES="${LOOKBACK_MINUTES:-5}"
SWEEP_INTERVAL="${SWEEP_INTERVAL:-300}"
ANSIBLE_DIR="${ANSIBLE_DIR:-${SCRIPT_DIR}/ansible}"
RESPONSE_LOG="${RESPONSE_LOG:-${HOME}/oral_arch/zta-response-actions.log}"
HUNT_INDEX_PREFIX="zta-hunt"

AUTO_RESPOND=false
LOOP_MODE=false

for arg in "$@"; do
  case "$arg" in
    --auto-respond)   AUTO_RESPOND=true ;;
    --loop)           LOOP_MODE=true ;;
    --lookback=*)     LOOKBACK_MINUTES="${arg#*=}" ;;
    --namespace=*)    NAMESPACE="${arg#*=}" ;;
    --interval=*)     SWEEP_INTERVAL="${arg#*=}" ;;
  esac
done

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# --- ES curl wrapper: injects auth header only when credentials are set ---
es_curl() {
  local auth_args=()
  [[ -n "$ES_USER" && -n "$ES_PASS" ]] && auth_args=(-u "${ES_USER}:${ES_PASS}")
  curl -sf "${auth_args[@]}" "$@"
}

# --- Dynamically resolve current pod IP from live cluster ---
resolve_pod_ip() {
  local label="$1"
  kubectl get pods -n "$NAMESPACE" -l "app=${label}" \
    -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true
}

# ============================================================
# CORE SWEEP
# ============================================================
run_sweep() {
  log "=== lateral_sweep starting (ns=${NAMESPACE}, lookback=${LOOKBACK_MINUTES}m, auto-respond=${AUTO_RESPOND}) ==="

  # 1. Resolve pod IPs — never hardcoded
  local IP_FRONTEND IP_BACKEND IP_DATABASE IP_ATTACKER
  IP_FRONTEND=$(resolve_pod_ip frontend)
  IP_BACKEND=$(resolve_pod_ip backend)
  IP_DATABASE=$(resolve_pod_ip database)
  IP_ATTACKER=$(resolve_pod_ip attacker)

  log "Resolved pod IPs: frontend=${IP_FRONTEND:-UNKNOWN} backend=${IP_BACKEND:-UNKNOWN} database=${IP_DATABASE:-UNKNOWN} attacker=${IP_ATTACKER:-UNKNOWN}"

  # 2. Build CNP allow matrix: "src:dst:port" tuples derived from active policies
  #    frontend->backend:80, backend->database:80
  #    All other east-west pairs are violations by design (default-deny-all)
  local ALLOWED=""
  [[ -n "$IP_FRONTEND" && -n "$IP_BACKEND"  ]] && ALLOWED+="${IP_FRONTEND}:${IP_BACKEND}:80,"
  [[ -n "$IP_BACKEND"  && -n "$IP_DATABASE" ]] && ALLOWED+="${IP_BACKEND}:${IP_DATABASE}:80,"
  local POD_IPS="${IP_FRONTEND},${IP_BACKEND},${IP_DATABASE},${IP_ATTACKER}"

  log "Allow matrix: ${ALLOWED:-EMPTY}"

  # 3. Query Elasticsearch for recent Zeek conn.log entries
  local SINCE_MS=$(( ($(date +%s) - LOOKBACK_MINUTES * 60) * 1000 ))
  local ES_QUERY
  ES_QUERY=$(cat <<EOF
{
  "size": 2000,
  "_source": ["src_ip","dest_ip","dest_port","proto","conn_state","duration","orig_bytes","@timestamp"],
  "query": {
    "bool": {
      "must": [
        { "term": { "fields.log_type": "zeek" } },
        { "exists": { "field": "src_ip" } },
        { "exists": { "field": "dest_ip" } },
        { "range": { "@timestamp": { "gte": ${SINCE_MS} } } }
      ],
      "must_not": [
        { "prefix": { "id.orig_h": "127." } },
        { "prefix": { "id.orig_h": "fe80:" } },
        { "prefix": { "id.orig_h": "::1"  } }
      ]
    }
  }
}
EOF
)

  local ES_RESPONSE=""
  ES_RESPONSE=$(es_curl -X POST \
    "http://${ES_HOST}:${ES_PORT}/zta-logs-*/_search" \
    -H "Content-Type: application/json" \
    -d "$ES_QUERY" 2>/dev/null) || true

  if [[ -z "$ES_RESPONSE" ]]; then
    log "WARN: Elasticsearch unreachable — falling back to direct log file scan"
    run_file_fallback "$ALLOWED" "$POD_IPS" "$IP_ATTACKER"
    return
  fi

  local TOTAL
  TOTAL=$(echo "$ES_RESPONSE" | python3 -c \
    "import json,sys; print(json.load(sys.stdin)['hits']['total']['value'])" 2>/dev/null || echo 0)
  log "ES returned ${TOTAL} Zeek conn records in lookback window"

  # 4. Detect violations
  local VIOLATIONS
  VIOLATIONS=$(echo "$ES_RESPONSE" | \
    ALLOWED_ENV="$ALLOWED" \
    POD_IPS_ENV="$POD_IPS" \
    IP_ATTACKER_ENV="$IP_ATTACKER" \
    python3 -c "
import json, sys, os

data    = json.load(sys.stdin)
hits    = data.get('hits', {}).get('hits', [])
allowed = set(p for p in os.environ.get('ALLOWED_ENV','').split(',') if p)
pod_set = set(p for p in os.environ.get('POD_IPS_ENV','').split(',') if p)
atk_ip  = os.environ.get('IP_ATTACKER_ENV', '')

violations = []
seen       = set()

for hit in hits:
    s    = hit.get('_source', {})
    src  = s.get('src_ip', '')
    dst  = s.get('dest_ip', '')
    port = str(s.get('dest_port', ''))
    if not src or not dst:
        continue

    src_pod = src in pod_set
    dst_pod = dst in pod_set

    # Only analyse traffic that involves at least one known pod
    if not (src_pod or dst_pod):
        continue

    # Rule 1: Any egress FROM the attacker pod
    if atk_ip and src == atk_ip:
        key = f'atk:{src}:{dst}:{port}'
        if key not in seen:
            seen.add(key)
            violations.append({
                'type':       'attacker_egress',
                'severity':   'high',
                'src':        src,
                'dst':        dst,
                'dst_port':   port,
                'proto':      s.get('proto', ''),
                'conn_state': s.get('conn_state', ''),
                'timestamp':  s.get('@timestamp', ''),
                'reason':     f'Attacker pod ({src}) sent traffic to {dst}:{port} — active lateral attempt'
            })
        continue

    # Rule 2: East-west pair not in CNP allow matrix
    if src_pod and dst_pod:
        pair = f'{src}:{dst}:{port}'
        if pair not in allowed:
            key = f'ew:{src}:{dst}:{port}'
            if key not in seen:
                seen.add(key)
                violations.append({
                    'type':       'policy_violation',
                    'severity':   'high',
                    'src':        src,
                    'dst':        dst,
                    'dst_port':   port,
                    'proto':      s.get('proto', ''),
                    'conn_state': s.get('conn_state', ''),
                    'timestamp':  s.get('@timestamp', ''),
                    'reason':     f'East-west {src}->{dst}:{port} violates default-deny-all CNP — not in allow matrix'
                })

print(json.dumps(violations))
") || VIOLATIONS="[]"

  local VCOUNT
  VCOUNT=$(echo "$VIOLATIONS" | python3 -c \
    "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
  log "Violations detected: ${VCOUNT}"

  if [[ "$VCOUNT" -eq 0 ]]; then
    log "=== lateral_sweep clean — no lateral movement detected ==="
    return
  fi

  # 5. Log violations to response log + index to zta-hunt-* in ES
  local HUNT_INDEX="${HUNT_INDEX_PREFIX}-$(date -u +%Y.%m.%d)"
  echo "$VIOLATIONS" | \
    ES_HOST="$ES_HOST" ES_PORT="$ES_PORT" \
    ES_USER="$ES_USER" ES_PASS="$ES_PASS" \
    HUNT_INDEX="$HUNT_INDEX" RESPONSE_LOG="$RESPONSE_LOG" \
    python3 -c "
import json, sys, os, subprocess, datetime

violations = json.load(sys.stdin)
es_host   = os.environ['ES_HOST']
es_port   = os.environ['ES_PORT']
es_user   = os.environ.get('ES_USER','')
es_pass   = os.environ.get('ES_PASS','')
hunt_idx  = os.environ['HUNT_INDEX']
log_file  = os.environ.get('RESPONSE_LOG','')
auth      = ['-u', f'{es_user}:{es_pass}'] if es_user else []

now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + 'Z'

for v in violations:
    doc = {**v, '@timestamp': now, 'source': 'lateral_sweep'}
    doc_json = json.dumps(doc)

    # Index to zta-hunt-* for Kibana visibility
    cmd = ['curl', '-sf'] + auth + [
        '-X', 'POST',
        f'http://{es_host}:{es_port}/{hunt_idx}/_doc',
        '-H', 'Content-Type: application/json',
        '-d', doc_json
    ]
    subprocess.run(cmd, capture_output=True)

    # Append to audit log (same format as block_ip_cilium.yml and threat_hunter.py)
    line = (
        f\"{now} action=lateral_sweep_alert \"
        f\"type={v['type']} src={v['src']} dst={v['dst']} \"
        f\"dst_port={v['dst_port']} severity={v['severity']} \"
        f\"reason=\\\"{v['reason']}\\\"\"
    )
    print(line)
    if log_file:
        with open(log_file, 'a') as f:
            f.write(line + '\n')
"

  # 6. Auto-respond: block each unique violating source via Ansible
  if [[ "$AUTO_RESPOND" == "true" ]]; then
    log "Auto-respond: invoking block_ip_cilium.yml for each unique violating source"
    local UNIQUE_SRCS
    UNIQUE_SRCS=$(echo "$VIOLATIONS" | python3 -c \
      "import json,sys; vs=json.load(sys.stdin); [print(s) for s in sorted(set(v['src'] for v in vs))]")
    while IFS= read -r src_ip; do
      [[ -z "$src_ip" ]] && continue
      log "Blocking ${src_ip} via Ansible (reason=lateral_movement_detected)..."
      ansible-playbook "${ANSIBLE_DIR}/block_ip_cilium.yml" \
        -e "target_ip=${src_ip}" \
        -e "reason=lateral_movement_detected" \
        || log "WARN: Ansible block failed for ${src_ip}"
    done <<< "$UNIQUE_SRCS"
  fi

  log "=== lateral_sweep complete: ${VCOUNT} violation(s) logged to ${HUNT_INDEX} and ${RESPONSE_LOG} ==="
}

# ============================================================
# FALLBACK: Direct Zeek log file read when ES is unavailable
# ============================================================
run_file_fallback() {
  local ALLOWED="$1"
  local POD_IPS="$2"
  local IP_ATTACKER="$3"

  local LOG_DIRS=(
    "/opt/zeek/logs/current"   # worker-backend (zeekctl)
    "/opt/zeek/logs/frontend"  # zeek-frontend.service
    "/opt/zeek/logs/database"  # zeek-database.service
    "/opt/zeek/logs/attacker"  # zeek-attacker.service
  )

  log "Scanning Zeek conn.log files directly..."
  local found=0
  local SEEN_FILE
  SEEN_FILE=$(mktemp)

  for dir in "${LOG_DIRS[@]}"; do
    local logfile="${dir}/conn.log"
    [[ -f "$logfile" ]] || continue
    found=1
    log "  Scanning: ${logfile}"

    tail -500 "$logfile" | \
      ALLOWED_ENV="$ALLOWED" POD_IPS_ENV="$POD_IPS" \
      IP_ATTACKER_ENV="$IP_ATTACKER" RESPONSE_LOG="$RESPONSE_LOG" \
      SEEN_FILE="$SEEN_FILE" \
      python3 -c "
import json, sys, os, datetime

allowed = set(p for p in os.environ.get('ALLOWED_ENV','').split(',') if p)
pod_set = set(p for p in os.environ.get('POD_IPS_ENV','').split(',') if p)
atk_ip  = os.environ.get('IP_ATTACKER_ENV','')
log_file = os.environ.get('RESPONSE_LOG','')
now     = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + 'Z'

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:   rec = json.loads(line)
    except: continue

    src  = rec.get('id.orig_h','')
    dst  = rec.get('id.resp_h','')
    port = str(rec.get('id.resp_p',''))
    if not src or not dst: continue
    if src.startswith('127.') or src.startswith('fe80:'): continue

    src_pod = src in pod_set
    dst_pod = dst in pod_set
    if not (src_pod or dst_pod): continue

    violation = False
    vtype     = ''
    reason    = ''

    if atk_ip and src == atk_ip:
        violation = True
        vtype     = 'attacker_egress'
        reason    = f'Attacker pod egress {src}->{dst}:{port} (file-fallback)'
    elif src_pod and dst_pod and f'{src}:{dst}:{port}' not in allowed:
        violation = True
        vtype     = 'policy_violation'
        reason    = f'East-west violation {src}->{dst}:{port} (file-fallback)'

    if violation:
        msg = f'{now} action=lateral_sweep_alert type={vtype} src={src} dst={dst} dst_port={port} severity=high reason=\"{reason}\"'
        print(msg)
        if log_file:
            with open(log_file,'a') as f: f.write(msg+'\n')
"
  done

  [[ "$found" -eq 0 ]] && log "WARN: No Zeek conn.log files found in expected directories"
  rm -f "$SEEN_FILE"
  log "File fallback complete"
}

# ============================================================
# ENTRY POINT
# ============================================================
if [[ "$LOOP_MODE" == "true" ]]; then
  log "Loop mode: sweeping every ${SWEEP_INTERVAL}s — Ctrl-C to stop"
  while true; do
    run_sweep
    sleep "$SWEEP_INTERVAL"
  done
else
  run_sweep
fi
