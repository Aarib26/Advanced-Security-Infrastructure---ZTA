#!/bin/bash
# ~/oral_arch/nac/quarantine/reverify_posture.sh
#
# Continuous posture re-verification for devices currently in the production
# VLAN. Run periodically via a systemd timer (interval set in quarantine.env,
# not hardcoded into the unit file, so it's adjustable without editing code).
#
# Unlike a naive "re-read the last log line" check, this does a REAL re-probe:
# it re-invokes device_onboard.py against each production device exactly as
# FreeRADIUS would on auth, which re-runs the live SSH posture collection
# (patch-mgmt presence, disk encryption) for Tier-1 (full) devices. This is
# genuine continuous verification — posture can regress between checks (e.g.
# disk encryption gets disabled, a patch tool gets removed) and this will
# catch it on the next cycle, not just replay a stale decision.
#
# If the re-probe shows the device no longer qualifies for production
# (per the SAME real field values vlan_assign_hook.sh checks — full-tier +
# standard-decision — kept in sync, not duplicated logic drifting apart),
# this fires a real RADIUS CoA-Request to move it back to quarantine, reusing
# the same CoA mechanism already proven for manual release-to-production.
#
# No hardcoded device list: the set of "currently production" devices is
# derived fresh each run from the live NAC log, same as vlan_assign_hook.sh.
# Devices with no SSH key in ZTA_SSH_KEY_DIR (auth_only/BYOD/IoT) are never
# production in the first place, so they're correctly skipped here too —
# nothing to re-probe for a device that was never SSH-trusted.
set -euo pipefail

QENV="/home/aak/oral_arch/nac/quarantine/quarantine.env"
source "$QENV"

NAC_LOG="${ZTA_NAC_LOG:-/var/log/zta-nac.log}"
REVERIFY_LOG="/var/log/zta-quarantine-reverify.log"
DEVICE_ONBOARD="/home/aak/oral_arch/nac/device_onboard.py"

RADIUS_HOST="${RADIUS_HOST:-localhost}"
RADIUS_COA_PORT="${RADIUS_COA_PORT:-3799}"
RADIUS_SECRET="${RADIUS_SHARED_SECRET:?RADIUS_SHARED_SECRET must be set in quarantine.env}"

log_event() {
  local mac="$1" ip="$2" from_tier="$3" to_tier="$4" reason="$5"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "{\"timestamp\":\"$ts\",\"mac\":\"$mac\",\"ip\":\"$ip\",\"from\":\"$from_tier\",\"to\":\"$to_tier\",\"reason\":\"$reason\"}" >> "$REVERIFY_LOG"
}

if [ ! -f "$NAC_LOG" ]; then
  echo "$(date -u +%FT%TZ) NAC log not found at $NAC_LOG, nothing to reverify" >> "$REVERIFY_LOG"
  exit 0
fi

mapfile -t PRODUCTION_DEVICES < <(python3 -c "
import json

latest = {}
with open('$NAC_LOG') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        mac = d.get('mac')
        if not mac:
            continue
        latest[mac.lower()] = d

for mac, d in latest.items():
    if d.get('posture_tier') == 'full' and d.get('access_decision') == 'standard':
        print(f\"{mac}|{d.get('ip','')}|{d.get('device_id','')}\")"
)

if [ "${#PRODUCTION_DEVICES[@]}" -eq 0 ]; then
  echo "$(date -u +%FT%TZ) No devices currently in production tier, nothing to reverify" >> "$REVERIFY_LOG"
  exit 0
fi

for ENTRY in "${PRODUCTION_DEVICES[@]}"; do
  IFS='|' read -r MAC IP DEVICE_ID <<< "$ENTRY"

  if [ -z "$IP" ] || [ -z "$DEVICE_ID" ]; then
    log_event "$MAC" "$IP" "production" "production" "skipped_missing_ip_or_device_id"
    continue
  fi

  if ! python3 "$DEVICE_ONBOARD" \
        --device-id "$DEVICE_ID" \
        --ip "$IP" \
        --mac "$MAC" \
        --auth-result accept \
        >> "$REVERIFY_LOG" 2>&1
  then
    log_event "$MAC" "$IP" "production" "production" "reverify_script_error"
    continue
  fi

  FRESH_ENTRY=$(grep -i "$MAC" "$NAC_LOG" | tail -n1)
  FRESH_TIER=$(echo "$FRESH_ENTRY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('posture_tier','unknown'))" 2>/dev/null || echo "unknown")
  FRESH_DECISION=$(echo "$FRESH_ENTRY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_decision','blocked'))" 2>/dev/null || echo "blocked")

  if [ "$FRESH_TIER" = "full" ] && [ "$FRESH_DECISION" = "standard" ]; then
    continue
  fi

  if radclient -x "${RADIUS_HOST}:${RADIUS_COA_PORT}" coa "${RADIUS_SECRET}" <<EOF >> "$REVERIFY_LOG" 2>&1
Calling-Station-Id = "${MAC}"
Tunnel-Private-Group-Id = "90"
EOF
  then
    log_event "$MAC" "$IP" "production" "quarantine" "posture_regressed_on_reverify"
  else
    log_event "$MAC" "$IP" "production" "quarantine" "coa_send_failed"
  fi
done
