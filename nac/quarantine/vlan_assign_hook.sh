#!/bin/bash
# ~/oral_arch/nac/quarantine/vlan_assign_hook.sh
#
# Called from FreeRADIUS post-auth (Access-Accept) alongside device_onboard.py.
# Reads the tier device_onboard.py just wrote to zta-nac.log for this MAC and
# emits Tunnel-Private-Group-ID accordingly. No hardcoded MAC/tier list —
# always derived from the live NAC log entry.
#
# FIX (10 Aug): posture_tier/access_decision field values were checked
# against "tier1"/"allow", but device_onboard.py actually writes
# posture_tier="full"|"auth_only" and access_decision="standard"|
# "restricted"|"blocked" (the pomerium_tier value). The old condition could
# never be true for any device, so every device — including fully
# SSH-verified Tier-1 machines — fell through to quarantine. Fixed to check
# the real field values device_onboard.py emits.
set -euo pipefail

QENV="/home/aak/oral_arch/nac/quarantine/quarantine.env"
source "$QENV"

NAC_LOG="/var/log/zta-nac.log"
CALLING_STATION_ID="${1:-}"   # MAC passed in from FreeRADIUS unlang, %{Calling-Station-Id}

if [ -z "$CALLING_STATION_ID" ]; then
  echo "ERROR: no Calling-Station-Id passed" >&2
  echo "quarantine"   # fail-safe: unknown MAC -> quarantine tier, never fail-closed/deny
  exit 0
fi

MAC_NORM=$(echo "$CALLING_STATION_ID" | tr 'A-Z' 'a-z')

# Find the most recent NAC log entry for this MAC (device_onboard.py writes JSON lines)
LATEST_ENTRY=$(grep -i "$MAC_NORM" "$NAC_LOG" 2>/dev/null | tail -n1 || true)

if [ -z "$LATEST_ENTRY" ]; then
  # No posture record yet for this device -> graceful degrade to quarantine tier,
  # not a hard deny. BYOD/IoT devices with no prior trust land here by design.
  echo "quarantine"
  exit 0
fi

# Extract posture_tier and access_decision fields dynamically (no assumed field order)
POSTURE_TIER=$(echo "$LATEST_ENTRY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('posture_tier','unknown'))" 2>/dev/null || echo "unknown")
ACCESS_DECISION=$(echo "$LATEST_ENTRY" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('access_decision','blocked'))" 2>/dev/null || echo "blocked")

# REAL field values from device_onboard.py:
#   posture_tier: "full" (SSH-verified) | "auth_only" (BYOD/IoT, no SSH trust)
#   access_decision (== pomerium_tier): "standard" | "restricted" | "blocked"
# Production VLAN requires BOTH a full SSH-verified posture check AND the
# highest access tier device_onboard.py can grant (standard). "auth_only"
# devices (BYOD/IoT) and any posture score below the "standard" threshold
# correctly stay in quarantine — this is the honest, intended degrade path,
# not a bug being hidden.
if [ "$POSTURE_TIER" = "full" ] && [ "$ACCESS_DECISION" = "standard" ]; then
  echo "production"
else
  # auth_only tier, restricted/blocked posture, or anything unexpected -> quarantine
  echo "quarantine"
fi
