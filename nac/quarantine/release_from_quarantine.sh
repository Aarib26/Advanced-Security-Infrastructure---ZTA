#!/bin/bash
# ~/oral_arch/nac/quarantine/release_from_quarantine.sh
# Called from FreeRADIUS recv-coa on a CoA-Request. Runs as freerad
# (no sudo available/needed) — log file ownership handles write access.
set -euo pipefail

MAC="${1:-unknown}"
TARGET_VLAN="${2:-unknown}"
QENV="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/quarantine.env"
LOG="/var/log/zta-quarantine-release.log"

[ -f "$QENV" ] && source "$QENV"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "{\"timestamp\":\"$TIMESTAMP\",\"mac\":\"$MAC\",\"target_vlan\":\"$TARGET_VLAN\",\"action\":\"release_from_quarantine\"}" >> "$LOG"

echo "Released $MAC to VLAN $TARGET_VLAN"
