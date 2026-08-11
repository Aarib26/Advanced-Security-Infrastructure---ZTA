#!/bin/bash
# ~/oral_arch/nac/quarantine/render_reverify_timer.sh
#
# systemd timer units can't read ${env[VAR]} at parse time (same class of
# limitation already hit with FreeRADIUS's module config — see
# render_keycloak_module.sh). This detect-then-render script reads
# REVERIFY_INTERVAL from quarantine.env and writes a real, static
# zta-posture-reverify.timer with that value substituted in. Re-run this
# any time you change the interval in quarantine.env; do not hand-edit
# the rendered .timer file directly (it will be overwritten).
set -euo pipefail

QENV="/home/aak/oral_arch/nac/quarantine/quarantine.env"
source "$QENV"

INTERVAL="${REVERIFY_INTERVAL:-5min}"   # sensible default if not set in env

TIMER_SRC="/home/aak/oral_arch/nac/quarantine/systemd/zta-posture-reverify.timer.template"
TIMER_DST="/etc/systemd/system/zta-posture-reverify.timer"
SERVICE_SRC="/home/aak/oral_arch/nac/quarantine/systemd/zta-posture-reverify.service"
SERVICE_DST="/etc/systemd/system/zta-posture-reverify.service"

sed "s/%%REVERIFY_INTERVAL%%/${INTERVAL}/" "$TIMER_SRC" | sudo tee "$TIMER_DST" > /dev/null
sudo cp "$SERVICE_SRC" "$SERVICE_DST"

sudo systemctl daemon-reload
sudo systemctl enable --now zta-posture-reverify.timer

echo "Rendered zta-posture-reverify.timer with REVERIFY_INTERVAL=${INTERVAL}"
echo "Check status: systemctl list-timers zta-posture-reverify.timer"
