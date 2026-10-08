#!/bin/bash
echo "========================================"
echo "  DEMO 6: NAC — 802.1X Device Auth (e)"
echo "========================================"
echo ""
echo "--- FreeRADIUS service status ---"
sudo systemctl status freeradius --no-pager | head -8

echo ""
echo "--- 802.1X auth test — COMPLIANT device (alice) ---"
radtest alice Alice123! 127.0.0.1 0 testing123
echo ""
echo "--- 802.1X auth test — UNKNOWN device (blocked) ---"
radtest attacker wrongpass 127.0.0.1 0 testing123

echo ""
echo "--- FreeRADIUS recent auth events ---"
sudo tail -10 /var/log/freeradius/radius.log 2>/dev/null || \
  sudo journalctl -u freeradius --no-pager -n 10
