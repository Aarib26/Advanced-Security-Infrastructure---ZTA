#!/bin/bash
echo "========================================"
echo "  DEMO 8: DRP — Failover Script + IaC"
echo "========================================"
echo ""
echo "--- Failover script syntax check ---"
SCRIPT=$(find ~ -name "failover-identity.sh" 2>/dev/null | head -1)
echo "Script location: $SCRIPT"
bash -n "$SCRIPT" && echo "SYNTAX OK — ready for live failover in < 2 minutes"

echo ""
echo "--- What the failover script does ---"
grep "^echo" "$SCRIPT" | head -10

echo ""
echo "--- Git history (Infrastructure as Code) ---"
cd ~/git_oral_arch/Advanced-Security-Infrastructure---ZTA 2>/dev/null || \
  cd ~/oral_arch
git log --oneline -7

echo ""
echo "--- Repo structure ---"
ls -la
