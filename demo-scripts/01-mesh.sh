#!/bin/bash
echo "========================================"
echo "  DEMO 1: Two-Site WireGuard Mesh"
echo "========================================"
echo ""
echo "--- Tailscale mesh status ---"
tailscale status
echo ""
echo "--- Latency ztauser → ztacloud ---"
ping -c 3 100.111.196.121
echo ""
echo "--- ztacloud reachable on port 8080 (Tailscale only) ---"
nc -zv 100.111.196.121 8080 2>&1
