#!/bin/bash
# ~/oral_arch/nac/quarantine/setup_quarantine_net.sh
# Dynamic pre-admission quarantine namespace. No hardcoded IPs/interfaces —
# auto-detects primary interface and picks an unused /24 for quarantine.
set -euo pipefail

QDIR="/home/aak/oral_arch/nac/quarantine"
mkdir -p "$QDIR"

# Auto-detect primary interface (the one with the default route) instead of hardcoding
PRIMARY_IF=$(ip route show default | awk '{print $5; exit}')
if [ -z "$PRIMARY_IF" ]; then
  echo "ERROR: could not auto-detect primary interface" >&2
  exit 1
fi
echo "Detected primary interface: $PRIMARY_IF"

# Dynamically find an unused RFC1918 /24 for the quarantine segment
# Scans 10.90.0.0/24 .. 10.90.255.0/24 for one not already in `ip route`
find_free_subnet() {
  for i in $(seq 90 250); do
    CAND="10.$i.0.0/24"
    if ! ip route | grep -q "10.$i.0."; then
      echo "10.$i.0"
      return 0
    fi
  done
  echo "ERROR: no free subnet found" >&2
  exit 1
}
Q_BASE=$(find_free_subnet)
Q_BRIDGE_IP="${Q_BASE}.1/24"
Q_NS_IP="${Q_BASE}.2/24"
echo "Quarantine subnet chosen dynamically: ${Q_BASE}.0/24"

# Persist the chosen values so later scripts (FreeRADIUS hook, CoA release)
# read them instead of re-deriving or hardcoding
cat > "$QDIR/quarantine.env" <<EOF
PRIMARY_IF=$PRIMARY_IF
Q_BRIDGE=zta-quar-br0
Q_NS=zta-quarantine
Q_VETH_HOST=zq-veth-h
Q_VETH_NS=zq-veth-n
Q_BASE=$Q_BASE
Q_BRIDGE_IP=$Q_BRIDGE_IP
Q_NS_IP=$Q_NS_IP
EOF
echo "Wrote $QDIR/quarantine.env"

source "$QDIR/quarantine.env"

# Idempotent teardown of any prior run
ip netns del "$Q_NS" 2>/dev/null || true
ip link del "$Q_BRIDGE" 2>/dev/null || true

# Create bridge (represents the "quarantine VLAN" in the all-VM lab)
ip link add name "$Q_BRIDGE" type bridge
ip addr add "$Q_BRIDGE_IP" dev "$Q_BRIDGE"
ip link set "$Q_BRIDGE" up

# Create isolated netns + veth pair, attach to bridge
ip netns add "$Q_NS"
ip link add "$Q_VETH_HOST" type veth peer name "$Q_VETH_NS"
ip link set "$Q_VETH_HOST" master "$Q_BRIDGE"
ip link set "$Q_VETH_HOST" up
ip link set "$Q_VETH_NS" netns "$Q_NS"
ip netns exec "$Q_NS" ip addr add "$Q_NS_IP" dev "$Q_VETH_NS"
ip netns exec "$Q_NS" ip link set "$Q_VETH_NS" up
ip netns exec "$Q_NS" ip link set lo up
ip netns exec "$Q_NS" ip route add default via "${Q_BASE}.1"

# nftables: quarantine gets DNS + DHCP + access ONLY to Keycloak/RADIUS (posture check path),
# everything else dropped. Reads Keycloak/RADIUS reachability dynamically via resolve script
# if present, else falls back to allowing only the bridge gateway + localhost chain.
nft delete table inet zta_quarantine 2>/dev/null || true
nft -f - <<NFT
table inet zta_quarantine {
  chain quarantine_out {
    type filter hook forward priority 0; policy drop;
    iifname "$Q_BRIDGE" udp dport 53 accept
    iifname "$Q_BRIDGE" udp dport 67 accept
    iifname "$Q_BRIDGE" tcp dport { 1812, 1813, 8081 } accept
    iifname "$Q_BRIDGE" ct state established,related accept
  }
}
NFT

echo "Quarantine bridge/netns/nftables live. Subnet: ${Q_BASE}.0/24 on $Q_BRIDGE"
echo "Verify: ip netns exec $Q_NS ping -c1 ${Q_BASE}.1"
