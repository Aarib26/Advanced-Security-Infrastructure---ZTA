#!/bin/bash
set -euo pipefail

NODE_CFG="/opt/zeek/etc/node.cfg"
NAMESPACE="zta-demo"

echo "=== fix-zeek-interfaces: resolving current Cilium endpoint interfaces ==="

CILIUM_POD=$(kubectl get pods -n kube-system -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')
if [ -z "$CILIUM_POD" ]; then
  echo "ERROR: could not find a running cilium pod in kube-system" >&2
  exit 1
fi

get_iface_for_app() {
  local app_label="$1"
  local pod_ip
  pod_ip=$(kubectl get pods -n "$NAMESPACE" -l "app=${app_label}" -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)
  if [ -z "$pod_ip" ]; then
    echo "ERROR: no running pod found for app=${app_label} in ${NAMESPACE}" >&2
    return 1
  fi

  local ep_id
  ep_id=$(kubectl exec -n kube-system "$CILIUM_POD" -- cilium-dbg endpoint list -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for ep in data:
    addr = (ep.get('status', {}).get('networking', {}).get('addressing') or [{}])[0]
    if addr.get('ipv4') == '${pod_ip}':
        print(ep['id'])
        break
")
  if [ -z "$ep_id" ]; then
    echo "ERROR: could not resolve Cilium endpoint id for pod IP ${pod_ip} (app=${app_label})" >&2
    return 1
  fi

  local iface
  iface=$(kubectl exec -n kube-system "$CILIUM_POD" -- cilium-dbg endpoint get "$ep_id" -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
ep = data[0] if isinstance(data, list) else data
print(ep['status']['networking']['interface-name'])
")
  if [ -z "$iface" ]; then
    echo "ERROR: could not resolve interface-name for endpoint id ${ep_id} (app=${app_label})" >&2
    return 1
  fi
  echo "$iface"
}

IFACE_BACKEND=$(get_iface_for_app backend)
IFACE_FRONTEND=$(get_iface_for_app frontend)
IFACE_DATABASE=$(get_iface_for_app database)
IFACE_ATTACKER=$(get_iface_for_app attacker)

echo "backend  -> ${IFACE_BACKEND}"
echo "frontend -> ${IFACE_FRONTEND}"
echo "database -> ${IFACE_DATABASE}"
echo "attacker -> ${IFACE_ATTACKER}"

echo "=== updating ${NODE_CFG} (worker-backend) ==="
sudo sed -i "s/interface=af_packet::lxc[a-f0-9]*/interface=af_packet::${IFACE_BACKEND}/" "$NODE_CFG"
grep -A3 "\[worker-backend\]" "$NODE_CFG" || true

echo "=== updating standalone systemd units ==="
sudo sed -i "s|zeek -i lxc[a-f0-9]* local|zeek -i ${IFACE_FRONTEND} local|" /etc/systemd/system/zeek-frontend.service
sudo sed -i "s|zeek -i lxc[a-f0-9]* local|zeek -i ${IFACE_DATABASE} local|" /etc/systemd/system/zeek-database.service
sudo sed -i "s|zeek -i lxc[a-f0-9]* local|zeek -i ${IFACE_ATTACKER} local|" /etc/systemd/system/zeek-attacker.service

sudo systemctl daemon-reload

echo "=== redeploying zeekctl (worker-backend) ==="
sudo /opt/zeek/bin/zeekctl deploy

echo "=== restarting standalone units ==="
sudo systemctl restart zeek-frontend zeek-database zeek-attacker

sleep 3
echo "=== final status ==="
sudo /opt/zeek/bin/zeekctl status
sudo systemctl status zeek-frontend zeek-database zeek-attacker --no-pager | grep -E "Active|zeek -i"

echo "=== fix-zeek-interfaces: done ==="
