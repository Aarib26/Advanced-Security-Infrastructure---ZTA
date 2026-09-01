#!/bin/bash
echo "=== Checking Cilium Status ==="
cilium status

echo "=== Starting Hubble UI Port-Forward ==="
# Kill any existing port-forward on port 12000 to avoid conflicts
pkill -f "kubectl port-forward.*12000:80" || true

# Forward port 12000 on all interfaces to the hubble-ui service in the background
kubectl port-forward --address 0.0.0.0 -n kube-system svc/hubble-ui 12000:80 > /dev/null 2>&1 &

sleep 3

echo "=== Hubble UI is Live ==="
echo "Open your browser to: http://100.96.17.20:12000"
