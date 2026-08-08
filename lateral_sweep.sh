#!/usr/bin/env bash
NAMESPACE="zta-demo"

echo "== Locating attacker pod =="
ATTACKER_POD=$(kubectl get pod -n $NAMESPACE -l app=attacker -o jsonpath='{.items[0].metadata.name}')

echo "== Generating Lateral Movement IOCs =="
# Grab 5 UNIQUE pod IPs strictly from the Cilium pod CIDR
TARGET_IPS=$(kubectl get po -A -o jsonpath='{.items[*].status.podIP}' | tr ' ' '\n' | grep '^10\.0\.0\.' | sort -u | grep -v '^$' | head -n 5)

for ip in $TARGET_IPS; do
    echo "Probing $ip:22..."
    kubectl exec -n $NAMESPACE $ATTACKER_POD -- /bin/sh -c "nc -z -w 1 $ip 22 >/dev/null 2>&1 || true"
done

echo "== Lateral movement sweep complete. =="
