#!/usr/bin/env bash
# ZTA Dynamic Attacker Sweep
# Uses POSIX /bin/sh with BusyBox nc and wget. Zero hardcoded IPs.

NAMESPACE="zta-demo"

echo "== Resolving target IPs dynamically =="
BACKEND_IP=$(kubectl get pod -n $NAMESPACE -l app=backend -o jsonpath='{.items[0].status.podIP}')
DATABASE_IP=$(kubectl get pod -n $NAMESPACE -l app=database -o jsonpath='{.items[0].status.podIP}')

if [ -z "$BACKEND_IP" ] || [ -z "$DATABASE_IP" ]; then
    echo "ERROR: Could not resolve backend or database IPs."
    exit 1
fi

echo "Target Backend:  $BACKEND_IP"
echo "Target Database: $DATABASE_IP"

echo "== Locating attacker pod =="
ATTACKER_POD=$(kubectl get pod -n $NAMESPACE -l app=attacker -o jsonpath='{.items[0].metadata.name}')
ATTACKER_IP=$(kubectl get pod -n $NAMESPACE -l app=attacker -o jsonpath='{.items[0].status.podIP}')
echo "Attacker Pod: $ATTACKER_POD ($ATTACKER_IP)"

echo "== Executing port sweep (ports 1-200) via /bin/sh and BusyBox nc =="
kubectl exec -n $NAMESPACE $ATTACKER_POD -- /bin/sh -c "
p=1
while [ \$p -le 200 ]; do
    nc -z -w 1 $BACKEND_IP \$p >/dev/null 2>&1
    nc -z -w 1 $DATABASE_IP \$p >/dev/null 2>&1
    p=\$((p + 1))
done
"

echo "== Executing HTTP connection probes via BusyBox wget =="
kubectl exec -n $NAMESPACE $ATTACKER_POD -- /bin/sh -c "
wget -q -T 2 -O - http://$BACKEND_IP/ >/dev/null 2>&1 || true
wget -q -T 2 -O - http://$DATABASE_IP/ >/dev/null 2>&1 || true
"

echo "== Sweep complete. =="
