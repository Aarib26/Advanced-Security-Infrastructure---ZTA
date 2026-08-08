#!/usr/bin/env bash

for SITE in default inner-tunnel; do
    CONFIG="/etc/freeradius/3.0/sites-available/$SITE"
    
    echo "Patching $CONFIG..."
    sudo cp "$CONFIG" "$CONFIG.bak.$(date +%s)"

    sudo sed -i '/^post-auth {/a \
\n\t# ZTA Dynamic NAC Hook: Auto-Onboard BYOD/IoT/Hybrid Devices\
\t# Executes on every successful connection using dynamic payload variables.\
\texec {\
\t\twait = yes\
\t\tprogram = "/usr/bin/env ZTA_SSH_KEY_DIR=/home/aak/.ssh/zta_managed /home/aak/oral_arch/python-scripts/ztaenv/bin/python3 /home/aak/oral_arch/nac/device_onboard.py --device-id %{User-Name} --ip %{Framed-IP-Address} --mac %{Calling-Station-Id} --auth-result accept"\
\t}' "$CONFIG"
done

echo "== Patch Complete =="
