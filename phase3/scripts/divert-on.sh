#!/bin/sh
set -eu

# Find interface facing resolver-net (172.16.2.0/24)
IFACE=$(ip -4 -o addr show to 172.16.2.0/24 | awk '{print $2}')
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi

echo "Diverting resolver traffic (172.16.2.10) to attacker (172.16.2.100) via $IFACE..."
ip route replace 172.16.2.10/32 via 172.16.2.100 dev "$IFACE"
echo "Diversion active."

