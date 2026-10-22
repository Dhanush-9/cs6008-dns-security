#!/bin/sh
set -eu

NEXT_HOP=172.16.2.3

ping -c 1 -W 1 "$NEXT_HOP" >/dev/null 2>&1 || true
arping -c 1 -w 1 -I eth0 "$NEXT_HOP" >/dev/null 2>&1 || true

NEXT_HOP_MAC=$(ip neigh show "$NEXT_HOP" 2>/dev/null | awk '/lladdr/ {print $5}' | head -n 1)
if [ -z "$NEXT_HOP_MAC" ]; then
    NEXT_HOP_MAC=$(awk -v ip="$NEXT_HOP" '$1 == ip {print $4}' /proc/net/arp | head -n 1)
fi

if [ -z "$NEXT_HOP_MAC" ] || [ "$NEXT_HOP_MAC" = "00:00:00:00:00:00" ]; then
    echo "Could not resolve the core router MAC address." >&2
    exit 1
fi

cd /lab/attacker
make

exec ./zone-walker \
    --iface eth0 \
    --server 172.16.3.30 \
    --zone example.com. \
    --next-hop-mac "$NEXT_HOP_MAC"
