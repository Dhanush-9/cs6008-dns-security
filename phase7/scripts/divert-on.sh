#!/bin/sh
set -eu

# Run this ON THE EDGE-ROUTER.
#
# The edge-router is the only path the resolver's reply takes to reach the
# client. Normally it delivers that reply straight to the client (172.16.1.10).
# Here we add a /32 route that sends anything bound for the client via the
# attacker (172.16.1.100) instead. The attacker then relays or forges it.
#
# This is pure routing on the router we control. There is NO ARP spoofing, and
# the client's own configuration is never touched.

# Find the interface facing the client network (172.16.1.0/24)
IFACE=$(ip -4 -o addr show to 172.16.1.0/24 | awk '{print $2}')
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi

echo "Diverting client-bound replies (172.16.1.10) via attacker (172.16.1.100) on $IFACE..."
ip route replace 172.16.1.10/32 via 172.16.1.100 dev "$IFACE"
echo "Diversion active."
