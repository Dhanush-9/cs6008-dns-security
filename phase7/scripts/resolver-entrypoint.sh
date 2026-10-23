#!/bin/sh
set -eu

# The resolver reaches the client network via the edge-router and the
# authoritative network via the core-router.
ip route del default 2>/dev/null || true
ip route replace 172.16.1.0/24 via 172.16.2.2
ip route replace 172.16.3.0/24 via 172.16.2.3

# Wait for the TLS certificate to be available (mounted by compose).
tries=0
while [ ! -f /etc/bind-tls/resolver.crt ]; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { echo "TLS cert not found after 30s – aborting." >&2; exit 1; }
    sleep 1
done

exec "$@"
