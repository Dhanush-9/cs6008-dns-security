#!/bin/sh
set -eu

# Static route – the client subnet reaches the resolver subnet through edge-router.
ip route del default 2>/dev/null || true
ip route replace 172.16.2.0/24 via 172.16.1.2

# Install the private CA so that curl, kdig, and openssl trust the resolver cert
# without any -k / --insecure flag.
if [ -f /etc/bind-tls/ca.crt ]; then
    cp /etc/bind-tls/ca.crt /usr/local/share/ca-certificates/cs6008-ca.crt
    update-ca-certificates --fresh >/dev/null 2>&1 || true
fi

exec "$@"
