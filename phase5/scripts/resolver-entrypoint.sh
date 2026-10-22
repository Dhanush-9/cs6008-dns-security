#!/bin/sh
set -eu

ip route del default 2>/dev/null || true
ip route replace 172.16.1.0/24 via 172.16.2.2
ip route replace 172.16.3.0/24 via 172.16.2.3

# Generate a fresh, container-local RNDC secret instead of storing one in Git.
rndc-confgen -a -c /etc/rndc.key -u bind >/dev/null

exec "$@"
