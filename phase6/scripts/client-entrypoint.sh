#!/bin/sh
set -eu

# The client reaches the resolver network through the edge-router.
ip route del default 2>/dev/null || true
ip route replace 172.16.2.0/24 via 172.16.1.2

exec "$@"
