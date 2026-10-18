#!/bin/sh
set -eu

ip route del default 2>/dev/null || true
ip route replace 172.16.2.0/24 via 172.16.3.3

exec "$@"