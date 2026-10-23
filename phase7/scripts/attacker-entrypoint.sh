#!/bin/sh
set -eu

# The attacker now lives on the client network (172.16.1.100). It talks to the
# client directly on the same bridge, so it only needs its default route removed.
ip route del default 2>/dev/null || true

exec "$@"
