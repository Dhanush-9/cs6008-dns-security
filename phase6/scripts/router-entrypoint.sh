#!/bin/sh
set -eu

# Routers have an interface in each of their two networks already, so they only
# need their catch-all default route removed.
ip route del default 2>/dev/null || true

exec "$@"
