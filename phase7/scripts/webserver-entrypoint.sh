#!/bin/sh
set -eu

ip route del default 2>/dev/null || true

exec "$@"
