#!/bin/sh
set -eu

echo "Removing diversion route for 172.16.2.10..."
ip route del 172.16.2.10/32 2>/dev/null || true
echo "Diversion removed."

