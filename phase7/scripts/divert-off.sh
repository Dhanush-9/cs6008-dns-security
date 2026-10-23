#!/bin/sh
set -eu

# Run this ON THE EDGE-ROUTER to remove the diversion route.
echo "Removing diversion route for 172.16.1.10..."
ip route del 172.16.1.10/32 2>/dev/null || true
echo "Diversion removed."
