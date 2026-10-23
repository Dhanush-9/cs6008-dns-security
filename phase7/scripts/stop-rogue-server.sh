#!/bin/sh
set -eu

echo "Stopping rogue TLS server..."
pkill -f 'openssl s_server' 2>/dev/null || true
ip addr del 172.16.2.10/32 dev lo 2>/dev/null || true
echo "Rogue TLS server stopped."

