#!/bin/sh
# Client 2 – OPPORTUNISTIC: tries DoT first; falls back to cleartext UDP 53
# ONLY on transport-level denial (connection refused or timeout on port 853).
# A completed-but-untrusted TLS handshake (certificate error) is NOT treated as
# transport denial – the query fails outright in that case.

set -eu
RESOLVER=resolver.cs6008.local
CA=/etc/ssl/certs/ca-certificates.crt

echo "[client-opportunistic] Attempting DoT to $RESOLVER:853 ..."
ERR=$(kdig +tls \
           +tls-ca="$CA" \
           +tls-hostname="$RESOLVER" \
           +time=3 +retry=1 \
           @"$RESOLVER" "$@" 2>&1) || RC=$?

if [ "${RC:-0}" -eq 0 ]; then
    printf '%s\n' "$ERR"
    exit 0
fi

# Distinguish transport-level denial from TLS-layer failure.
# Transport denial  → "can't connect" / "connection refused" / "timed out"
# TLS-layer failure → "handshake failed" / "certificate" / "bad record mac"
if printf '%s\n' "$ERR" | grep -qiE "can.t connect|connection refused|timed? ?out"; then
    echo "[client-opportunistic] Transport denial detected – falling back to cleartext UDP 53"
    kdig +time=3 +retry=1 @"$RESOLVER" "$@"
else
    echo "[client-opportunistic] TLS-layer error (no fallback):"
    printf '%s\n' "$ERR"
    exit 1
fi
