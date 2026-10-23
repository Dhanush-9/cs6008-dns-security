#!/bin/sh
# Client 1 – STRICT: encrypts with DoT, refuses any cleartext.
# Fails immediately if TLS cannot be established (connection refused,
# timeout, or certificate error).  Never falls back to port 53.

set -eu
RESOLVER=resolver.cs6008.local
CA=/etc/ssl/certs/ca-certificates.crt
TIMEOUT=5

exec timeout "$TIMEOUT" \
    kdig +tls \
         +tls-ca="$CA" \
         +tls-hostname="$RESOLVER" \
         +time=3 +retry=1 \
         @"$RESOLVER" "$@"
