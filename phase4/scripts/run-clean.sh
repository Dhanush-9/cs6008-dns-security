#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHASE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

compose() {
    docker compose -f "$PHASE_DIR/compose.yml" "$@" </dev/null
}

echo "=== Clean baseline: signed hierarchy, no attacker in the path ==="
compose down --remove-orphans 2>/dev/null || true
"$SCRIPT_DIR/sign-zones.sh" secure
compose up -d --force-recreate

echo "[*] Waiting for the resolver..."
tries=0
until compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 status >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 20 ] || { echo "Resolver did not become ready." >&2; exit 1; }
    sleep 1
done

compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 flush

echo
echo "Expected: dig returns 172.16.1.20 with the ad flag and RRSIG records."
compose exec -T client dig +dnssec example.com.
echo
echo "Expected: the genuine web page is returned."
compose exec -T client curl -sS http://example.com
