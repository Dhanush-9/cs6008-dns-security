#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHASE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

compose() {
    docker compose -f "$PHASE_DIR/compose.yml" "$@" </dev/null
}

echo "=== Run B: insecure delegation; stripping can succeed ==="
compose down --remove-orphans 2>/dev/null || true
"$SCRIPT_DIR/sign-zones.sh" insecure
compose up -d --force-recreate

echo "[*] Waiting for the resolver..."
tries=0
until compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 status >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 20 ] || { echo "Resolver did not become ready." >&2; exit 1; }
    sleep 1
done

compose exec -T core-router /lab/scripts/divert-on.sh
compose exec -T attacker /lab/scripts/start-strip.sh
compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 flush

echo
echo "Expected: example.com resolves to 172.16.1.30 and curl reaches the rogue page."
echo "Verify: docker compose -f phase4/compose.yml exec -T client dig +dnssec example.com. </dev/null"
echo "Verify: docker compose -f phase4/compose.yml exec -T client curl -sS http://example.com </dev/null"
