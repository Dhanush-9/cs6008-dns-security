#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHASE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

compose() {
    docker compose -f "$PHASE_DIR/compose.yml" "$@" </dev/null
}

echo "=== Run A: secure delegation; stripping must fail ==="
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

compose exec -T core-router /lab/scripts/divert-on.sh
compose exec -T attacker /lab/scripts/start-strip-full.sh
compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 flush

echo
echo "Expected: SERVFAIL, because com securely delegates example.com with a DS."
echo "Verify: docker compose -f phase4/compose.yml exec -T client dig +dnssec example.com. </dev/null"
echo "Verify: docker compose -f phase4/compose.yml exec -T client curl -sS http://example.com </dev/null"
