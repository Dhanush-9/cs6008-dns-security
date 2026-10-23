#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHASE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

compose() {
    docker compose -f "$PHASE_DIR/compose.yml" "$@" </dev/null
}

echo "=== Phase 7: start signed DoT last-mile lab ==="
compose down --remove-orphans 2>/dev/null || true

# Sign zones (reuses the script from Phase 6/7 – no changes needed).
"$SCRIPT_DIR/sign-zones.sh"

# Generate PKI (CA + resolver cert + rogue cert).
"$SCRIPT_DIR/generate-pki.sh"

compose up -d --force-recreate

echo "[*] Waiting for the resolver..."
tries=0
until compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 status >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || { echo "Resolver did not become ready." >&2; exit 1; }
    sleep 1
done

compose exec -T resolver rndc -k /etc/rndc.key -s 127.0.0.1 flush

echo "[+] Lab ready."
echo "    Verify DoT: docker compose -f phase7/compose.yml exec -T client /lab/client/client-strict.sh example.com"
