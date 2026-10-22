#!/bin/sh
set -eu

# Usage:
#   ./sign-zones.sh nsec   # readable NSEC chain; zone walking succeeds
#   ./sign-zones.sh nsec3  # hashed NSEC3 chain; direct walking fails

if [ "${1:-}" = "--inside-container" ]; then
    BASE=/lab
    MODE="${2:-nsec}"
else
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    BASE=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
    MODE="${1:-nsec}"

    if ! command -v dnssec-keygen >/dev/null 2>&1; then
        echo "[*] DNSSEC tools not found on host; signing inside the lab image..."
        docker run --rm --user "$(id -u):$(id -g)" -v "$BASE:/lab" cs6008-phase5-lab \
            /lab/scripts/sign-zones.sh --inside-container "$MODE" </dev/null
        exit $?
    fi
fi

case "$MODE" in
    nsec|nsec3) ;;
    *)
        echo "Usage: $0 [nsec|nsec3]" >&2
        exit 2
        ;;
esac

DOMAIN_DIR="$BASE/bind/domain"
TLD_DIR="$BASE/bind/tld"
ROOT_DIR="$BASE/bind/root"
RESOLVER_DIR="$BASE/bind/resolver"

echo "=== Phase 5 DNSSEC signing: $MODE denial ==="

rm -f "$DOMAIN_DIR"/K* "$DOMAIN_DIR"/*.signed "$DOMAIN_DIR"/dsset-*
rm -f "$TLD_DIR"/K* "$TLD_DIR"/*.signed "$TLD_DIR"/dsset-*
rm -f "$ROOT_DIR"/K* "$ROOT_DIR"/*.signed "$ROOT_DIR"/dsset-*
rm -f "$RESOLVER_DIR"/trust-anchors.conf "$RESOLVER_DIR"/root.key "$RESOLVER_DIR"/root.ds

echo "[*] 1/3 Signing example.com..."
cd "$DOMAIN_DIR"
cp db.example.com.base db.example.com
KSK_EX=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK example.com)
ZSK_EX=$(dnssec-keygen -a RSASHA256 -b 1024 example.com)
cat "${KSK_EX}.key" "${ZSK_EX}.key" >> db.example.com

if [ "$MODE" = "nsec3" ]; then
    dnssec-signzone -3 - -H 0 -o example.com -f db.example.com.signed \
        -e +30d db.example.com >/dev/null
    echo "[+] example.com uses NSEC3 with zero extra iterations and no extra salt."
else
    dnssec-signzone -o example.com -f db.example.com.signed \
        -e +30d db.example.com >/dev/null
    echo "[+] example.com uses the default readable NSEC chain."
fi

echo "[*] 2/3 Signing com with the example.com DS..."
cd "$TLD_DIR"
cp db.com.base db.com
cat "$DOMAIN_DIR/dsset-example.com." >> db.com
KSK_COM=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK com)
ZSK_COM=$(dnssec-keygen -a RSASHA256 -b 1024 com)
cat "${KSK_COM}.key" "${ZSK_COM}.key" >> db.com
dnssec-signzone -o com -f db.com.signed -e +30d db.com >/dev/null

echo "[*] 3/3 Signing root with the com DS..."
cd "$ROOT_DIR"
cp db.root.base db.root
cat "$TLD_DIR/dsset-com." >> db.root
KSK_ROOT=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK .)
ZSK_ROOT=$(dnssec-keygen -a RSASHA256 -b 1024 .)
cat "${KSK_ROOT}.key" "${ZSK_ROOT}.key" >> db.root
dnssec-signzone -o . -f db.root.signed -e +30d db.root >/dev/null

ROOT_KSK_KEYFILE=$(grep -l "257 3 8" "$ROOT_DIR"/K.*.key | head -n 1)
ROOT_PUBKEY=$(awk '/DNSKEY 257 3 8/ { $1=""; $2=""; $3=""; $4=""; $5=""; $6=""; print $0 }' \
    "$ROOT_KSK_KEYFILE" | tr -d ' \n\r\t')

cat > "$RESOLVER_DIR/trust-anchors.conf" <<EOF
trust-anchors {
    "." initial-key 257 3 8 "$ROOT_PUBKEY";
};
EOF

cp "$RESOLVER_DIR/trust-anchors.conf" "$RESOLVER_DIR/root.key"
cp "$ROOT_DIR/dsset-." "$RESOLVER_DIR/root.ds"

chmod 600 "$DOMAIN_DIR"/K*.private "$TLD_DIR"/K*.private "$ROOT_DIR"/K*.private
chmod 644 "$DOMAIN_DIR"/*.key "$DOMAIN_DIR"/*.signed "$DOMAIN_DIR"/dsset-* \
    "$TLD_DIR"/*.key "$TLD_DIR"/*.signed "$TLD_DIR"/dsset-* \
    "$ROOT_DIR"/*.key "$ROOT_DIR"/*.signed "$ROOT_DIR"/dsset-* \
    "$RESOLVER_DIR"/trust-anchors.conf "$RESOLVER_DIR"/root.key "$RESOLVER_DIR"/root.ds

echo "[+] Signing complete. example.com denial mode: $MODE"
