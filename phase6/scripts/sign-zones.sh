#!/bin/sh
set -eu

if [ "${1:-}" = "--inside-container" ]; then
    BASE=/lab
else
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    BASE=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

    if ! command -v dnssec-keygen >/dev/null 2>&1; then
        echo "[*] DNSSEC tools not found on host; signing inside the lab image..."
        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$BASE:/lab" cs6008-phase6-lab \
            /lab/scripts/sign-zones.sh --inside-container </dev/null
        exit $?
    fi
fi

DOMAIN_DIR="$BASE/bind/domain"
TLD_DIR="$BASE/bind/tld"
ROOT_DIR="$BASE/bind/root"
RESOLVER_DIR="$BASE/bind/resolver"

echo "=== Phase 6 DNSSEC signing ==="

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
dnssec-signzone -o example.com -f db.example.com.signed -e +30d db.example.com >/dev/null

echo "[*] 2/3 Signing com and adding the example.com DS..."
cd "$TLD_DIR"
cp db.com.base db.com
cat "$DOMAIN_DIR/dsset-example.com." >> db.com
KSK_COM=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK com)
ZSK_COM=$(dnssec-keygen -a RSASHA256 -b 1024 com)
cat "${KSK_COM}.key" "${ZSK_COM}.key" >> db.com
dnssec-signzone -o com -f db.com.signed -e +30d db.com >/dev/null

echo "[*] 3/3 Signing root and adding the com DS..."
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

# The resolver and locally validating client use the same public root anchor.
cp "$RESOLVER_DIR/trust-anchors.conf" "$RESOLVER_DIR/root.key"
cp "$ROOT_DIR/dsset-." "$RESOLVER_DIR/root.ds"

chmod 600 "$DOMAIN_DIR"/K*.private "$TLD_DIR"/K*.private "$ROOT_DIR"/K*.private
chmod 644 "$DOMAIN_DIR"/*.key "$DOMAIN_DIR"/*.signed "$DOMAIN_DIR"/dsset-* \
    "$TLD_DIR"/*.key "$TLD_DIR"/*.signed "$TLD_DIR"/dsset-* \
    "$ROOT_DIR"/*.key "$ROOT_DIR"/*.signed "$ROOT_DIR"/dsset-* \
    "$RESOLVER_DIR"/trust-anchors.conf "$RESOLVER_DIR"/root.key "$RESOLVER_DIR"/root.ds

echo "[+] Signed hierarchy and public root trust anchor are ready."
