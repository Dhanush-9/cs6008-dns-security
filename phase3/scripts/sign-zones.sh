#!/bin/sh
set -e

# If running on host and dnssec-keygen is not found, re-run inside Docker container
if [ "$1" != "--inside-container" ] && ! command -v dnssec-keygen >/dev/null 2>&1; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PHASE3_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    echo "[*] dnssec-keygen not found on host. Executing inside Docker container..."
    sg docker -c "docker run --rm -v \"$PHASE3_DIR:/lab\" cs6008-phase3-lab /lab/scripts/sign-zones.sh --inside-container"
    exit $?
fi

# Directory setup
if [ "$1" = "--inside-container" ]; then
    BASE="/lab"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    BASE="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

DOMAIN_DIR="$BASE/bind/domain"
TLD_DIR="$BASE/bind/tld"
ROOT_DIR="$BASE/bind/root"
RESOLVER_DIR="$BASE/bind/resolver"

echo "=== DNSSEC Zone Signing (RSASHA256) ==="

# 0. Clean previous keys and signed files
echo "[*] Cleaning old keys, signed files, and trust anchors..."
rm -f "$DOMAIN_DIR"/K* "$DOMAIN_DIR"/*.signed "$DOMAIN_DIR"/dsset-*
rm -f "$TLD_DIR"/K* "$TLD_DIR"/*.signed "$TLD_DIR"/dsset-*
rm -f "$ROOT_DIR"/K* "$ROOT_DIR"/*.signed "$ROOT_DIR"/dsset-*
rm -f "$RESOLVER_DIR"/trust-anchors.conf "$RESOLVER_DIR"/root.key "$RESOLVER_DIR"/root.ds

# 1. Sign example.com (Domain)
echo "[*] Step 1: Signing example.com zone..."
cd "$DOMAIN_DIR"
cp db.example.com.base db.example.com
KSK_EX=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK example.com)
ZSK_EX=$(dnssec-keygen -a RSASHA256 -b 1024 example.com)
cat "${KSK_EX}.key" "${ZSK_EX}.key" >> db.example.com
dnssec-signzone -o example.com -f db.example.com.signed -e +30d db.example.com
DS_EXAMPLE=$(cat dsset-example.com.)
echo "[+] example.com signed. Generated DS record:"
echo "$DS_EXAMPLE"

# 2. Sign com (TLD)
echo "[*] Step 2: Signing com zone (with example.com DS included)..."
cd "$TLD_DIR"
cp db.com.base db.com
cat "$DOMAIN_DIR/dsset-example.com." >> db.com
KSK_COM=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK com)
ZSK_COM=$(dnssec-keygen -a RSASHA256 -b 1024 com)
cat "${KSK_COM}.key" "${ZSK_COM}.key" >> db.com
dnssec-signzone -o com -f db.com.signed -e +30d db.com
DS_COM=$(cat dsset-com.)
echo "[+] com signed. Generated DS record:"
echo "$DS_COM"

# 3. Sign . (Root)
echo "[*] Step 3: Signing root (.) zone (with com DS included)..."
cd "$ROOT_DIR"
cp db.root.base db.root
cat "$TLD_DIR/dsset-com." >> db.root
KSK_ROOT=$(dnssec-keygen -a RSASHA256 -b 2048 -f KSK .)
ZSK_ROOT=$(dnssec-keygen -a RSASHA256 -b 1024 .)
cat "${KSK_ROOT}.key" "${ZSK_ROOT}.key" >> db.root
dnssec-signzone -o . -f db.root.signed -e +30d db.root
echo "[+] Root (.) signed."

# 4. Generate Resolver Trust Anchor and delv root.key
echo "[*] Step 4: Extracting Root KSK Trust Anchor for Resolver..."
ROOT_KSK_KEYFILE=$(grep -l "257 3 8" "$ROOT_DIR"/K.*.key | head -n 1)
ROOT_PUBKEY=$(awk '/DNSKEY 257 3 8/ { $1=""; $2=""; $3=""; $4=""; $5=""; $6=""; print $0 }' "$ROOT_KSK_KEYFILE" | tr -d ' \n\r\t')

cat << EOF > "$RESOLVER_DIR/trust-anchors.conf"
trust-anchors {
    "." initial-key 257 3 8 "$ROOT_PUBKEY";
};
EOF

cat << EOF > "$RESOLVER_DIR/root.key"
trust-anchors {
    "." initial-key 257 3 8 "$ROOT_PUBKEY";
};
EOF

cp "$ROOT_DIR/dsset-." "$RESOLVER_DIR/root.ds"

# Set permissions so BIND daemon can read them
chmod 644 "$DOMAIN_DIR"/* "$TLD_DIR"/* "$ROOT_DIR"/* "$RESOLVER_DIR"/* 2>/dev/null || true

echo "=== DNSSEC Signing Complete! ==="
echo "Trust Anchor installed at: $RESOLVER_DIR/trust-anchors.conf"

