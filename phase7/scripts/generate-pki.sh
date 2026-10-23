#!/bin/sh
set -eu

# If we were re-invoked inside a container, BASE is already set.
if [ "${1:-}" = "--inside-container" ]; then
    BASE=/lab
else
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    BASE=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

    if ! command -v openssl >/dev/null 2>&1; then
        echo "[*] openssl not found on host; running inside container..."
        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$BASE:/lab" cs6008-phase7-lab \
            /lab/scripts/generate-pki.sh --inside-container </dev/null
        exit $?
    fi
fi

PKI_DIR="$BASE/pki"
mkdir -p "$PKI_DIR"
cd "$PKI_DIR"

echo "=== Phase 7 PKI generation ==="

# ── 1. Private Root CA ─────────────────────────────────────────────────────────
echo "[*] 1/3  Generating Root CA..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 730 \
    -out ca.crt \
    -subj "/C=IN/O=CS6008 Lab/CN=CS6008 Root CA" 2>/dev/null

# ── 2. Resolver certificate (SAN: DNS only, no IP SAN) ────────────────────────
echo "[*] 2/3  Generating resolver certificate (SAN=DNS:resolver.cs6008.local)..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out resolver.key 2>/dev/null

cat > resolver.ext <<'EOF'
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = @alt_names

[alt_names]
DNS.1 = resolver.cs6008.local
EOF

openssl req -new -key resolver.key -out resolver.csr \
    -subj "/C=IN/O=CS6008 Lab/CN=resolver.cs6008.local" 2>/dev/null
openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out resolver.crt -days 730 -sha256 -extfile resolver.ext 2>/dev/null

# ── 3. Rogue certificate (self-signed, untrusted — for Attack ii) ─────────────
echo "[*] 3/3  Generating rogue (self-signed) certificate..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rogue.key 2>/dev/null
openssl req -x509 -new -nodes -key rogue.key -sha256 -days 730 \
    -out rogue.crt \
    -subj "/C=IN/O=Attacker/CN=resolver.cs6008.local" \
    -addext "subjectAltName=DNS:resolver.cs6008.local" \
    -addext "basicConstraints=CA:FALSE" 2>/dev/null

chmod 644 ca.key resolver.key rogue.key ca.crt resolver.crt rogue.crt

echo "[+] PKI ready in $PKI_DIR"
echo "    ca.crt       — trust anchor installed in client"
echo "    resolver.crt — BIND 9 DoT certificate (DNS SAN only)"
echo "    rogue.crt    — untrusted cert for Attack ii"
