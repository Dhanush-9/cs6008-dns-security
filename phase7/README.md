# Phase 7: Encrypting the Last Mile (DoT / DoH)

In Phase 6, moving the attacker to the client's subnet exposed that upstream DNSSEC
validation does not protect an unauthenticated, cleartext last-mile link between
the resolver and the stub.

In Phase 7, we secure the client–resolver hop with **DNS-over-TLS (DoT)** on TCP port 853:
- A **private Certificate Authority (CA)** is established and installed into the client's system trust store (allowing clean validation without `-k` or insecure bypasses).
- The resolver is reached strictly by name (`resolver.cs6008.local`). Its certificate is issued with exactly that name in the `subjectAltName` (DNS SAN only, no IP SAN).
- Upstream DNSSEC validation remains active on the recursive resolver (`dnssec-validation yes;`).
- We evaluate three distinct attacks against two client transport postures:
  - **Client 1 (Strict Profile)**: Refuses cleartext. Requires DoT with clean certificate validation; aborts immediately on any transport or security failure.
  - **Client 2 (Opportunistic Profile)**: Attempts DoT first; falls back to cleartext UDP 53 only upon transport denial (connection timeout/refusal). Aborts on TLS-layer errors.

---

## 1. Build and Start Phase 7

Run all commands from the repository root:

```bash
docker build -f phase7/docker/Dockerfile -t cs6008-phase7-lab phase7 </dev/null
bash phase7/scripts/run-lab.sh </dev/null
docker compose -f phase7/compose.yml ps </dev/null
```

All 10 containers will report `Up`. The start script generates the private CA, issues the resolver and rogue certificates into `phase7/pki/`, signs the DNSSEC hierarchy, and starts all services.

---

## 2. Verify Secure Baseline (Phase 7.2)

Verify clean DoT resolution and certificate validation:

```bash
# Query using Client 1 (Strict)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-strict.sh example.com </dev/null \
  | tee phase7/evidence/baseline-strict.log

# Query using Client 2 (Opportunistic)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-opportunistic.sh example.com </dev/null \
  | tee phase7/evidence/baseline-opportunistic.log
```

Expected: Both return `172.16.1.20` over TLS 1.3 on port 853 with the `ad` (Authentic Data) flag set and zero errors.

### Packet Capture on Edge Router
Verify that resolution traffic on the router is strictly encrypted TLS over TCP 853 with zero cleartext DNS packets:

```bash
docker compose -f phase7/compose.yml exec -d edge-router \
  tcpdump -U -i eth0 -nn -s0 -w /tmp/baseline.pcap 'port 53 or port 853' </dev/null

docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-strict.sh example.com </dev/null

docker compose -f phase7/compose.yml exec -T edge-router pkill -INT tcpdump </dev/null
docker compose -f phase7/compose.yml cp \
  edge-router:/tmp/baseline.pcap phase7/evidence/baseline-edge-router.pcap </dev/null

tcpdump -r phase7/evidence/baseline-edge-router.pcap -nn
```

---

## 3. Attack Attempt (i): Alter Answer in Transit (Tampering)

The on-path attacker intercepts client-bound TCP 853 packets, lets the TLS handshake complete, and corrupts the AEAD ciphertext of the post-handshake DNS answer record.

```bash
# 1. Enable router diversion
docker compose -f phase7/compose.yml exec -T edge-router \
  /lab/scripts/divert-on.sh </dev/null

# 2. Start tamper interceptor on attacker
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/start-tamper.sh </dev/null

# 3. Start packet capture
docker compose -f phase7/compose.yml exec -d attacker \
  tcpdump -U -i eth0 -nn -s0 -w /tmp/attempt1.pcap 'port 853 or port 53' </dev/null

# 4. Test Client 1 (Strict)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-strict.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt1-strict.log

# 5. Test Client 2 (Opportunistic)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-opportunistic.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt1-opportunistic.log

# 6. Stop capture and save logs
docker compose -f phase7/compose.yml exec -T attacker pkill -INT tcpdump </dev/null
docker compose -f phase7/compose.yml cp \
  attacker:/tmp/attempt1.pcap phase7/evidence/attempt1.pcap </dev/null
docker compose -f phase7/compose.yml exec -T attacker \
  cat /lab/attacker/interceptor.log </dev/null > phase7/evidence/attempt1-interceptor.log
```

Expected: Both clients fail with `Decryption has failed` (AEAD tag verification failure). Neither client accepts forged data, and Client 2 refuses fallback because this is a TLS cryptographic violation.

---

## 4. Attack Attempt (ii): Impersonate Resolver with Rogue Certificate

The adversary terminates TCP port 853 on the attacker and presents a rogue self-signed certificate (`rogue.crt`) for `resolver.cs6008.local`.

```bash
# 1. Stop previous interceptor
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/stop-interceptor.sh </dev/null

# 2. Divert resolver IP to attacker and start rogue TLS server
docker compose -f phase7/compose.yml exec -T edge-router \
  ip route replace 172.16.2.10/32 via 172.16.1.100 dev eth0 </dev/null
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/start-rogue-server.sh </dev/null

# 3. Start packet capture
docker compose -f phase7/compose.yml exec -d attacker \
  tcpdump -U -i eth0 -nn -s0 -w /tmp/attempt2.pcap 'port 853 or port 53' </dev/null

# 4. Test Client 1 (Strict)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-strict.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt2-strict.log

# 5. Test Client 2 (Opportunistic)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-opportunistic.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt2-opportunistic.log

# 6. Stop capture and clean up
docker compose -f phase7/compose.yml exec -T attacker pkill -INT tcpdump </dev/null
docker compose -f phase7/compose.yml cp \
  attacker:/tmp/attempt2.pcap phase7/evidence/attempt2.pcap </dev/null
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/stop-rogue-server.sh </dev/null
docker compose -f phase7/compose.yml exec -T edge-router \
  ip route del 172.16.2.10/32 </dev/null 2>&1 || true
```

Expected: Both clients fail with `TLS, handshake failed (Error in the certificate.)`. The rogue certificate is rejected by the client trust store. Client 2 refuses fallback.

---

## 5. Attack Attempt (iii): Deny Encrypted Transport & Downgrade

The adversary blocks TCP 853 traffic to simulate transport denial, then poisons the unencrypted UDP 53 fallback query using Phase 6 response forgery.

```bash
# 1. Ensure client diversion is active
docker compose -f phase7/compose.yml exec -T edge-router \
  /lab/scripts/divert-on.sh </dev/null

# 2. Start deny-and-downgrade interceptor on attacker
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/start-deny.sh </dev/null

# 3. Start packet capture
docker compose -f phase7/compose.yml exec -d attacker \
  tcpdump -U -i eth0 -nn -s0 -w /tmp/attempt3.pcap 'port 853 or port 53' </dev/null

# 4. Test Client 1 (Strict)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-strict.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt3-strict.log

# 5. Test Client 2 (Opportunistic)
docker compose -f phase7/compose.yml exec -T client \
  /lab/client/client-opportunistic.sh example.com </dev/null 2>&1 \
  | tee phase7/evidence/attempt3-opportunistic.log

# 6. Fetch website from client
docker compose -f phase7/compose.yml exec -T client \
  curl -4 -sS --connect-timeout 5 http://172.16.1.30/ </dev/null 2>&1 \
  | tee phase7/evidence/attempt3-curl.log

# 7. Stop capture and clean up
docker compose -f phase7/compose.yml exec -T attacker pkill -INT tcpdump </dev/null
docker compose -f phase7/compose.yml cp \
  attacker:/tmp/attempt3.pcap phase7/evidence/attempt3.pcap </dev/null
docker compose -f phase7/compose.yml exec -T attacker \
  cat /lab/attacker/interceptor.log </dev/null > phase7/evidence/attempt3-interceptor.log
docker compose -f phase7/compose.yml exec -T attacker \
  /lab/scripts/stop-deny.sh </dev/null
```

Expected:
- **Client 1 (Strict)**: Times out on port 853 and aborts. Attack fails to forge.
- **Client 2 (Opportunistic)**: Times out on port 853, detects transport denial, falls back to unencrypted UDP 53. The interceptor injects `172.16.1.30`. Web fetch loads **"Rogue Example.com"**. **Attack lands successfully.**

---

## 6. Stop Phase 7

```bash
docker compose -f phase7/compose.yml exec -T edge-router \
  /lab/scripts/divert-off.sh </dev/null 2>&1 || true
docker compose -f phase7/compose.yml down --remove-orphans </dev/null
```
