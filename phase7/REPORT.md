# Phase 7 Report: Encrypting the Last Mile (DoT / DoH)

**Course**: CS6008 Network Security  
**Phase**: 7 — Encrypting the Last Mile  

---

## 1. Architectural Overview & Deployment Choices

### 1.1 Secure Last-Mile Topology
In Phase 6, moving the attacker to the client's subnet (`172.16.1.100`) bypassed DNSSEC because the link between the recursive resolver and the client was unauthenticated cleartext. In Phase 7, we secure this hop using **DNS-over-TLS (DoT)** on standard TCP port 853:

1. **Private PKI**:
   - A private Root CA (`ca.key`, `ca.crt`) was generated and installed into the client's system trust store (`/usr/local/share/ca-certificates/cs6008-ca.crt` followed by `update-ca-certificates`). This guarantees clean validation without `-k` or insecure flags.
   - The resolver was assigned the DNS name `resolver.cs6008.local` pointing to `172.16.2.10` via Docker Compose `extra_hosts`.
   - The resolver certificate (`resolver.crt`) was issued with `subjectAltName = DNS:resolver.cs6008.local` (strictly no IP SAN, complying with the assignment specification).
2. **Resolver Configuration**:
   - BIND 9.20 on the resolver was configured with a `tls local-tls` block and `listen-on port 853 tls local-tls { 172.16.2.10; };`.
   - UDP/TCP port 53 was maintained for fallback and downgrade testing.
   - Upstream DNSSEC cryptographic validation was kept enabled (`dnssec-validation yes;`).
3. **Client Transport Profiles**:
   - **Client 1 (Strict Profile — `client-strict.sh`)**: Enforces DoT over port 853 with strict CA certificate validation. Never falls back to unencrypted cleartext.
   - **Client 2 (Opportunistic Profile — `client-opportunistic.sh`)**: Attempts DoT over port 853 first. Falls back to cleartext UDP 53 *only* when transport denial occurs (connection timeout or refusal). Aborts on TLS-layer errors (certificate verification failure or ciphertext tampering).

---

## 2. Baseline Verification Evidence (Phase 7.2)

### 2.1 Encrypted Resolution & DNSSEC Chain
From `phase7/evidence/baseline-strict.log`:
```text
;; TLS session (TLS1.3)-(ECDHE-X25519)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 24716
;; Flags: qr rd ra ad; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 1

;; ANSWER SECTION:
example.com.        	576	IN	A	172.16.1.20

;; From 172.16.2.10@853(TLS) in 3.3 ms
```
- **TLS 1.3 Session**: Authenticated cleanly against `CS6008 Root CA` without warnings.
- **DNSSEC Authentic Data (`ad`) Flag**: Present in the header flags, confirming that the recursive resolver validated the upstream hierarchy down from the root trust anchor before encrypting the answer to the client.
- **Resolution**: Returns genuine webserver `172.16.1.20`.

### 2.2 Traffic Inspection on Edge Router
From `phase7/evidence/baseline-edge-router.pcap`:
- Filtering for `port 53 or port 853` on `edge-router`:
  - 100% of packets between `172.16.1.10` and `172.16.2.10` are TCP port 853 (TLS 1.3 Handshake and Application Data).
  - Exactly **0 cleartext DNS packets** (port 53) traverse the router during lookup.

---

## 3. Attack Evaluation: The $3 \times 2$ Matrix (Phase 7.3 & 7.4)

With the adversary positioned on the client subnet (`172.16.1.100`) and client-bound replies diverted through the attacker via `edge-router` route diversion, we executed all three attack aims against both client configurations.

### Summary Results Matrix

| Attempt | Client 1 (Strict Profile) | Client 2 (Opportunistic Profile) | Security Outcome |
| :--- | :--- | :--- | :--- |
| **(i) Alter Answer in Transit** | **FAILED TO FORGE**<br>`TLS decryption failed` | **FAILED TO FORGE**<br>`TLS decryption failed` (Refuses fallback) | Cryptographic integrity (AEAD) prevents in-flight tampering. |
| **(ii) Impersonate Resolver (Rogue Cert)** | **FAILED TO FORGE**<br>`Error in the certificate` | **FAILED TO FORGE**<br>`Error in the certificate` (Refuses fallback) | PKI authentication & SAN verification block MITM impersonation. |
| **(iii) Deny Encrypted Transport** | **FAILED TO FORGE**<br>Query times out (DoS only) | **SUCCESSFUL FORGERY**<br>Downgrades to UDP 53 $\rightarrow$ resolves `172.16.1.30` | Opportunistic fallback creates a silent downgrade vulnerability. |

---

### 3.1 Attempt (i): Alter Answer in Transit (Tampering)

#### Attack Mechanism
The adversary ran the C++ interceptor in `--tamper-tls` mode. The TCP 3-way handshake and the TLS 1.3 handshake flight (`ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`) were relayed transparently. When the resolver transmitted the subsequent TLS record containing the encrypted DNS answer, the interceptor flipped bits inside the ciphertext payload, recomputed TCP and IP checksums, and forwarded the segment.

#### Observed Results
From `phase7/evidence/attempt1-strict.log`:
```text
;; WARNING: TLS, failed to receive reply (Decryption has failed.)
;; WARNING: can't receive reply from 172.16.2.10@853(TLS)
;; ERROR: failed to query server resolver.cs6008.local@853(TCP)
```
From `phase7/evidence/attempt1-opportunistic.log`:
```text
[client-opportunistic] Attempting DoT to resolver.cs6008.local:853 ...
[client-opportunistic] TLS-layer error (no fallback):
;; WARNING: TLS, failed to receive reply (Decryption has failed.)
;; WARNING: can't receive reply from 172.16.2.10@853(TLS)
;; ERROR: failed to query server resolver.cs6008.local@853(TCP)
```

#### Explanation
- **Why it failed for Client 1**: TLS 1.3 uses Authenticated Encryption with Associated Data (AEAD, here `AES-256-GCM`). Any modification to the ciphertext or record headers invalidates the GCM authentication tag. Upon decryption, the client's crypto engine detects tag mismatch, rejects the payload, and aborts the connection with a fatal TLS alert (`bad_record_mac`).
- **Why it failed for Client 2**: Client 2 distinguishes between transport denial and cryptographic tampering. Because the TLS connection was established and failed due to a decryption error, Client 2 recognizes an active tampering attempt and refuses to fall back to cleartext.

---

### 3.2 Attempt (ii): Impersonate Resolver with a Rogue Certificate

#### Attack Mechanism
The adversary routed `172.16.2.10/32` to `172.16.1.100` and bound a rogue TLS daemon (`openssl s_server`) on port 853 serving `rogue.crt` (a self-signed certificate with `SAN = DNS:resolver.cs6008.local`). The attacker completed the TCP handshake and TLS server flight with the client.

#### Observed Results
From `phase7/evidence/attempt2-strict.log`:
```text
;; WARNING: TLS, handshake failed (Error in the certificate.)
;; ERROR: failed to query server resolver.cs6008.local@853(TCP)
```
From `phase7/evidence/attempt2-opportunistic.log`:
```text
[client-opportunistic] Attempting DoT to resolver.cs6008.local:853 ...
[client-opportunistic] TLS-layer error (no fallback):
;; WARNING: TLS, handshake failed (Error in the certificate.)
;; ERROR: failed to query server resolver.cs6008.local@853(TCP)
```

#### Explanation
- **Why it failed for Client 1**: The client validates the presented certificate against its installed CA store (`CS6008 Root CA`). Because `rogue.crt` was not signed by the trusted CA, certificate path validation failed (`X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT`). The client terminated the handshake without sending any DNS query.
- **Why it failed for Client 2**: Although the transport connected, the handshake aborted with a TLS certificate validation failure. In RFC 8310, authentication failures indicate an active impersonation attack; opportunistic clients must not fall back to unencrypted transmission when certificate validation fails.

---

### 3.3 Attempt (iii): Deny Encrypted Transport (Downgrade Attack)

#### Attack Mechanism
The adversary ran the C++ interceptor in `--deny` mode. The interceptor captured and dropped all TCP 853 segments from the resolver to the client, preventing DoT handshake completion. Concurrently, it monitored UDP port 53: when cleartext queries for `example.com` arrived, it injected forged responses pointing to `rogue-web` (`172.16.1.30`).

#### Observed Results
- **Client 1 (Strict)** (`phase7/evidence/attempt3-strict.log`):
  ```text
  ;; WARNING: connection timeout for 172.16.2.10@853(TLS)
  ;; ERROR: failed to query server resolver.cs6008.local@853(TCP)
  ```
  *Result*: Attack caused Denial of Service (DoS), but **failed to forge**.
- **Client 2 (Opportunistic)** (`phase7/evidence/attempt3-opportunistic.log`):
  ```text
  [client-opportunistic] Attempting DoT to resolver.cs6008.local:853 ...
  [client-opportunistic] Transport denial detected – falling back to cleartext UDP 53
  ;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 56811
  ;; Flags: qr rd ra ad; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 0

  ;; ANSWER SECTION:
  example.com.        	600	IN	A	172.16.1.30
  ```
- **Web Fetch (`curl`)** (`phase7/evidence/attempt3-curl.log`):
  ```html
  <h1>Rogue Example.com</h1>
  <p>You have been redirected to the rogue server at 172.16.1.30!</p>
  ```
  *Result*: **ATTACK SUCCEEDED.** The client was redirected to the rogue website.

#### Explanation
- **Why Client 1 resisted**: Strict DoT requires an encrypted and authenticated transport. When TCP 853 timed out, Client 1 threw a transport error and halted. It never transmitted an unencrypted query, giving the attacker no cleartext surface to poison.
- **Why Client 2 succumbed**: Opportunistic security prioritizes availability over security. When TCP 853 failed to connect, Client 2 assumed the resolver did not support DoT and automatically downgraded to legacy UDP 53. Once on cleartext UDP, the resolver-to-client link had no authentication, allowing the Phase 6 response forgery attack to inject the rogue IP `172.16.1.30`.

---

## 4. Discussion & Analysis Questions (Phase 7.4)

### 4.1 DoT vs. DoH: Deployment Choice and Comparative Drawbacks
In this phase, we deployed **DNS-over-TLS (DoT)** on TCP port 853.

#### Drawbacks of DoT Relative to DoH:
1. **Easy Port-Based Blocking & Censorship**: DoT runs on a dedicated, standardized port (TCP 853). Network operators, captive portals, and on-path adversaries can easily identify, filter, or blackhole port 853 (as demonstrated in Attempt iii) without disrupting web traffic. DoH, by contrast, multiplexes over TCP 443 alongside standard HTTPS traffic, making selective blocking far more difficult without breaking general web browsing.
2. **Middlebox & Enterprise Firewall Incompatibility**: Many restrictive networks (e.g., enterprise Wi-Fi, hotels) block non-standard outbound ports by default, completely preventing DoT from establishing connections.

#### Drawbacks of DoH Relative to DoT:
1. **Protocol Overhead & Complexity**: DoH runs DNS inside HTTP/2 or HTTP/3 frames layered over TLS and TCP/QUIC. This introduces substantial framing overhead, HPACK/QPACK state management, and additional parsing complexity compared to DoT's simple 2-byte length-prefixed DNS message framing.
2. **Privacy Risks via HTTP Metadata**: DoH operates at the application layer, meaning HTTP request headers (User-Agent, cookies, accept headers) can potentially leak client metadata or enable tracking if the client and DoH resolver exchange HTTP session state.
3. **Bypassing Local Enterprise Controls**: DoH can bypass corporate split-horizon DNS, internal domain routing, and enterprise malware filtering, creating administrative blind spots.

---

### 4.2 What an Encrypted, Authenticated Last Mile Still Does Not Protect
Securing the client–resolver link with DoT/DoH is critical, but it does **not** protect against the following threat vectors:

1. **Malicious or Compromised Recursive Resolver**:
   DoT only provides hop-by-hop encryption. The recursive resolver decrypts the query in plaintext. A malicious, compromised, or legally compelled resolver can log user lookup history, perform censorship, or inject false answers (unless end-to-end DNSSEC is verified on the stub itself).
2. **Upstream Insecurity for Unsigned Zones**:
   If the queried domain does not implement DNSSEC, encryption between the client and resolver does not protect against poisoning on the resolver–authoritative hops (Phases 2 and 4). If upstream data is forged, the resolver will simply encrypt and deliver the poisoned data to the client.
3. **SNI and IP Leakage on Subsequent Connections**:
   Even if the DNS lookup of `example.com` is completely confidential, when the client subsequently initiates an HTTPS or HTTP connection to `172.16.1.20`, the destination IP address is visible in the IP header, and the Server Name Indication (SNI) is transmitted in cleartext during the TLS ClientHello (unless Encrypted Client Hello / ECH is deployed). On-path eavesdroppers can readily infer the destination domain.
4. **Traffic Analysis & Metadata Leaks**:
   Although payloads are encrypted, packet timing, query frequency, and packet sizes (unless padded with EDNS(0) padding RFC 7830) allow on-path passive adversaries to fingerprint specific domain lookups with high statistical confidence.

---

## 5. Deliverables Inventory

All required deliverables are present in the `phase7/` directory:
- `phase7/pki/`: `ca.crt`, `ca.key`, `resolver.crt`, `resolver.key`, `rogue.crt`, `rogue.key`
- `phase7/scripts/generate-pki.sh`: Automated PKI generation script
- `phase7/bind/resolver/named.conf`: BIND 9.20 DoT resolver configuration (`listen-on port 853 tls local-tls`)
- `phase7/client/client-strict.sh`: Client 1 transport configuration script (strict DoT)
- `phase7/client/client-opportunistic.sh`: Client 2 transport configuration script (opportunistic DoT with cleartext fallback)
- `phase7/attacker/interceptor.cpp`: C++ libpcap interceptor supporting relay, forge, TLS tamper, and transport denial
- `phase7/scripts/`: `run-lab.sh`, `start-tamper.sh`, `start-rogue-server.sh`, `start-deny.sh`, `stop-deny.sh`
- `phase7/evidence/`: Complete logs and `.pcap` packet captures for baseline resolution and all 6 attack/client combinations
- `phase7/README.md`: Reproduction commands and walkthrough
- `phase7/REPORT.md`: Comprehensive phase report

