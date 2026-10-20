# CS6008 Assignment 2: Phase 3 Report
**DNSSEC Chain of Trust & On-Path Forgery Defense**

---

## 1. Design & Deployment Overview

In Phase 3, we establish an unbroken **DNSSEC cryptographic chain of trust** across all three authoritative tiers and configure cryptographic validation on the recursive resolver:

* **Root (`.`)**: Signed with 2048-bit KSK and 1024-bit ZSK using `RSASHA256` (Algorithm 8). Publishes a `DS` record for `com.` (Digest type 2 / SHA-256).
* **TLD (`com.`)**: Signed with 2048-bit KSK and 1024-bit ZSK using `RSASHA256`. Publishes a `DS` record for `example.com.` (Digest type 2 / SHA-256).
* **Domain (`example.com.`)**: Signed with 2048-bit KSK and 1024-bit ZSK using `RSASHA256`. Serves signed `A` records and `RRSIG` signatures for `example.com` and `www.example.com`.
* **Resolver (`172.16.2.10`)**: Enabled `dnssec-validation yes;` in `named.conf` and configured with a single static trust anchor containing the public key of the Root KSK (`trust-anchors { "." initial-key 257 3 8 "..."; };`).
* **Attacker (`172.16.2.100`)**: The Phase 2 libpcap C++ interceptor binary and core-router diversion route are reused **completely unchanged**.

---

## 2. Verification of the Signed Hierarchy (Section 3.2)

Before mounting the attack, the health of the DNSSEC hierarchy was verified with no interceptor in the path:

### 2.1 `dig +dnssec example.com.`
* **Authenticated Data (`ad`) Flag**: Present in the header flags: `flags: qr rd ra ad;`.
* **Status**: `NOERROR`.
* **Answer Section**:
  ```text
  example.com.   600   IN   A       172.16.1.20
  example.com.   600   IN   RRSIG   A 8 2 600 20261118... 20739 example.com. ...
  ```
  *(See full log in `phase3/evidence/dnssec-verify.log`)*

### 2.2 Full Chain Validation via `delv`
Running `delv -a /etc/bind/root.key example.com.` from the client validates the full cryptographic chain from the Root KSK down to the leaf record:
```text
; fully validated
example.com.   600   IN   A       172.16.1.20
example.com.   600   IN   RRSIG   A 8 2 600 ...
```
*(See full log in `phase3/evidence/delv-chain.log`)*

---

## 3. Re-running the Phase 2 Attack under DNSSEC (Section 3.3 & 3.4)

With the core-router diverting resolver reply traffic to the attacker running in `--forge` mode:

1. Resolver cache was flushed (`rndc flush`).
2. Client issued `dig example.com.`.
3. Client issued `curl http://example.com`.
4. Client issued `dig www.example.com.`.

### 3.1 Observed Results
* **Resolution**:
  ```text
  ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 46759
  ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
  ```
  The resolver returns **`SERVFAIL`** with **0 answers**.
* **Client Fetch**:
  ```text
  curl: (6) Could not resolve host: example.com (DNS server returned general failure)
  ```
  The client connection fails immediately. The rogue website (`172.16.1.30`) is **never reached**.
* **Unaffected Lookup**:
  `dig +dnssec www.example.com.` resolves successfully to `172.16.1.20` with `status: NOERROR` and `flags: qr rd ra ad;`.

---

## 4. Deep-Dive Answers to Section 3.4 Report Questions

### Question 1: Resolver Behavior & Comparison with Phase 2
> *What does the resolver do with the forged response and what does the client’s fetch return? How does this differ from Phase 2, and what specifically does the resolver check to produce that outcome?*

* **In Phase 2 (Plain DNS)**:
  * The resolver had no way to authenticate the integrity of DNS responses. It only matched the 16-bit Transaction ID (`TXID`), destination UDP port, and query tuple `(qname, qtype)`.
  * Because the on-path attacker intercepted the authentic reply and immediately injected an unsigned forged reply with the correct TXID and port, the resolver accepted it first, admitted `example.com. A 172.16.1.30` into its cache, and returned `NOERROR` to the client. The client subsequently retrieved the defacement page.

* **In Phase 3 (DNSSEC Validated)**:
  * During iterative resolution, the resolver follows the delegation chain:
    1. It validates `com.`'s `DS` record in the root zone against the Root KSK trust anchor.
    2. It validates `example.com.`'s `DS` record in the `com.` zone against `com.`'s ZSK.
    3. The existence of `example.com.`'s DS record cryptographically proves that `example.com.` is a **signed zone**.
  * When the attacker's forged packet arrives (`example.com. A 172.16.1.30`), the resolver evaluates its DNSSEC validity:
    1. **Signature Presence**: It checks for an `RRSIG` record covering the `A` record. The forged packet contains no `RRSIG`.
    2. **Cryptographic Verification**: Even if an attacker attempted to forge an RRSIG, without the private ZSK of `example.com.`, any generated signature would fail cryptographic verification against the authentic `DNSKEY` published by `example.com.` (which itself is authenticated by the parent's DS record).
  * Finding no valid signature for a secured domain, BIND marks the response as **`BOGUS`**.
  * The resolver immediately drops the forged packet and refuses to admit it into the cache (confirmed by `named_dump.db`).
  * Because no authentic validated response is obtained before timeout, the resolver returns **`SERVFAIL`** to the client.
  * The client's HTTP client (`curl`) cannot resolve the host and safely aborts.

---

### Question 2: Wire Inspection vs Phase 1 & Privacy Properties
> *Compare the attacked exchange on the wire with your Phase 1 capture. What can the on-path attacker still read? What does DNSSEC therefore protect, and what does it not?*

* **Wire Comparison**:
  * In Phase 1, packets were compact (70–150 bytes), containing only plaintext questions and answers.
  * In Phase 3, message sizes increase substantially (300–1000+ bytes) to accommodate `DNSKEY`, `RRSIG`, and `DS` records. Multiple additional iterative queries are exchanged to fetch DNSKEY sets.
* **What the On-Path Attacker Can Still Read**:
  * **Plaintext Query Names**: The attacker sees every domain and subdomain being looked up (`example.com`, `www.example.com`).
  * **Network Metadata**: Source/destination IP addresses (`172.16.2.10`, `172.16.3.30`), UDP ports, and timestamps.
  * **Record Data**: All returned IP addresses, TTLs, and public keys remain completely readable in the clear.
* **What DNSSEC Protects**:
  * **Data Integrity**: Guarantees records were not altered or injected in transit.
  * **Origin Authenticity**: Cryptographically authenticates that the records originated from the legitimate zone holder.
  * **Authenticated Denial of Existence**: Proves whether a domain or RRset genuinely does not exist (via NSEC/NSEC3).
* **What DNSSEC DOES NOT Protect**:
  * **Confidentiality / Privacy**: DNSSEC is **authentication, not encryption**. It does not hide query names or browsing activity from eavesdroppers. (Confidentiality requires transport encryption such as DNS-over-TLS / DoT or DNS-over-HTTPS / DoH).
  * **Availability / DoS Resistance**: An on-path attacker can still drop packets or inject garbage to trigger `SERVFAIL`, causing denial of service.

---

### Question 3: Algorithm Choice, Trade-offs & Private Key Policy
> *State your signing-algorithm choice and its trade-offs, and whether any private key belongs in the submitted repository.*

* **Signing Algorithm**: **RSASHA256 (Algorithm 8)**
  * Key parameters: 2048-bit KSK (Key Signing Key) and 1024-bit ZSK (Zone Signing Key).
* **Trade-offs**:
  * **Advantages of RSASHA256**:
    * Broadest backward compatibility across legacy resolvers, validator implementations, and hardware security modules (HSMs).
    * Very fast signature verification (RSA with public exponent $e=65537$ requires only 17 modular multiplications).
  * **Disadvantages of RSASHA256**:
    * Large key and signature sizes (2048-bit key produces 256-byte signatures).
    * DNS responses with DNSKEY RRsets easily reach ~950–1000 bytes, nearing the standard 1232-byte UDP buffer threshold and increasing the risk of IP fragmentation.
  * **Comparison with Modern Alternatives (e.g. ECDSAP256SHA256 / Alg 13)**:
    * Algorithm 13 provides equivalent 128-bit security with only 256-bit keys and 64-byte signatures, drastically reducing packet sizes and preventing UDP fragmentation attacks.
* **Private Key Repository Policy**:
  * **Under NO circumstances do private keys (`.private`) belong in a production or public repository.** Leaking private keys allows adversaries to forge valid signatures, completely destroying the security of the DNSSEC zone.
  * In this academic submission, as required by git hygiene guidelines:
    * Our `scripts/sign-zones.sh` script automatically generates keys and signs zones on demand.
    * Only configurations, templates, and scripts are tracked in git; generated artifacts are built reproducibly from source.

---

## 5. Deliverables Summary

| Deliverable | Location | Description |
| :--- | :--- | :--- |
| **Zone Signing Script** | `phase3/scripts/sign-zones.sh` | Generates keys, chains DS records, signs zones with RSASHA256, and extracts root trust anchor. |
| **Signed Zones** | `phase3/bind/{root,tld,domain}/*.signed` | Fully signed zone files with NSEC and RRSIGs. |
| **Delegation Chain** | `phase3/bind/{root,tld}/db.*` | DS records included in parent zones (`com` in `.`, `example.com` in `com`). |
| **Resolver Trust Anchor** | `phase3/bind/resolver/root.key` | Root KSK trust anchor in BIND `trust-anchors` format. |
| **Healthy Signed Evidence** | `phase3/evidence/dnssec-verify.log`, `delv-chain.log` | `dig +dnssec` showing `ad` flag and `delv` showing `; fully validated`. |
| **Re-run Attack Evidence** | `phase3/evidence/attack-resolution.log`, `attack-fetch.log` | `dig` returning `SERVFAIL` and `curl` failing to resolve host. |
| **Attack Packet Capture** | `phase3/evidence/attack.pcap` | Full pcap showing intercepted genuine packet and rejected forged packet. |
| **Annotated Capture Trace** | `phase3/evidence/attack-annotated.txt` | Detailed frame-by-frame walkthrough. |
| **Unaffected Domain Log** | `phase3/evidence/unaffected-lookup.log` | `www.example.com` resolving to `172.16.1.20` with `ad` flag. |
