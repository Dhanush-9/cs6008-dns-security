# Phase 3: DNSSEC Chain of Trust & Defense Against Forgery

In this phase, we introduce a cryptographic **DNSSEC chain of trust** across all authoritative nameservers (`.` -> `com.` -> `example.com.`) signed with `RSASHA256` (Algorithm 8), and enable DNSSEC validation on the recursive resolver anchored at the Root KSK.

We then re-run the exact same Phase 2 on-path attack to demonstrate that DNSSEC validation detects the forged response as `BOGUS` and returns `SERVFAIL`, completely protecting the client.

---

## 1. Build the Lab Image

Run from the repository root:

```bash
docker build -f phase3/docker/Dockerfile -t cs6008-phase3-lab phase3
```

---

## 2. Sign Zones & Generate Trust Anchors (Automated)

Run the automated signing script. It generates KSK/ZSK pairs, chains DS records from children into parent zones, signs all three zones, and creates the resolver trust anchor:

```bash
./phase3/scripts/sign-zones.sh
```

---

## 3. Start the Environment

```bash
docker compose -f phase3/compose.yml up -d --force-recreate
docker compose -f phase3/compose.yml ps
```

All 10 containers should report status `Up`.

---

## 4. Verify the Healthy DNSSEC Hierarchy (Section 3.2)

Before mounting any attack, verify that the signed hierarchy resolves securely:

1. **Verify `ad` flag and `RRSIG` from client:**
   ```bash
   docker compose -f phase3/compose.yml exec -T client dig +dnssec example.com.
   ```
   **Expected Output**:
   - Header flags include `ad` (`flags: qr rd ra ad;`).
   - Answer section includes both `A` and `RRSIG` records.

2. **Verify full chain validation via `delv`:**
   ```bash
   docker compose -f phase3/compose.yml exec -T client delv -a /etc/bind/root.key example.com.
   ```
   **Expected Output**:
   - Prints `; fully validated`.

3. **Verify web fetch:**
   ```bash
   docker compose -f phase3/compose.yml exec -T client curl -si http://example.com
   ```
   **Expected Output**:
   - Returns `Real Example.com` (`HTTP 200 OK`).

---

## 5. Mount the Phase 2 Attack under DNSSEC (Section 3.3)

1. **Compile the interceptor binary inside the attacker container:**
   ```bash
   docker compose -f phase3/compose.yml exec -T attacker sh -c "cd /lab/attacker && make"
   ```

2. **Enable traffic diversion on core-router:**
   ```bash
   docker compose -f phase3/compose.yml exec -T core-router /lab/scripts/divert-on.sh
   ```

3. **Start the interceptor in `--forge` mode:**
   ```bash
   docker compose -f phase3/compose.yml exec -T attacker /lab/scripts/start-forge.sh
   ```

4. **Flush the resolver's cache:**
   ```bash
   docker compose -f phase3/compose.yml exec -T resolver rndc flush
   ```

5. **Execute lookup and fetch from client:**
   ```bash
   docker compose -f phase3/compose.yml exec -T client dig example.com.
   docker compose -f phase3/compose.yml exec -T client curl -si http://example.com
   ```
   **Expected Outcome**:
   - `dig` returns **`status: SERVFAIL`** with `ANSWER: 0`.
   - `curl` fails with `curl: (6) Could not resolve host: example.com`.
   - The forged record is rejected because it lacks a valid `RRSIG`.

6. **Verify unaffected non-target lookup:**
   ```bash
   docker compose -f phase3/compose.yml exec -T client dig +dnssec www.example.com.
   ```
   **Expected Outcome**:
   - `www.example.com` resolves with `status: NOERROR` and `flags: qr rd ra ad;` pointing to `172.16.1.20`.

7. **Verify resolver cache contains NO forged entries:**
   ```bash
   docker compose -f phase3/compose.yml exec -T resolver rndc dumpdb -cache
   docker compose -f phase3/compose.yml exec -T resolver grep -A 2 "example.com" /var/cache/bind/named_dump.db
   ```
   **Expected Outcome**:
   - No `172.16.1.30` in the cache dump!

---

## 6. Teardown

```bash
docker compose -f phase3/compose.yml down
```
