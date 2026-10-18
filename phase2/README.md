# Phase 2: On-Path Response Forgery (Cache Poisoning)

In this phase, an on-path attacker on the resolver subnet (`172.16.2.100`) intercepts DNS responses from authoritative servers destined for the resolver (`172.16.2.10`).

- When **Relay Mode** is active: all DNS traffic is forwarded transparently. The client resolves `example.com` to `172.16.1.20` (the legitimate web server).
- When **Forge Mode** is active: the interceptor identifies the authoritative answer for `example.com` from `domain-ns` (`172.16.3.30`), suppresses the genuine answer, and injects a forged `A` record pointing to `172.16.1.30` (`rogue-web`).
- All other lookups (e.g., `www.example.com`) continue to resolve genuinely to `172.16.1.20`.

---

## 1. Build the Lab Image

Run from the project root:

```bash
docker build -f phase2/docker/Dockerfile -t cs6008-phase2-lab phase2
```

---

## 2. Start the Environment

```bash
docker compose -f phase2/compose.yml up -d --force-recreate
docker compose -f phase2/compose.yml ps
```

All 10 containers should show status `Up`.

---

## 3. Enable Inbound Traffic Diversion on Core Router

Route inbound DNS traffic destined for the resolver (`172.16.2.10`) via the attacker (`172.16.2.100`):

```bash
docker compose -f phase2/compose.yml exec -T core-router /lab/scripts/divert-on.sh
```

---

## 4. Test 1: Verify Transparent Relay (Section 2.2)

1. Start the interceptor in **transparent relay mode**:
   ```bash
   docker compose -f phase2/compose.yml exec -T attacker /lab/scripts/start-relay.sh
   ```

2. Flush the resolver's cache:
   ```bash
   docker compose -f phase2/compose.yml exec -T resolver rndc flush
   ```

3. Query `example.com` from the client:
   ```bash
   docker compose -f phase2/compose.yml exec -T client dig example.com.
   docker compose -f phase2/compose.yml exec -T client curl -i http://example.com
   ```
   **Expected Result**:
   - `dig` returns `172.16.1.20`.
   - `curl` prints `Real Example.com` (`HTTP 200 OK`).

---

## 5. Test 2: Execute the Forgery Attack (Section 2.3)

1. Switch the interceptor to **forge mode**:
   ```bash
   docker compose -f phase2/compose.yml exec -T attacker /lab/scripts/start-forge.sh
   ```

2. Flush the resolver's cache:
   ```bash
   docker compose -f phase2/compose.yml exec -T resolver rndc flush
   ```

3. Query `example.com` and fetch the website:
   ```bash
   docker compose -f phase2/compose.yml exec -T client dig example.com.
   docker compose -f phase2/compose.yml exec -T client curl -i http://example.com
   ```
   **Expected Result**:
   - `dig` returns `172.16.1.30`!
   - `curl` prints `Rogue Example.com` (`You have been redirected to the rogue server at 172.16.1.30!`).
   - The resolver's cache is now poisoned with the rogue IP.

4. Verify that non-target names remain untouched:
   ```bash
   docker compose -f phase2/compose.yml exec -T client dig www.example.com.
   ```
   **Expected Result**:
   - `www.example.com` still resolves to `172.16.1.20`.

5. View the attacker interceptor logs:
   ```bash
   docker compose -f phase2/compose.yml exec -T attacker cat /lab/attacker/interceptor.log
   ```

---

## 6. Teardown

```bash
docker compose -f phase2/compose.yml down
```

