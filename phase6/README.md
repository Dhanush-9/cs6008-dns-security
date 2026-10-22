# Phase 6: Last-Mile Response Forgery

This phase keeps the signed DNSSEC hierarchy and the validating resolver from
Phase 3. The only thing that changes is where the attacker sits. It is now
`172.16.1.100`, on the client's own subnet. A host route on `edge-router` sends
the resolver's replies to the client through the attacker, so the attacker can
rewrite the final answer. The client configuration is not touched and no ARP
spoofing is used.

Two clients show where DNSSEC's protection ends:

- **Client A** is the normal system stub used by `curl`. It trusts any reply
  that looks like it came from its resolver, so the forged answer works.
- **Client B** is `delv`, which checks the DNSSEC proof itself using its own
  copy of the root key, so the same forged answer fails.

Run every command from the project root. Add `sudo` before `docker` if your
computer needs it. Keep `</dev/null` on the commands so Docker does not wait
for terminal input.

## 1. Build and start Phase 6

```bash
docker build -f phase6/docker/Dockerfile -t cs6008-phase6-lab phase6 </dev/null
./phase6/scripts/run-lab.sh </dev/null
docker compose -f phase6/compose.yml ps </dev/null
```

All ten containers should say `Up`. The signing script creates a fresh chain of
trust and mounts the same public root key into the resolver and the client.

## 2. Record the clean baseline

```bash
docker compose -f phase6/compose.yml exec -T client \
  dig +dnssec example.com. </dev/null \
  | tee phase6/evidence/clean-dig.log

docker compose -f phase6/compose.yml exec -T client \
  delv @172.16.2.10 -a /etc/bind/root.key example.com. A </dev/null \
  | tee phase6/evidence/clean-delv.log
```

Expected: `dig` returns `172.16.1.20` with an `RRSIG` and the `ad` flag. `delv`
prints `fully validated`.

## 3. Test transparent relay

Start the interceptor in relay mode, then turn on diversion:

```bash
docker compose -f phase6/compose.yml exec -T attacker \
  /lab/scripts/start-relay.sh </dev/null

docker compose -f phase6/compose.yml exec -T edge-router \
  /lab/scripts/divert-on.sh </dev/null

docker compose -f phase6/compose.yml exec -T edge-router \
  ip route get 172.16.1.10 </dev/null
```

The route should say `via 172.16.1.100`. Now test the result:

```bash
docker compose -f phase6/compose.yml exec -T client \
  dig example.com. </dev/null \
  | tee phase6/evidence/relay-dig.log

docker compose -f phase6/compose.yml exec -T client \
  curl -4 --noproxy '*' -sS --connect-timeout 5 \
  http://example.com/ </dev/null 2>&1 \
  | tee phase6/evidence/relay-curl.log
```

Expected: `dig` returns `172.16.1.20` and `curl` prints `Real Example.com`.

## 4. Attack Client A (the normal stub)

Switch the same interceptor to forge mode:

```bash
docker compose -f phase6/compose.yml exec -T attacker \
  /lab/scripts/start-forge.sh </dev/null
```

Start a capture, then run the lookup and web fetch:

```bash
docker compose -f phase6/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/client-a.pcap \
  'udp port 53 and host 172.16.1.10' </dev/null

docker compose -f phase6/compose.yml exec -T client \
  dig example.com. </dev/null \
  | tee phase6/evidence/client-a-dig.log

docker compose -f phase6/compose.yml exec -T client \
  curl -4 --noproxy '*' -sS --connect-timeout 5 \
  http://example.com/ </dev/null 2>&1 \
  | tee phase6/evidence/client-a-curl.log
```

Expected: `dig` returns `172.16.1.30` and `curl` prints `Rogue Example.com`.
The resolver itself was not poisoned; only its final reply to the stub was
replaced.

Stop and copy the capture:

```bash
docker compose -f phase6/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase6/compose.yml cp \
  attacker:/tmp/client-a.pcap phase6/evidence/client-a.pcap </dev/null
```

## 5. Attack Client B (local DNSSEC validation)

Start a new capture, then run `delv` with the root key:

```bash
docker compose -f phase6/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/client-b.pcap \
  'udp port 53 and host 172.16.1.10' </dev/null

docker compose -f phase6/compose.yml exec -T client \
  delv @172.16.2.10 -a /etc/bind/root.key example.com. A </dev/null 2>&1 \
  | tee phase6/evidence/client-b-delv.log
```

Expected: `delv` rejects the answer with a DNSSEC validation error (for example
`insecurity proof failed` or `broken trust`). It does not accept `172.16.1.30`,
because it checks the answer against its own root trust anchor.

Stop and copy the capture, then save the interceptor log:

```bash
docker compose -f phase6/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase6/compose.yml cp \
  attacker:/tmp/client-b.pcap phase6/evidence/client-b.pcap </dev/null

docker compose -f phase6/compose.yml exec -T attacker \
  cat /lab/attacker/interceptor.log </dev/null \
  | tee phase6/evidence/interceptor.log
```

## 6. Check the evidence

```text
clean-dig.log
clean-delv.log
relay-dig.log
relay-curl.log
client-a-dig.log
client-a-curl.log
client-a.pcap
client-b-delv.log
client-b.pcap
interceptor.log
```

Check that both captures contain packets:

```bash
capinfos phase6/evidence/client-a.pcap \
  phase6/evidence/client-b.pcap </dev/null
```

## 7. Stop Phase 6

```bash
docker compose -f phase6/compose.yml exec -T edge-router \
  /lab/scripts/divert-off.sh </dev/null
docker compose -f phase6/compose.yml down --remove-orphans </dev/null
```

DNSSEC proves that DNS data is genuine, but a validating resolver does not make
its plain link to a non-validating stub safe. Client A trusts the forged reply,
while Client B checks the signatures itself and rejects it. Phase 7 protects
this last mile with an encrypted, authenticated transport.