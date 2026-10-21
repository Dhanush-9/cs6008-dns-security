# Phase 4: DNSSEC Downgrade Test

This phase tests whether removing DNSSEC records can make a signed zone look
unsigned.

- **Run A:** `com` contains the `example.com` DS record. The attack must fail.
- **Run B:** `com` is signed without the `example.com` DS record. The attack
  succeeds because the delegation is genuinely insecure.

Run every command from the project root. Add `sudo` before `docker` if your
computer needs it. Keep `</dev/null` on the commands; it prevents Docker
commands from waiting for terminal input.

## 1. Build the image

```bash
docker build -f phase4/docker/Dockerfile -t cs6008-phase4-lab phase4 </dev/null
```

## 2. Record the clean DNSSEC baseline

```bash
./phase4/scripts/run-clean.sh </dev/null 2>&1 | tee phase4/evidence/clean.log
```

Check `clean.log` for all three results:

- `status: NOERROR`
- the `ad` flag and an `RRSIG` record
- the real address `172.16.1.20`

## 3. Run A, then save its evidence

Run A creates the complete chain of trust, including the `example.com` DS in
`com`, and starts the stripping attack:

```bash
./phase4/scripts/run-a.sh </dev/null
```

Start the packet capture **before** flushing the cache:

```bash
docker compose -f phase4/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/run-a.pcap udp port 53 </dev/null
```

Flush the resolver cache. The RNDC key is generated inside the resolver at
`/etc/rndc.key`; it is intentionally not stored in `phase4/bind/resolver/`.

```bash
docker compose -f phase4/compose.yml exec -T resolver \
  rndc -k /etc/rndc.key -s 127.0.0.1 flush </dev/null
```

Now run the tests and save their output:

```bash
docker compose -f phase4/compose.yml exec -T client \
  dig +dnssec example.com. </dev/null \
  | tee phase4/evidence/run-a-dig.log

docker compose -f phase4/compose.yml exec -T client \
  curl -sS http://example.com </dev/null 2>&1 \
  | tee phase4/evidence/run-a-curl.log

docker compose -f phase4/compose.yml exec -T attacker \
  cat /lab/attacker/interceptor.log </dev/null \
  | tee phase4/evidence/run-a-interceptor.log
```

Expected result: `dig` returns `SERVFAIL`, `curl` cannot resolve the name, and
the interceptor log shows DS/DNSSEC stripping. The forged address must not be
accepted.

Stop and copy the Run A capture:

```bash
docker compose -f phase4/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase4/compose.yml cp \
  attacker:/tmp/run-a.pcap phase4/evidence/run-a.pcap </dev/null
```

Do not start Run B until these four Run A files have been saved.

## 4. Run B, then save its evidence

Run B signs `example.com` but deliberately leaves its DS out of the signed
`com` zone:

```bash
./phase4/scripts/run-b.sh </dev/null
```

Start a new capture, then flush the new resolver cache:

```bash
docker compose -f phase4/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/run-b.pcap udp port 53 </dev/null

docker compose -f phase4/compose.yml exec -T resolver \
  rndc -k /etc/rndc.key -s 127.0.0.1 flush </dev/null
```

Run the tests and save their output:

```bash
docker compose -f phase4/compose.yml exec -T client \
  dig +dnssec example.com. </dev/null \
  | tee phase4/evidence/run-b-dig.log

docker compose -f phase4/compose.yml exec -T client \
  curl -sS http://example.com </dev/null 2>&1 \
  | tee phase4/evidence/run-b-curl.log

docker compose -f phase4/compose.yml exec -T attacker \
  cat /lab/attacker/interceptor.log </dev/null \
  | tee phase4/evidence/run-b-interceptor.log
```

Expected result: `dig` returns `172.16.1.30` without the `ad` flag, `curl`
returns the rogue page, and the interceptor log shows an unsigned forged A
record.

Stop and copy the Run B capture:

```bash
docker compose -f phase4/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase4/compose.yml cp \
  attacker:/tmp/run-b.pcap phase4/evidence/run-b.pcap </dev/null
```

## 5. Check the evidence

The final evidence directory should contain:

```text
clean.log
run-a-dig.log
run-a-curl.log
run-a-interceptor.log
run-a.pcap
run-b-dig.log
run-b-curl.log
run-b-interceptor.log
run-b.pcap
```

Check that both captures contain packets:

```bash
capinfos phase4/evidence/run-a.pcap phase4/evidence/run-b.pcap </dev/null
```

The `Number of packets` must be greater than zero for both files.
Each capture must also show both the genuine `172.16.1.20` answer and the
attacker's forged `172.16.1.30` answer:

```bash
tcpdump -nn -r phase4/evidence/run-a.pcap udp port 53 </dev/null \
  | grep '172.16.1.'
tcpdump -nn -r phase4/evidence/run-b.pcap udp port 53 </dev/null \
  | grep '172.16.1.'
```

## 6. Stop Phase 4

```bash
docker compose -f phase4/compose.yml down --remove-orphans </dev/null
```

DNSSEC blocks Run A because an authenticated parent DS requires a valid signed
child answer. Run B succeeds because the signed parent itself proves that no DS
exists, so the resolver has no chain of trust to `example.com`.
