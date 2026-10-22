# Phase 5: DNSSEC Zone Walking

This phase shows that ordinary NSEC records can reveal every name in a signed
zone. It then changes only the denial mechanism to NSEC3, which keeps
authenticated denial but replaces readable next-name links with hashes.

Run every command from the project root. Add `sudo` before `docker` if your
computer needs it. Keep `</dev/null` on the commands so Docker does not wait
for terminal input.

The run scripts create `/etc/rndc.key` inside the resolver and flush its cache
after every restart. You do not need an `rndc.key` file in
`phase5/bind/resolver`.

## 1. Build the image

```bash
docker build -f phase5/docker/Dockerfile -t cs6008-phase5-lab phase5 </dev/null
```

## 2. Run A: walk the NSEC zone

Start the signed hierarchy with readable NSEC denial records:

```bash
./phase5/scripts/run-nsec.sh </dev/null
```

Verify that a missing name receives an authenticated denial:

```bash
docker compose -f phase5/compose.yml exec -T client \
  dig +dnssec missing.example.com. </dev/null \
  | tee phase5/evidence/nsec-denial.log
```

Expected: `NXDOMAIN`, the `ad` flag, and NSEC plus RRSIG records.

Start a capture on the attacker:

```bash
docker compose -f phase5/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/nsec-walk.pcap \
  'udp port 53 and host 172.16.3.30' </dev/null
```

Run the C++/libpcap walker:

```bash
docker compose -f phase5/compose.yml exec -T attacker \
  /lab/scripts/run-walker.sh </dev/null \
  | tee phase5/evidence/nsec-walk.log
```

The walker starts with only `example.com` and should recover:

```text
admin.example.com.
api.example.com.
dev.example.com.
domain-ns.example.com.
mail.example.com.
vpn.example.com.
www.example.com.
```

Including the already-known apex, the zone has eight owner names. The walk
should use eight queries, which is below the assignment limit of ten.

Stop and copy the capture:

```bash
docker compose -f phase5/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase5/compose.yml cp \
  attacker:/tmp/nsec-walk.pcap phase5/evidence/nsec-walk.pcap </dev/null
```

Save these files before moving to Run B.

## 3. Run B: replace NSEC with NSEC3

Re-sign the same zone with NSEC3 and recreate the containers:

```bash
./phase5/scripts/run-nsec3.sh </dev/null
```

Verify that authenticated denial still works:

```bash
docker compose -f phase5/compose.yml exec -T client \
  dig +dnssec missing.example.com. </dev/null \
  | tee phase5/evidence/nsec3-denial.log
```

Expected: `NXDOMAIN`, the `ad` flag, and NSEC3 plus RRSIG records.

Capture and run the same walker again:

```bash
docker compose -f phase5/compose.yml exec -d attacker \
  tcpdump -i eth0 -nn -s0 -w /tmp/nsec3-walk.pcap \
  'udp port 53 and host 172.16.3.30' </dev/null

docker compose -f phase5/compose.yml exec -T attacker \
  /lab/scripts/run-walker.sh </dev/null \
  | tee phase5/evidence/nsec3-walk.log
```

Expected: the walker reports NSEC3, stops after one query, and recovers zero
plaintext names.

Stop and copy the capture:

```bash
docker compose -f phase5/compose.yml exec -T attacker \
  pkill -INT tcpdump </dev/null
docker compose -f phase5/compose.yml cp \
  attacker:/tmp/nsec3-walk.pcap phase5/evidence/nsec3-walk.pcap </dev/null
```

## 4. Check the evidence

```text
nsec-denial.log
nsec-walk.log
nsec-walk.pcap
nsec3-denial.log
nsec3-walk.log
nsec3-walk.pcap
```

Check that both captures contain packets:

```bash
capinfos phase5/evidence/nsec-walk.pcap \
  phase5/evidence/nsec3-walk.pcap </dev/null
```

## 5. Stop Phase 5

```bash
docker compose -f phase5/compose.yml down --remove-orphans </dev/null
```

NSEC leaks the next real owner name, so following the chain reconstructs the
zone. NSEC3 publishes hashes instead, so the same procedure cannot directly
recover the names. Predictable names can still be tested with an offline
dictionary attack, and NSEC3 costs extra processing and operational complexity.
