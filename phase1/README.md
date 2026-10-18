# Phase 1: Plain DNS

This phase builds a small DNS system inside Docker.

The client asks the resolver for `example.com`. The resolver asks the root,
`.com`, and `example.com` DNS servers. The answer is `172.16.1.20`, which is
the real web server.

Run every command from the project root. Add `sudo` before `docker` if your
computer needs it.

## 1. Build the image

```bash
docker build -f phase1/docker/Dockerfile -t cs6008-phase1-lab phase1
```

## 2. Start Phase 1

```bash
docker compose -f phase1/compose.yml up -d --force-recreate
docker compose -f phase1/compose.yml ps
```

All eight containers should say `Up`.

## 3. Test DNS

```bash
docker compose -f phase1/compose.yml exec -T client dig example.com. </dev/null
docker compose -f phase1/compose.yml exec -T client dig www.example.com. </dev/null
```

Both names should return `172.16.1.20`.

## 4. Test the website

```bash
docker compose -f phase1/compose.yml exec -T client curl -i http://example.com </dev/null
```

The result should contain `Real Example.com`.

## 5. Test isolation

```bash
docker compose -f phase1/compose.yml exec -T client \
  dig @172.16.3.10 example.com. +time=2 +tries=1 </dev/null
```

This should fail with `network unreachable`. The client must use the resolver.

## 6. Check the resolver's route

```bash
docker compose -f phase1/compose.yml exec -T resolver \
  ip route get 172.16.3.10 </dev/null
```

The result should say `via 172.16.2.3`. This is the core router.

## 7. Repeat the DNS capture

First clear the resolver's cache:

```bash
docker compose -f phase1/compose.yml exec -T resolver rndc flush </dev/null
```

In one terminal, start the capture:

```bash
docker compose -f phase1/compose.yml exec core-router \
  tcpdump -i eth1 -nn -s0 -w /tmp/phase1-referral-chain.pcap port 53
```

In another terminal, run:

```bash
docker compose -f phase1/compose.yml exec -T client dig example.com. </dev/null
```

Press `Ctrl+C` in the capture terminal. Then copy the capture:

```bash
docker compose -f phase1/compose.yml cp \
  core-router:/tmp/phase1-referral-chain.pcap \
  phase1/evidence/referral-chain.pcap
```

The saved evidence is in `phase1/evidence/`.

## 8. Stop Phase 1

```bash
docker compose -f phase1/compose.yml down
```
