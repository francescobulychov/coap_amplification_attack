# CoAP Amplification Testbed

A small, self-contained lab for measuring CoAP (RFC 7252) reflection/amplification
attacks and, later, their mitigations. Built for DTU 34371 Communication Network
Security. Everything runs in Docker containers on one host — **no traffic ever
leaves the isolated bridge** (`--internal`, no route to the internet).

It reproduces the attacks catalogued in
`draft-irtf-t2trg-amplification-attacks-05` and the `/.well-known/core`
reflection baseline from Oliveira et al. (2020), and reports the amplification
factor at both the UDP-payload and IPv4-packet layers (the draft requires you to
state the layer).

## Ethics / containment

- The Docker network is `internal: true` → **no gateway, no internet route**.
- All spoofed traffic stays between `attacker`, `reflector_*`, and `victim`.
- This is the "closed, instructor-approved lab" the project proposal commits to.
- Do not run the attacker against anything outside this lab. It forges source IPs.

## Requirements

- Docker (tested with engine 29.x). No docker-compose needed — `run.sh` uses the
  plain `docker` CLI. (`docker-compose.yml` is provided for convenience on hosts
  that have Compose.)
- Host sysctl `net.ipv4.conf.all.rp_filter=0` is NOT required (spoofing happens
  inside one L2 subnet), but leave it at 0 if you extend to routed topologies.

## Components

| File | Role |
|------|------|
| `reflector.py` | Unsecured ("NoSec") aiocoap server: `/quote` (size = `QUOTE_SIZE`), `/temperature`, `/obs` (observable, `OBS_COUNT`×`OBS_SIZE`), auto `/.well-known/core`. Joins the All-CoAP-Nodes group for multicast. |
| `attacker.py` | Pure-Python raw-socket spoofer. Sends CoAP with `src = victim`. Modes: `discovery`, `simple`, `observe`, `multicast`. Fresh Message ID + token per packet (else the server deduplicates). |
| `victim.py` | Passive UDP sink. Counts packets/bytes, never replies. `SIGHUP` resets counters. |
| `coap.py` | Hand-written CoAP encoder/decoder (auditable bytes). |
| `rawsend.py` | Raw IPv4/UDP builder with spoofable source address. |
| `compute_af.py` | Amplification factor at UDP and IP layers. |
| `run.sh` | Orchestrator (build / up / attack / af / down). |

## Quick start

```bash
./run.sh up 5                      # build + start victim, 5 reflectors, attacker
./run.sh attack simple  --count 1  ; sleep 2  ; ./run.sh af
./run.sh attack discovery          ; sleep 2  ; ./run.sh af
./run.sh attack observe --count 1  ; sleep 12 ; ./run.sh af   # wait for the stream
./run.sh attack multicast --path quote --count 1 ; sleep 3 ; ./run.sh af
./run.sh down
```

Tunables (env on `up`): `QUOTE_SIZE`, `OBS_COUNT`, `OBS_SIZE`, `OBS_INTERVAL`.
Example: `QUOTE_SIZE=1500 OBS_COUNT=200 ./run.sh up 10`.

## How each mode maps to the draft

| Mode | Draft section | Mechanism | Factor |
|------|---------------|-----------|--------|
| `discovery` | Oliveira baseline | spoofed GET `/.well-known/core` | c |
| `simple` | §2.1 | spoofed GET of a large resource | c |
| `observe` | §2.2 | one spoofed Observe registration → stream of notifications | c·n |
| `multicast` | §2.3 | one spoofed GET to `224.0.1.187` → m servers answer | c·m |

## Measured results (1000-byte quote, OBS_COUNT=50, 5 reflectors)

| Mode | attacker→ | victim← | AF (UDP) | AF (IP) | packet gain |
|------|-----------|---------|----------|---------|-------------|
| discovery | 25 B | 151 B | 6.0× | 3.4× | 1× |
| simple | 14 B | 1009 B | 72× | 24.7× | 1× |
| observe | 13 B | 10 760 B / 51 pkt | 828× | 297× | 51× |
| multicast /quote | 14 B | 5045 B / 5 pkt | 360× | 123× | 5× (=m) |

Observations for the report:
- **The amplification factor depends on the layer.** UDP-payload factors are
  always higher than IP-packet factors (the IP+UDP 28-byte header is fixed
  overhead on both sides). Always state which layer.
- **Observe (c·n) is the worst single-server attack**: one 13-byte request → 10 KB.
- **Multicast gives c·m from a single packet**: packet gain equals the number of
  responders exactly; byte factor scales with the resource size too.
- **Deduplication matters**: an attacker reusing Message IDs from the same
  (spoofed) source is silenced by RFC 7252 §4.5 dedup. Varying the Message ID is
  part of a working attack — and NOT varying it is a (weak) accidental mitigation.

## Measurement notes

- `victim.py` counts received UDP payload bytes; IP-layer bytes = payload + 28 ×
  packets (no IP options, no fragmentation in this lab — verify with tcpdump if
  you change MTUs).
- Counters are cumulative; `run.sh attack` sends `SIGHUP` to zero them before
  each run (do **not** restart the victim container — that disrupts the neighbor
  table and drops the reflected replies).

## Gotchas discovered while building this (document these in your report)

1. **IPv6 bind** — aiocoap's default `::` bind fails on an IPv4-only internal
   network; bind `0.0.0.0`.
2. **Message-ID dedup** — see above; the single most important correctness bug.
3. **Victim restart breaks delivery** — reset counters by signal, not restart.
4. **IP collisions** — reflectors auto-assign from the low subnet; keep static
   victim/attacker IPs high (`.250`/`.251`).
5. **Multicast needs a route** — raw sockets can't send to `224.0.1.187` without
   `ip route add 224.0.0.0/4 dev eth0` (added automatically in `run.sh up`).

## Next step: the hardened setup

Not yet implemented. Planned mitigations to add as a second server profile and
measure the same table against:
- **Echo option (RFC 9175)** — reachability check; kills NoSec spoofing for unicast.
- **DTLS / OSCORE** — address validation via the security association.
- **Block2 slicing (RFC 7959)** — cap response size → cap c.
- **Response rate limiting (RFC 7252 §4.7)** — cap notifications/s, bound c·n.
- **Refusing/limiting multicast** (RFC 7252 §11.3) and `pmax` limits for Observe.
