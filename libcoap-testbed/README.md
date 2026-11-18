# CoAP Amplification Testbed — libcoap edition (testbed2)

Same lab as `../testbed`, but the reflector is **libcoap**'s C server
(`coap-server-notls`) instead of the Python `aiocoap` server. The attacker,
victim and measurement code are byte-for-byte the same, so the two testbeds are
**directly comparable** — any difference in the numbers is an implementation
difference, not a measurement difference. That comparison is itself a result for
the report: it shows the amplification is a property of the CoAP *protocol*, not
of one library.

Isolated `--internal` Docker bridge (`10.81.0.0/24`), no internet route. Runs
alongside testbed1 (different network/subnet/container names).

## Why a second implementation

- **Credibility**: reproducing the attack on two independent stacks (Python
  aiocoap + C libcoap) shows it isn't a quirk of one implementation.
- **Mitigations**: libcoap ships the strong DTLS/OSCORE stack
  (`coap-server-openssl`) and real Block2 handling (`-L`), so the *hardened*
  server for the second half of the project will be built here.

## Server: libcoap `coap-server-notls` (v4.3.1)

Started as:
```
coap-server-notls -A 0.0.0.0 -p 5683 -d 100 -g 224.0.1.187 -G eth0 -N
```
- `-d 100` — allow dynamic resource creation via PUT (we seed `/big`).
- `-g 224.0.1.187 -G eth0` — join the All-CoAP-Nodes group **on eth0** (the `-G`
  is required; `-g` alone does not actually join on the container interface).
- `-N` — Non-confirmable observe notifications.

Default resources (from `/.well-known/core`): `/` (banner), `/time`
(observable, notifies ~once per second), `/async`, `/example_data`. On `up` we
also PUT a `BIG_SIZE`-byte `/big` resource (default 1000 B) — which, as a bonus,
enlarges `/.well-known/core`, the draft's "grow /.well-known/core" trick.

## Attack → resource mapping (set automatically by run.sh)

| Mode | Resource | Draft § | Factor |
|------|----------|---------|--------|
| discovery | `/.well-known/core` | Oliveira baseline | c |
| simple | `/big` (seeded, 1000 B) | §2.1 | c |
| observe | `/time` (endless ~1 Hz stream) | §2.2 | c·n |
| multicast | `/big` via `224.0.1.187` | §2.3 | c·m |

## Quick start

```bash
./run.sh up 5
./run.sh attack simple    ; sleep 2  ; ./run.sh af
./run.sh attack discovery ; sleep 2  ; ./run.sh af
./run.sh attack observe   ; sleep 8  ; ./run.sh af     # /time streams ~1 notif/s
./run.sh attack multicast ; sleep 6  ; ./run.sh af     # Leisure can delay replies
./run.sh watch                                          # live view in another terminal
./run.sh down
```
Tune: `BIG_SIZE=1500 ./run.sh up 10`.

## Measured results (5 reflectors, /big = 1000 B)

| Mode | attacker→ | victim← | AF (UDP) | AF (IP) | packet gain |
|------|-----------|---------|----------|---------|-------------|
| discovery | 125 B / 5 pkt | 970 B / 5 pkt | 7.8× | 4.2× | 1× |
| simple | 60 B / 5 pkt | 5045 B / 5 pkt | 84× | 25.9× | 1× |
| observe (8 s) | 70 B / 5 pkt | 1400 B / 50 pkt | 20× | ~13× | 10× |
| multicast | 12 B / 1 pkt | 5045 B / 5 pkt | **420×** | 123× | 5× (=m) |

(discovery/simple send one request per reflector, so attacker packets = 5;
multicast sends **one** packet total — that's the c·m point.)

### testbed1 (aiocoap) vs testbed2 (libcoap), same conditions

| Mode | aiocoap AF (UDP) | libcoap AF (UDP) | note |
|------|------------------|------------------|------|
| discovery | 6.0× | 7.8× | libcoap `/.well-known/core` is larger |
| simple (1000 B) | 72× | 84× | different header/option overhead |
| multicast (c·m) | 360× | 420× | both scale with m; libcoap request is smaller |
| observe | 828× (finite 50×0.2 s) | rate ~1 Hz, grows with window | different notify cadence |

The factors are the same order of magnitude on both stacks — the amplification
is protocol-level.

## libcoap-specific gotchas discovered while building this (document them)

1. **Binary names are suffixed**: `coap-server-notls` / `-openssl` / `-gnutls`;
   there is no plain `coap-server`.
2. **Multicast join needs `-G eth0`** — `-g` alone silently fails to join on the
   container interface (`ip maddr show eth0` is the check).
3. **Observers are permanent** — libcoap `/time` streams forever, unlike the
   aiocoap resource that self-terminated after OBS_COUNT. Back-to-back observe
   runs therefore accumulate observers; restart the reflectors between observe
   measurements if you want a clean window. This also exposed a measurement bug
   (now fixed): the victim only wrote its counters on a 1 s recv *timeout*, which
   never happens under an endless stream — it now also dumps every 0.5 s.
4. **Multicast Leisure delay** — libcoap delays multicast responses by a random
   time (RFC 7252 §8.2, up to ~5 s). Use a longer wait before reading `af`.
5. **Multicast forwarding over the Docker bridge** can be flaky without an IGMP
   querier (bridge multicast snooping). If reflectors are joined (`ip maddr`) but
   responses don't arrive, the host bridge is dropping the group traffic; on your
   own host disable snooping (`echo 0 > /sys/class/net/<bridge>/bridge/multicast_snooping`,
   needs root) or add a querier. With `-G eth0` set, it works reliably here.

## Next: the hardened server

Build a second profile with `coap-server-openssl` to add **DTLS/OSCORE** address
validation and `-L` **Block2** slicing, plus response **rate limiting**, and
re-run this exact table to show the factors collapse. The **Echo option
(RFC 9175)** is the key NoSec-compatible mitigation to test for the unicast
attacks.
