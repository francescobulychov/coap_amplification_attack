# CoAP Amplification Attack — Testbeds & Study Material

Reproducible, **fully isolated** lab for measuring CoAP (RFC 7252)
reflection/amplification attacks and their mitigations. Built for the DTU course
**34371 Communication Network Security**.

The project reproduces the attacks catalogued in
[`draft-irtf-t2trg-amplification-attacks`](https://datatracker.ietf.org/doc/draft-irtf-t2trg-amplification-attacks/)
and the `/.well-known/core` reflection baseline from Oliveira et al. (2020), and
reports the **amplification factor** at both the UDP-payload and IPv4-packet
layers.

> ⚠️ **Ethics & safety.** Everything runs on an isolated Docker bridge with
> **no route to the internet** (`--internal`). The attacker forges source IP
> addresses; only ever run it inside this closed lab. This is defensive security
> research in an instructor-approved setting.

## Two independent implementations

The attacker, victim and measurement code are identical across both; only the
CoAP **server** differs. Reproducing the attack on two independent stacks shows
the amplification is a property of the **protocol**, not of one library.

| Folder | CoAP server | Notes |
|--------|-------------|-------|
| [`aiocoap-testbed/`](aiocoap-testbed/) | Python **aiocoap** | easy to script; finite observe stream |
| [`libcoap-testbed/`](libcoap-testbed/) | C **libcoap** (`coap-server-notls`) | ships DTLS/OSCORE + Block2 for the hardened server |

Each folder has its own README with full instructions and measured results.

## Quick start

```bash
cd aiocoap-testbed          # or libcoap-testbed
./run.sh up 5               # victim + 5 reflectors + attacker on an isolated net
./run.sh attack simple      ; sleep 2  ; ./run.sh af
./run.sh attack observe     ; sleep 10 ; ./run.sh af
./run.sh attack multicast   ; sleep 4  ; ./run.sh af
./run.sh watch              # live view of the flood (run in a second terminal)
./run.sh down
```
Requires only Docker.

## Attacks implemented (from the IETF draft)

| Mode | Mechanism | Amplification factor |
|------|-----------|----------------------|
| `discovery` | spoofed GET `/.well-known/core` (Oliveira baseline) | c |
| `simple` | spoofed GET of a large resource | c |
| `observe` | one spoofed Observe registration → stream of notifications | c·n |
| `multicast` | one spoofed GET to the All-CoAP-Nodes group → m servers reply | c·m |

Representative results (5 reflectors, 1000-byte resource): simple ≈ 72–84×,
multicast ≈ 360–420× (one packet in), observe hundreds× and growing with the
stream. See each testbed's README for the full tables and the implementation
gotchas discovered while building them.

## Repository layout

```
aiocoap-testbed/     CoAP amplification lab (aiocoap server)
libcoap-testbed/     same lab, libcoap server
docs/
  oral_exam_questions.md   exam-prep questions linking the project to the course
```

## Components (shared by both testbeds)

- `reflector.py` / `coap-server-notls` — the unsecured ("NoSec") CoAP server under study
- `attacker.py` — pure-Python raw-socket spoofer (forges the victim's source IP)
- `coap.py` — hand-written CoAP message encoder/decoder (auditable bytes)
- `rawsend.py` — raw IPv4/UDP builder
- `victim.py` — passive sink that counts reflected bytes/packets
- `compute_af.py` — amplification factor at UDP and IP layers
- `run.sh` — orchestrator (`up` / `attack` / `af` / `watch` / `down`)

## Status

Attack side complete and measured on both implementations. **Next step:** a
hardened server profile (Echo option RFC 9175, DTLS/OSCORE, Block2 slicing,
response rate limiting) to re-run the same attacks and show the factors collapse.
