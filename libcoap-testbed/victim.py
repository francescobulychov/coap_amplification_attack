"""Passive victim: counts bytes/packets the reflectors reflect at it.

Binds the UDP port the spoofed requests claim as their source port, receives
whatever the reflectors send, and NEVER replies (a real DDoS victim is just a
flooded address). Writes running counters to /results/victim.json so the
amplification factor can be computed without host-side capture tools.
"""
import json
import os
import signal
import socket
import time

PORT = int(os.environ.get("VICTIM_PORT", "5683"))
OUT = os.environ.get("VICTIM_OUT", "/results/victim.json")


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    s.bind(("0.0.0.0", PORT))
    udp_bytes = 0
    packets = 0
    first = None
    last = None

    def dump(*_):
        data = {
            "udp_payload_bytes": udp_bytes,
            "packets": packets,
            # IP layer = UDP payload + UDP(8) + IPv4(20) header per packet
            "ip_bytes": udp_bytes + 28 * packets,
            "first_ts": first,
            "last_ts": last,
        }
        with open(OUT, "w") as f:
            json.dump(data, f)
        print("victim:", data, flush=True)

    def reset(*_):
        nonlocal udp_bytes, packets, first, last
        udp_bytes = 0
        packets = 0
        first = None
        last = None
        dump()
        print("victim: counters reset", flush=True)

    signal.signal(signal.SIGTERM, lambda *a: (dump(), os._exit(0)))
    signal.signal(signal.SIGHUP, reset)  # reset counters without restarting (keeps MAC/ARP)
    print("victim listening udp/%d -> %s" % (PORT, OUT), flush=True)
    s.settimeout(1.0)
    last_dump = 0.0
    while True:
        try:
            d, _ = s.recvfrom(65535)
        except socket.timeout:
            dump()
            last_dump = time.time()
            continue
        now = time.time()
        if first is None:
            first = now
        last = now
        udp_bytes += len(d)
        packets += 1
        # Dump on a time interval too: with an endless notification stream
        # (e.g. libcoap /time) the recv timeout never fires, so a timeout-only
        # dump would leave victim.json frozen at the last reset value.
        if now - last_dump >= 0.5:
            dump()
            last_dump = now


if __name__ == "__main__":
    main()
