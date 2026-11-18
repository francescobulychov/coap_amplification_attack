"""Compute the amplification factor from the attacker and victim counters.

AF is reported at two layers (draft-irtf-t2trg-amplification-attacks requires
stating the layer): UDP payload and whole IPv4 packet. IP-layer bytes assume no
IP fragmentation and no IP options (true in this lab), i.e. +28 bytes/packet.
"""
import json
import sys


def load(p):
    with open(p) as f:
        return json.load(f)


def main():
    a = load(sys.argv[1] if len(sys.argv) > 1 else "/results/attacker.json")
    v = load(sys.argv[2] if len(sys.argv) > 2 else "/results/victim.json")

    def ratio(n, d):
        return round(n / d, 3) if d else float("inf")

    print("=" * 56)
    print("mode:", a.get("mode"), " reflectors hit:", len(a.get("targets", [])))
    print("-" * 56)
    print("attacker sent : %6d pkt  %8d B (udp)  %8d B (ip)"
          % (a["packets"], a["udp_payload_bytes"], a["ip_bytes"]))
    print("victim recv   : %6d pkt  %8d B (udp)  %8d B (ip)"
          % (v["packets"], v["udp_payload_bytes"], v["ip_bytes"]))
    print("-" * 56)
    print("packet gain              : %.3f x" % ratio(v["packets"], a["packets"]))
    print("amplification (UDP layer): %.3f x" % ratio(v["udp_payload_bytes"], a["udp_payload_bytes"]))
    print("amplification (IP  layer): %.3f x" % ratio(v["ip_bytes"], a["ip_bytes"]))
    print("=" * 56)


if __name__ == "__main__":
    main()
