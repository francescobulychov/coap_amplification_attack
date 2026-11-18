"""Raw IPv4/UDP sender with a spoofable source address.

Pure Python, no scapy. Uses a raw socket with the kernel's implicit IP_HDRINCL
(IPPROTO_RAW) so we supply the full IP header and can set any source address.
Requires CAP_NET_RAW (root inside the container). The UDP checksum is set to 0,
which is legal and common over IPv4 (RFC 768); Linux accepts it on receipt.

CONTAINMENT: this only ever sends to destinations you pass in, which in this
project are the lab reflector IPs on an isolated Docker bridge with no route to
the internet. Do not run it anywhere else.
"""
import socket
import struct


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_packet(src_ip, dst_ip, sport, dport, payload, ip_id=0):
    """Return raw IPv4+UDP+payload bytes with source IP = src_ip (may be spoofed)."""
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload  # checksum 0

    total_len = 20 + udp_len
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,            # version 4, IHL 5 (no options)
        0,                        # DSCP/ECN
        total_len,
        ip_id,
        0,                        # flags/fragment offset
        64,                       # TTL
        socket.IPPROTO_UDP,       # 17
        0,                        # checksum (filled below)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + udp


class RawSender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.ip_bytes = 0
        self.udp_payload_bytes = 0
        self.packets = 0

    def send(self, src_ip, dst_ip, sport, dport, payload):
        pkt = build_packet(src_ip, dst_ip, sport, dport, payload, ip_id=self.packets & 0xFFFF)
        self.sock.sendto(pkt, (dst_ip, 0))
        self.packets += 1
        self.udp_payload_bytes += len(payload)
        self.ip_bytes += len(pkt)
