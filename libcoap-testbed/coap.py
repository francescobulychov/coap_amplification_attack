"""Minimal CoAP (RFC 7252) message encoder/decoder.

Hand-written so the exact bytes on the wire are visible and auditable — useful
for a security report where you must justify every byte that enters the
amplification-factor numerator/denominator.
"""
import struct

# Message types (RFC 7252 section 4)
CON, NON, ACK, RST = 0, 1, 2, 3

# Codes: c.dd encoded as (class << 5) | detail
GET, POST, PUT, DELETE = 1, 2, 3, 4

# Option numbers (RFC 7252 Table 4 / RFC 7641)
OPT_OBSERVE = 6
OPT_URI_PATH = 11
OPT_URI_QUERY = 15


def _opt_header(delta, length):
    """Encode one option's delta/length nibbles plus any extended bytes."""
    def ext(n):
        if n < 13:
            return n, b""
        elif n < 269:
            return 13, struct.pack("!B", n - 13)
        else:
            return 14, struct.pack("!H", n - 269)
    dn, dext = ext(delta)
    ln, lext = ext(length)
    return struct.pack("!B", (dn << 4) | ln) + dext + lext


def encode(mtype, code, mid, token=b"", options=None, payload=b""):
    """Build a CoAP message. options = list of (number, value_bytes), any order."""
    options = options or []
    tkl = len(token)
    assert tkl <= 8, "token length 0-8"
    hdr = struct.pack("!BBH", (1 << 6) | (mtype << 4) | tkl, code, mid)
    out = hdr + token
    last = 0
    for num, val in sorted(options, key=lambda o: o[0]):
        out += _opt_header(num - last, len(val)) + val
        last = num
    if payload:
        out += b"\xff" + payload
    return out


def uri_path_options(path):
    """'/.well-known/core' -> [(11,b'.well-known'),(11,b'core')]"""
    segs = [s for s in path.strip("/").split("/") if s]
    return [(OPT_URI_PATH, s.encode()) for s in segs]


def decode_header(data):
    """Return (ver, type, tkl, code, mid). Enough to classify captured packets."""
    b0, code, mid = struct.unpack("!BBH", data[:4])
    return (b0 >> 6, (b0 >> 4) & 3, b0 & 0x0F, code, mid)
