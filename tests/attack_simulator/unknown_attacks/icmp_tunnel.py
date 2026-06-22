"""ICMP tunnel payload generator.

Protocol fingerprint:
  - Large ICMP echo request/reply packets (> 1000 bytes total)
  - TCP-like headers embedded inside the ICMP data payload area
  - ICMP type 8 (echo request) carrying non-echo data
  - High-entropy payloads wrapped in IP+ICMP headers

Why not in 44-class training set:
  The training datasets do not include ICMP protocol traffic at all.
  ICMP tunneling is a well-known data exfiltration technique where
  attackers embed TCP streams inside ICMP payloads to bypass
  firewalls that allow ping but block direct TCP.
"""

import os
import random
import struct

from . import register_attack

# ICMP types
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

# IP protocol numbers
IPPROTO_ICMP = 1
IPPROTO_TCP = 6


def _checksum(data: bytes) -> int:
    """Compute 16-bit one's complement checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_ipv4_header(
    src_ip: bytes, dst_ip: bytes,
    payload_len: int, protocol: int = IPPROTO_ICMP,
    ttl: int = 64,
) -> bytes:
    """Build a minimal IPv4 header (20 bytes)."""
    version_ihl = 0x45  # version 4, IHL 5
    dscp_ecn = 0x00
    total_length = 20 + payload_len
    ident = random.randint(0, 65535)
    flags_frag = 0x4000  # DF flag set
    header_checksum = 0  # computed later
    proto = protocol

    header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        ident,
        flags_frag,
        ttl,
        proto,
        header_checksum,  # placeholder
        src_ip,
        dst_ip,
    )
    # Compute checksum over IP header only
    csum = _checksum(header)
    header = (
        header[:10]
        + struct.pack(">H", csum)
        + header[12:]
    )
    return header


def _build_icmp_echo(icmp_type: int, code: int, identifier: int,
                     seq: int, payload: bytes) -> bytes:
    """Build an ICMP echo request/reply packet."""
    header = struct.pack(">BBHHH", icmp_type, code, 0, identifier, seq)
    csum = _checksum(header + payload)
    header = struct.pack(">BBHHH", icmp_type, code, csum, identifier, seq)
    return header + payload


def _build_fake_tcp_segment(src_port: int, dst_port: int,
                            seq_num: int, ack_num: int,
                            payload: bytes) -> bytes:
    """Build a fake TCP header followed by payload data.

    This simulates TCP data being tunnelled inside ICMP.
    """
    data_offset_reserved = (5 << 4)  # data offset = 5 words (20 bytes)
    flags = 0x18  # PSH + ACK
    window = 65535
    urgent = 0

    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset_reserved,
        flags,
        window,
        0,   # checksum placeholder
        urgent,
    )
    return tcp_header + payload


@register_attack("icmp_tunnel")
def generate_icmp_tunnel(count: int = 1) -> list[bytes]:
    """Generate ICMP tunnel payload(s).

    Each payload wraps a large ICMP echo request containing a
    TCP-like segment inside the payload — the classic pattern of
    an ICMP tunnel used for data exfiltration or C2.

    Returns:
        List of bytes payloads, each 500-1500 bytes.
    """
    payloads = []
    for i in range(count):
        # Source and destination IPs
        src = bytes(random.randint(10, 192) for _ in range(4))
        dst = bytes(random.randint(10, 192) for _ in range(4))

        # TCP segment tunnelled inside ICMP
        src_port = random.randint(49152, 65535)
        dst_port = random.randint(1, 65535)
        seq = random.randint(0, 2 ** 32 - 1)
        ack = random.randint(0, 2 ** 32 - 1)

        # Payload mimicking exfiltrated data
        tunnel_payload_size = random.randint(200, 1000)
        tunnel_payload = os.urandom(tunnel_payload_size)

        tcp_seg = _build_fake_tcp_segment(
            src_port, dst_port, seq, ack, tunnel_payload
        )

        # ICMP header + tunnelled data
        icmp_id = random.randint(0, 65535)
        icmp_seq = i + 1
        icmp_pkt = _build_icmp_echo(
            ICMP_ECHO_REQUEST, 0, icmp_id, icmp_seq, tcp_seg
        )

        # IP header wrapping ICMP
        ip_pkt = _build_ipv4_header(src, dst, len(icmp_pkt), IPPROTO_ICMP)

        payloads.append(ip_pkt + icmp_pkt)

    return payloads
