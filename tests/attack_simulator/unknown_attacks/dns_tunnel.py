"""DNS tunnel payload generator.

Protocol fingerprint:
  - Overly-long DNS query names (300-500 bytes)
  - Base64-encoded data embedded in subdomain labels
  - TXT/AAAA record type queries
  - High-entropy character distribution in domain names

Why not in 44-class training set:
  Normal DNS traffic has short, human-meaningful domain names (< 253 chars
  total, with each label < 63 chars).  44-class datasets contain benign DNS
  but no long-domain tunneling traffic.
"""

import base64
import os
import random
import struct
import string

from . import register_attack

# DNS header flags
DNS_QR_QUERY = 0
DNS_OPCODE_QUERY = 0
DNS_RD = 1  # recursion desired


def _build_dns_header(txid: int) -> bytes:
    """Build a 12-byte DNS header."""
    flags = (DNS_QR_QUERY << 15) | (DNS_OPCODE_QUERY << 11) | (DNS_RD << 8)
    # Transaction ID | Flags | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
    return struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)


def _encode_dns_name(domain: bytes) -> bytes:
    """Encode a domain name into DNS wire format (label-length prefixed)."""
    result = bytearray()
    for label in domain.split(b"."):
        result.append(len(label))
        result.extend(label)
    result.append(0)  # terminating zero-length label
    return bytes(result)


def _encode_dns_name_long(labels: list[bytes]) -> bytes:
    """Encode a list of labels as a DNS name (each label <= 63 bytes)."""
    result = bytearray()
    for label in labels:
        if len(label) > 63:
            # Split into 63-byte chunks per DNS label limit
            for j in range(0, len(label), 63):
                chunk = label[j:j + 63]
                result.append(len(chunk))
                result.extend(chunk)
        else:
            result.append(len(label))
            result.extend(label)
    result.append(0)
    return bytes(result)


def _build_dns_question(name_encoded: bytes, qtype: int, qclass: int = 1) -> bytes:
    """Build a DNS question section."""
    return name_encoded + struct.pack(">HH", qtype, qclass)


# DNS record types used for tunneling
DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_TYPE_TXT = 16
DNS_TYPE_CNAME = 5
DNS_TYPE_NULL = 10


@register_attack("dns_tunnel")
def generate_dns_tunnel(count: int = 1) -> list[bytes]:
    """Generate DNS tunnel payload(s).

    Each payload contains a full DNS query packet with:
      - Long domain name (300+ bytes after encoding) carrying base64 data
      - TXT/AAAA/NULL record type (common tunnel types)
      - High-entropy encoded payload in subdomain labels

    Returns:
        List of bytes payloads, each 400-800 bytes.
    """
    payloads = []
    for i in range(count):
        # Generate random data to tunnel (simulating exfiltrated content)
        data_size = random.randint(150, 350)
        tunneled_data = os.urandom(data_size)

        # Base64-encode it (DNS tunnels often use base32/base64
        # to stay within alphanumeric domain-name constraints)
        encoded = base64.b64encode(tunneled_data).rstrip(b"=")

        # Build subdomain labels from encoded data
        labels = []
        remaining = encoded
        while remaining:
            # DNS label max is 63; pick a length that fills efficiently
            chunk_len = min(63, len(remaining))
            labels.append(remaining[:chunk_len])
            remaining = remaining[chunk_len:]

        # Prefix with a tunnel marker for recognisability
        tunnel_markers = [
            b"tun", b"data", b"dnscat", b"iodine",
            b"dns2tcp", b"exfil", b"beacon",
        ]
        labels.insert(0, random.choice(tunnel_markers))

        # Append a fake TLD
        tlds = [b"com", b"net", b"org", b"io", b"xyz"]
        labels.append(random.choice(tlds))

        # Build full DNS name
        dns_name = _encode_dns_name_long(labels)

        # Build the DNS question
        qtypes = [DNS_TYPE_TXT, DNS_TYPE_AAAA, DNS_TYPE_NULL, DNS_TYPE_CNAME]
        qtype = random.choice(qtypes)
        question = _build_dns_question(dns_name, qtype)

        # Build the full DNS packet
        txid = random.randint(0, 65535)
        header = _build_dns_header(txid)
        dns_packet = header + question

        payloads.append(dns_packet)

    return payloads
