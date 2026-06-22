"""DGA (Domain Generation Algorithm) payload generator.

Protocol fingerprint:
  - DNS queries for pseudo-random domain names
  - High ratio of consonants and digits in domain labels
  - No dictionary words — completely algorithmically generated
  - Very low Jaccard similarity to any legitimate domain corpus
  - Each domain is short-lived (single-use or time-seeded)

Why not in 44-class training set:
  Normal DNS queries in CIC-IDS datasets use real, human-readable
  domain names (e.g. google.com, facebook.com).  DGA domains are
  algorithmically generated strings like "aek39xqy8h.com" with
  no semantic meaning, resulting in a completely different byte
  entropy distribution.
"""

import hashlib
import random
import struct
import time

from . import register_attack

# Character sets used by real DGAs
DGA_CHARS_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
DGA_CHARS_MIXED = "abcdefghijklmnopqrstuvwxyz0123456789"
DGA_CHARS_HEX = "0123456789abcdef"
DGA_CHARS_CONSONANT_HEAVY = "bcdfghjklmnpqrstvwxyz0123456789"

TLDS = [b"com", b"net", b"org", b"info", b"biz", b"xyz", b"top", b"cc"]


def _generate_dga_label(seed: str, length: int, charset: str) -> bytes:
    """Generate a pseudo-random domain label using a hashed seed."""
    h = hashlib.sha256(seed.encode()).digest()
    label = bytearray()
    for i in range(length):
        idx = h[i % len(h)] % len(charset)
        label.append(ord(charset[idx]))
    return bytes(label)


def _generate_dga_domain(method: int, idx: int) -> bytes:
    """Generate one DGA domain using one of several algorithms.

    Different DGA families use different generation strategies:
      - GameOver Zeus: 128 chars from a-z + 0-9
      - Conficker: 8-12 chars from consonant-heavy set
      - Locky: hex-based with suffixes
      - Necurs: 7-18 chars mixed case simulation
    """
    if method == 0:
        # GameOver Zeus style: medium-length, full charset
        label = _generate_dga_label(
            f"goz-{idx}-{int(time.time() // 86400)}",
            random.randint(20, 64),
            DGA_CHARS_MIXED,
        )
    elif method == 1:
        # Conficker style: consonant-heavy, short labels
        label = _generate_dga_label(
            f"conf-{idx}",
            random.randint(12, 20),
            DGA_CHARS_CONSONANT_HEAVY,
        )
    elif method == 2:
        # Locky style: hex-based, numeric suffix
        label = _generate_dga_label(
            f"locky-{idx}",
            32,
            DGA_CHARS_HEX,
        )
        # append a random suffix
        suffix = f"{random.randint(0, 9999):04d}"
        label = label + suffix.encode()
    elif method == 3:
        # Necurs/Matsnu style: medium-length mixed, alternating patterns
        label = _generate_dga_label(
            f"necurs-{idx}",
            random.randint(12, 24),
            DGA_CHARS_LOWERCASE,
        )
    else:
        # Generic DGA: random length with consonant prefix
        prefix = _generate_dga_label(f"pre-{idx}", random.randint(3, 6), DGA_CHARS_CONSONANT_HEAVY)
        body = _generate_dga_label(f"body-{idx}", random.randint(4, 50), DGA_CHARS_MIXED)
        label = prefix + body

    tld = random.choice(TLDS)
    return label + b"." + tld


def _encode_dns_name(domain: bytes) -> bytes:
    """Encode domain name into DNS wire format."""
    result = bytearray()
    for label in domain.split(b"."):
        result.append(len(label))
        result.extend(label)
    result.append(0)
    return bytes(result)


def _build_dns_header(txid: int) -> bytes:
    """Build a 12-byte DNS query header."""
    flags = 0x0100  # standard query, recursion desired
    return struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)


def _build_dns_query(domain_name: bytes, qtype: int = 1) -> bytes:
    """Build a complete DNS query packet."""
    txid = random.randint(0, 65535)
    header = _build_dns_header(txid)
    name_enc = _encode_dns_name(domain_name)
    question = name_enc + struct.pack(">HH", qtype, 1)  # qtype A, qclass IN
    return header + question


@register_attack("dga_domains")
def generate_dga_domains(count: int = 1) -> list[bytes]:
    """Generate DGA domain query payload(s).

    Each payload wraps one or more DNS queries for algorithmically
    generated domains into a single byte stream.  This simulates
    what a botnet client would produce when trying to locate its
    C2 servers via DGA.

    Returns:
        List of bytes payloads, each 200-800 bytes.
    """
    payloads = []
    for i in range(count):
        parts = []

        # Generate multiple DGA domain queries in one stream
        num_queries = random.randint(5, 6)
        for j in range(num_queries):
            method = (i * num_queries + j) % 5
            idx = i * 100 + j
            domain = _generate_dga_domain(method, idx)
            dns_query = _build_dns_query(domain, qtype=1)  # A record query
            parts.append(dns_query)

        payloads.append(b"".join(parts))

    return payloads
