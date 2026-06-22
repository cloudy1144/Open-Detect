"""Byte-stream to 32x32 grayscale image helpers used before model inference."""

from __future__ import annotations

from datetime import datetime
import os
import re
from typing import Iterable

import numpy as np

from .flow_manager import FlowData

_IPV4_TEXT_RE = re.compile(
    rb"(?<![0-9\.])"
    rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    rb"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    rb"(?![0-9\.])"
)

_IPV4_TEXT_MASK = b"0.0.0.0"


def _mask_ip_header(packet: bytes) -> bytes:
    """Mask IPv4/IPv6 addresses inside packet headers if present."""
    def _mask_at_offset(data: bytearray, offset: int) -> bool:
        if len(data) < offset + 20:
            return False
        version = data[offset] >> 4
        if version == 4:
            ihl = (data[offset] & 0x0F) * 4
            if ihl >= 20 and len(data) >= offset + ihl:
                data[offset + 12: offset + 16] = b"\x00" * 4
                data[offset + 16: offset + 20] = b"\x00" * 4
                return True
        elif version == 6:
            if len(data) >= offset + 40:
                data[offset + 8: offset + 24] = b"\x00" * 16
                data[offset + 24: offset + 40] = b"\x00" * 16
                return True
        return False

    if len(packet) >= 20:
        mutable = bytearray(packet)
        if _mask_at_offset(mutable, 0):
            return bytes(mutable)

        # Common link-layer encapsulation: Ethernet II header (14 bytes)
        if len(packet) >= 34 and packet[12:14] == b"\x08\x00":
            if _mask_at_offset(mutable, 14):
                return bytes(mutable)

    return packet


def _mask_ip_text(packet: bytes) -> bytes:
    """Mask any ASCII dotted IPv4 addresses appearing in payload bytes."""
    return _IPV4_TEXT_RE.sub(_IPV4_TEXT_MASK, packet)


def mask_ip_addresses(packet: bytes) -> bytes:
    """Mask both header-level IP addresses and textual IPv4 addresses in a packet."""
    packet = _mask_ip_header(packet)
    packet = _mask_ip_text(packet)
    return packet


def build_gray_image(packets_data: Iterable[bytes], image_size: int = 32, max_bytes: int = 1024, mask_ips: bool = True) -> np.ndarray:
    """Convert packet bytes into a fixed 32x32 uint8 grayscale image.

    When `mask_ips` is enabled, IPv4 addresses are masked before the image
    is built so the model learns traffic behavior rather than host identity.
    """

    if mask_ips:
        packets_data = (mask_ip_addresses(packet) for packet in packets_data)

    payload = b"".join(packet[:max_bytes] for packet in packets_data)
    payload = payload[: image_size * image_size].ljust(image_size * image_size, b"\x00")
    return np.frombuffer(payload, dtype=np.uint8).reshape(image_size, image_size)


def build_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, timestamp: float) -> str:
    """Construct a stable flow id based on 5-tuple (no timestamp in id).

    Uses second-level timestamp to distinguish re-connections from the
    same 5-tuple without creating a new id for every packet burst.
    Deduplication cooldown is handled by FlowManager.
    """
    time_part = datetime.fromtimestamp(timestamp).strftime("%Y%m%d_%H%M%S")
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{time_part}"


def mock_flow_data() -> FlowData:
    """Generate a deterministic example flow for local smoke testing."""

    timestamp = datetime.now().timestamp()
    packets = [
        f"mock-packet-{index}".encode("utf-8")
        for index in range(1, 3)
    ] + [os.urandom(128) for _ in range(8)]
    gray_img = build_gray_image(packets)

    return FlowData(
        flow_id=build_flow_id("192.168.1.10", 52001, "172.16.0.8", 443, timestamp),
        src_ip="192.168.1.10",
        dst_ip="172.16.0.8",
        src_port=52001,
        dst_port=443,
        protocol="TLS1.3",
        timestamp=timestamp,
        packets_data=packets,
        gray_img=gray_img,
        metadata={"source": "mock"},
    )
