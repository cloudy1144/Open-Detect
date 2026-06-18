"""Byte-stream to 32x32 grayscale image helpers used before model inference."""

from __future__ import annotations

from datetime import datetime
import os
from typing import Iterable

import numpy as np

from .flow_manager import FlowData


def build_gray_image(packets_data: Iterable[bytes], image_size: int = 32, max_bytes: int = 1024) -> np.ndarray:
    """Convert packet bytes into a fixed 32x32 uint8 grayscale image."""

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
