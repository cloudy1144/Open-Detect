"""Byte-stream to 32x32 grayscale image helpers used before model inference."""

from __future__ import annotations

from datetime import datetime
import ipaddress
import os
import re
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


def mask_ip_address(ip: str, mask_type: str = "private") -> str:
    """Mask IP address for privacy protection.

    Args:
        ip: IP address string (IPv4 or IPv6)
        mask_type: Masking strategy:
            - "private": Mask last octet for private IPs, last two for public
            - "public": Mask last two octets
            - "all": Mask all except network prefix
            - "zero": Replace entire IP with zeros

    Returns:
        Masked IP address string
    """
    try:
        addr = ipaddress.ip_address(ip)
        
        if isinstance(addr, ipaddress.IPv4Address):
            parts = ip.split(".")
            if len(parts) != 4:
                return "***.***.***.***"
            
            is_private = addr.is_private
            
            if mask_type == "zero":
                return "0.0.0.0"
            elif mask_type == "all":
                if is_private:
                    return f"{parts[0]}.{parts[1]}.0.0"
                else:
                    return f"{parts[0]}.0.0.0"
            elif mask_type == "public":
                return f"{parts[0]}.{parts[1]}.xxx.xxx"
            else:
                if is_private:
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
                else:
                    return f"{parts[0]}.{parts[1]}.xxx.xxx"
        else:
            hextets = str(addr).split(":")
            
            if mask_type == "zero":
                return "::"
            elif mask_type == "all":
                return f"{hextets[0]}:{hextets[1]}::"
            else:
                masked = []
                for i, hextet in enumerate(hextets):
                    if i < len(hextets) - 2:
                        masked.append(hextet)
                    else:
                        masked.append("xxxx")
                return ":".join(masked)
    except ValueError:
        return "***.***.***.***"


def mask_ip_in_bytes(packet_data: bytes, mask_type: str = "private") -> bytes:
    """Mask all IP addresses found in raw packet bytes."""
    packet_str = packet_data.decode("latin-1")
    
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    
    for ip in re.findall(ipv4_pattern, packet_str):
        masked = mask_ip_address(ip, mask_type)
        packet_str = packet_str.replace(ip, masked)
    
    for ip in re.findall(ipv6_pattern, packet_str):
        masked = mask_ip_address(ip, mask_type)
        packet_str = packet_str.replace(ip, masked)
    
    return packet_str.encode("latin-1")


def mask_flow_ips(flow: FlowData, mask_type: str = "private") -> FlowData:
    """Mask all IP addresses in a flow for privacy protection."""
    flow.src_ip = mask_ip_address(flow.src_ip, mask_type)
    flow.dst_ip = mask_ip_address(flow.dst_ip, mask_type)
    
    if flow.packets_data:
        flow.packets_data = [
            mask_ip_in_bytes(packet, mask_type) 
            for packet in flow.packets_data
        ]
    
    flow.flow_id = build_flow_id(
        flow.src_ip, flow.src_port, 
        flow.dst_ip, flow.dst_port, 
        flow.timestamp
    )
    
    if flow.gray_img is None:
        flow.gray_img = build_gray_image(flow.packets_data)
    else:
        flow.gray_img = build_gray_image(flow.packets_data)
    
    return flow


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
