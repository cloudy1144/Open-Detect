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


def build_gray_image_training_compat(
    packets_data: Iterable[bytes],
    max_packets: int = 8,
    image_size: int = 32,
    header_hex_len: int = 160,
    payload_hex_len: int = 96,
) -> np.ndarray:
    """与训练预处理完全一致的 32x32 灰度图构建。

    训练管线 (data/Preprocessing/utils.py):
      PCAP → raw_packet_to_string()
        → ip.src = ip.dst = "0.0.0.0"
        → bytes(ip), hexlify, 去除 payload hex, 仅保留 IP+TCP 头
        → header[:160] hex chars (80B) + payload[:96] hex chars (48B)
        → 8 packets × 256 hex chars = 2048 hex → 1024 uint8 → 32×32

    本函数模拟此管线：剥离 Ethernet 头、零化 IP、分离 header/payload、hex 补齐。
    """
    result_hex = ""
    chunk_hex_len = header_hex_len + payload_hex_len

    pkts = list(packets_data)
    for pkt_idx in range(max_packets):
        if pkt_idx < len(pkts):
            raw = bytes(pkts[pkt_idx])

            # 1. 剥离 Ethernet 头 (14 bytes)
            if len(raw) > 14:
                raw = raw[14:]

            # 2. 零化 IP 地址 (bytes 12-19 of IP header)
            raw = bytearray(raw)
            if len(raw) >= 20:
                raw[12:20] = b"\x00" * 8
            raw = bytes(raw)

            # 3. 解析 header 长度
            ip_ihl = raw[0] & 0x0F if len(raw) > 0 else 5
            ip_hdr_len = ip_ihl * 4
            if len(raw) > ip_hdr_len + 12:
                tcp_data_off = (raw[ip_hdr_len + 12] >> 4) & 0x0F
            else:
                tcp_data_off = 5
            tcp_hdr_len = tcp_data_off * 4
            total_hdr_len = ip_hdr_len + tcp_hdr_len

            # 4. 分离 IP+TCP header 和 TCP payload
            hdr_bytes = raw[:total_hdr_len]
            pld_bytes = raw[total_hdr_len:]

            hdr_hex = hdr_bytes.hex()
            pld_hex = pld_bytes.hex()

            # 5. 截断/补齐 (与训练完全一致)
            hdr_hex = hdr_hex[:header_hex_len].ljust(header_hex_len, "0")
            pld_hex = pld_hex[:payload_hex_len].ljust(payload_hex_len, "0")

            result_hex += hdr_hex + pld_hex
        else:
            result_hex += "0" * chunk_hex_len

    # 6. hex 字符串 → uint8 数组
    result_bytes = bytes.fromhex(result_hex)
    result_bytes = result_bytes[: image_size * image_size].ljust(image_size * image_size, b"\x00")
    return np.frombuffer(result_bytes, dtype=np.uint8).reshape(image_size, image_size)


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
