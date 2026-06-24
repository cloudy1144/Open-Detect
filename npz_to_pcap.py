#!/usr/bin/env python3
"""
从 mixed_44_train.npz 训练数据逆向重建合法 PCAP 文件。

原理:
  训练预处理管线:
    PCAP → raw_packet_to_string() → hex 字符串(IP零化,80B头+48B负载)
    → 8 packets × 128 bytes = 1024 bytes → 32×32 uint8 灰度图

  逆向:
    32×32 uint8 → 1024 bytes → 8 chunks × 128B
    → 解析 IP/TCP 头 → 修复 IP 地址 + 重算 checksum
    → scapy 构建合法 PCAP → 写入 .pcap 文件

用法:
    python npz_to_pcap.py                        # 默认: 每类1条, 输出到 output/pcaps/
    python npz_to_pcap.py --per-class 3          # 每类3条
    python npz_to_pcap.py --output /tmp/pcaps    # 指定输出目录
    python npz_to_pcap.py --classes 15,30,2      # 只生成指定类别
"""

import argparse
import os
import struct
import sys
from pathlib import Path

import numpy as np

# Ensure project root is on path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from predict import CLASS_NAMES


# ──────────────────────────────────────────
# 从 model_adapter 的定义复制
# ──────────────────────────────────────────
CLASS_ATTACK_TYPE: dict[int, str] = {
    0:  "known_malware", 1:  "known_malware", 2:  "known_malware",
    3:  "known_malware", 5:  "known_malware", 6:  "known_malware",
    7:  "known_malware", 8:  "known_malware", 9:  "known_malware",
    11: "known_malware", 12: "known_malware", 13: "known_malware",
    14: "known_malware", 15: "known_malware", 16: "known_malware",
    17: "known_malware", 19: "known_malware", 20: "known_malware",
    4:  "suspicious_tool", 10: "suspicious_tool", 18: "suspicious_tool",
    21: "suspicious_tool", 22: "suspicious_tool", 23: "suspicious_tool",
    29: "known_malware", 30: "known_malware", 34: "known_malware",
    36: "known_malware", 37: "known_malware", 39: "known_malware",
    40: "known_malware", 42: "known_malware", 43: "known_malware",
}

ALERT_LEVEL_MAP = {
    "known_malware": "CRITICAL",
    "suspicious_tool": "WARNING",
    "unknown_attack": "WARNING",
    "normal": "INFO",
}


# ──────────────────────────────────────────
# checksum 计算 (RFC 1071)
# ──────────────────────────────────────────

def _ones_complement_checksum(data: bytes) -> int:
    """16-bit one's complement checksum."""
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) + data[i + 1]
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_checksum(ip_header_20b: bytes) -> int:
    """计算 IP header checksum (仅 IP 头, 不含 payload)."""
    return _ones_complement_checksum(ip_header_20b)


def tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_segment: bytes) -> int:
    """计算 TCP checksum (含 pseudo-header).
    
    pseudo-header: src_ip(4B) + dst_ip(4B) + zero(1B) + proto(1B) + tcp_len(2B)
    """
    protocol = 6  # TCP
    tcp_len = len(tcp_segment)
    pseudo = src_ip + dst_ip + b'\x00' + bytes([protocol]) + struct.pack('>H', tcp_len)
    # pseudo-header 长度可能为奇数, 需要处理
    data = pseudo + tcp_segment
    return _ones_complement_checksum(data)


# ──────────────────────────────────────────
# 图像 → PCAP 核心逻辑
# ──────────────────────────────────────────

CLIENT_IP = b'\x0a\x00\x00\x01'   # 10.0.0.1
SERVER_IP = b'\x0a\x00\x00\x02'   # 10.0.0.2


def _strip_zeros(data: bytes) -> bytes:
    """去除尾部全零填充."""
    return data.rstrip(b'\x00')


def reconstruct_single_packet(header_80b: bytes, payload_48b: bytes,
                               is_client_to_server: bool) -> bytes | None:
    """从训练格式的 header+payload 重建合法 IP/TCP 包.

    Args:
        header_80b: 80 字节的 IP+TCP 头部 (含零填充)
        payload_48b: 48 字节的 TCP 负载 (含零填充)
        is_client_to_server: True=client→server, False=server→client

    Returns:
        完整的 IP+TCP+payload 字节, 或 None (空包)
    """
    if header_80b[0] == 0:
        return None  # 全零包

    # ── 解析 IP 头 ──
    ip_ihl = header_80b[0] & 0x0F
    ip_header_len = ip_ihl * 4
    if ip_header_len < 20 or ip_header_len > 60:
        ip_header_len = 20

    # ── 解析 TCP 头 ──
    tcp_start = ip_header_len
    if tcp_start + 20 > 80:
        # TCP header extends beyond 80 bytes — unusual but handle
        tcp_header_len = 20
    else:
        tcp_data_offset = (header_80b[tcp_start + 12] >> 4) & 0x0F
        tcp_header_len = tcp_data_offset * 4
        if tcp_header_len < 20 or tcp_header_len > 60:
            tcp_header_len = 20

    total_header_len = ip_header_len + tcp_header_len

    # ── 剥离零填充 ──
    actual_header = header_80b[:total_header_len]
    actual_payload = _strip_zeros(payload_48b)

    # ── 构建修复后的字节 ──
    ip_hdr = bytearray(actual_header[:ip_header_len])
    tcp_hdr = bytearray(actual_header[ip_header_len:total_header_len])

    # 修复 IP 地址
    if is_client_to_server:
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP

    ip_hdr[12:16] = src_ip
    ip_hdr[16:20] = dst_ip

    # 重算 IP header checksum
    ip_hdr[10:12] = b'\x00\x00'
    ip_csum = ip_checksum(bytes(ip_hdr))
    struct.pack_into('>H', ip_hdr, 10, ip_csum)

    # 重算 TCP checksum
    tcp_hdr[16:18] = b'\x00\x00'
    tcp_segment = bytes(tcp_hdr) + actual_payload
    tcp_csum = tcp_checksum(src_ip, dst_ip, tcp_segment)
    struct.pack_into('>H', tcp_hdr, 16, tcp_csum)

    return bytes(ip_hdr) + bytes(tcp_hdr) + actual_payload


def _get_tcp_flags(tcp_hdr: bytes) -> int:
    """从 TCP header 提取 flags 字节."""
    if len(tcp_hdr) < 14:
        return 0
    return tcp_hdr[13]


def _determine_directions(headers: list[bytes]) -> list[bool]:
    """根据 TCP SYN 标志判断每包的方向.
    
    Returns:
        list[bool]: True=client→server, False=server→client
    """
    directions = []
    for hdr in headers:
        if hdr[0] == 0:
            directions.append(True)  # placeholder for empty
            continue
        
        ip_ihl = hdr[0] & 0x0F
        ip_header_len = ip_ihl * 4
        tcp_start = ip_header_len
        if tcp_start + 14 > len(hdr):
            directions.append(True)
            continue
        
        flags = _get_tcp_flags(hdr[tcp_start:tcp_start + 20])
        syn = flags & 0x02
        ack = flags & 0x10

        if syn and not ack:
            # SYN (no ACK) → client initiates
            directions.append(True)
        elif syn and ack:
            # SYN+ACK → server responds
            directions.append(False)
        else:
            # For established packets, use port direction:
            # lower port = server (typical), but here both ports are arbitrary
            # Use the first packet's direction as reference
            directions.append(True)  # will be overridden below
    
    # Normalize: packets after SYN go the same direction as their 5-tuple
    # All packets in the same flow direction should be consistent
    # Simple heuristic: if first SYN is client→server, subsequent packets 
    # from same src_port→dst_port are client→server
    client_ports = set()
    server_ports = set()
    for i, (hdr, d) in enumerate(zip(headers, directions)):
        if hdr[0] == 0:
            continue
        ip_ihl = hdr[0] & 0x0F
        tcp_start = ip_ihl * 4
        if tcp_start + 4 > len(hdr):
            continue
        sp = struct.unpack('>H', hdr[tcp_start:tcp_start + 2])[0]
        dp = struct.unpack('>H', hdr[tcp_start + 2:tcp_start + 4])[0]
        flags = _get_tcp_flags(hdr[tcp_start:tcp_start + 20]) if tcp_start + 14 <= len(hdr) else 0
        
        if flags & 0x02 and not (flags & 0x10):
            # This is a SYN (client → server)
            client_ports.add(sp)
            server_ports.add(dp)

    # Now correct directions
    result = []
    for hdr in headers:
        if hdr[0] == 0:
            result.append(True)
            continue
        ip_ihl = hdr[0] & 0x0F
        tcp_start = ip_ihl * 4
        if tcp_start + 4 > len(hdr):
            result.append(True)
            continue
        sp = struct.unpack('>H', hdr[tcp_start:tcp_start + 2])[0]
        
        if client_ports and sp in client_ports:
            result.append(True)
        elif server_ports and sp in server_ports:
            result.append(False)
        else:
            result.append(True)
    
    return result


def image_to_packets(img: np.ndarray) -> list[bytes | None]:
    """将 32×32 训练图像转换为 8 个包的原始 IP+TCP+payload 字节列表.
    
    Returns:
        list of bytes | None: 每个包的重建字节, None 表示空包
    """
    flat = img.flatten().tobytes()  # 1024 bytes
    chunks = [flat[i:i + 128] for i in range(0, 1024, 128)]

    headers = [c[:80] for c in chunks]
    payloads = [c[80:128] for c in chunks]
    directions = _determine_directions(headers)

    packets = []
    for hdr, pld, direction in zip(headers, payloads, directions):
        pkt = reconstruct_single_packet(hdr, pld, direction)
        packets.append(pkt)
    
    return packets


def generate_pcaps(npz_path: str, output_dir: str, per_class: int = 1,
                    target_classes: list[int] | None = None):
    """从 .npz 训练数据生成 PCAP 文件.

    Args:
        npz_path: mixed_44_train.npz 路径
        output_dir: PCAP 输出目录
        per_class: 每类生成的流数
        target_classes: 指定生成的类别列表, None=全部
    """
    data = np.load(npz_path)
    images = data['data']
    labels = data['target']

    os.makedirs(output_dir, exist_ok=True)

    unique_labels = sorted(set(int(l) for l in labels))
    if target_classes:
        unique_labels = [l for l in unique_labels if l in target_classes]

    manifest = []
    total_flows = 0

    for class_id in unique_labels:
        class_name = CLASS_NAMES.get(class_id, f"class_{class_id}")
        attack_type = CLASS_ATTACK_TYPE.get(class_id, "normal")
        alert_level = ALERT_LEVEL_MAP.get(attack_type, "INFO")

        idxs = np.where(labels == class_id)[0]
        if len(idxs) == 0:
            continue

        for sample_i in range(min(per_class, len(idxs))):
            img_idx = idxs[sample_i]
            img = images[img_idx]
            flow_packets = image_to_packets(img)

            # 统计有效包
            valid_count = sum(1 for p in flow_packets if p is not None)

            # 生成 PCAP 文件名
            safe_name = class_name.replace('/', '_').replace(' ', '_')
            pcap_filename = f"{class_id:02d}_{safe_name}_{sample_i:03d}.pcap"
            pcap_path = os.path.join(output_dir, pcap_filename)

            # 用 scapy 写 PCAP
            try:
                from scapy.all import Ether, IP, Raw, wrpcap

                scapy_pkts = []
                for i, raw_pkt in enumerate(flow_packets):
                    if raw_pkt is None:
                        continue
                    try:
                        # raw_pkt = IP hdr + TCP hdr + payload
                        # 用 scapy 封装: Ether / IP(raw)
                        pkt = Ether() / IP(raw_pkt)
                        scapy_pkts.append(pkt)
                    except Exception as exc:
                        print(f"  [WARN] Packet {i} reconstruction failed for "
                              f"{class_name}#{sample_i}: {exc}")

                if scapy_pkts:
                    wrpcap(pcap_path, scapy_pkts)
                    total_flows += 1
                    manifest.append({
                        "class_id": class_id,
                        "class_name": class_name,
                        "attack_type": attack_type,
                        "alert_level": alert_level,
                        "packets": valid_count,
                        "file": pcap_filename,
                    })
                    print(f"  [{alert_level:8s}] {class_id:2d} {class_name:<20s} "
                          f"→ {pcap_filename} ({valid_count} packets)")
            except ImportError:
                print("[ERROR] scapy not installed. Run: pip install scapy")
                sys.exit(1)

    # 写入 manifest
    manifest_path = os.path.join(output_dir, "manifest.json")
    import json
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\nDone: {total_flows} PCAP files written to {output_dir}/")
    print(f"Manifest: {manifest_path}")

    # 汇总统计
    by_level = {}
    for m in manifest:
        lv = m['alert_level']
        by_level[lv] = by_level.get(lv, 0) + 1
    print(f"Breakdown: {by_level}")


def main():
    parser = argparse.ArgumentParser(
        description="从 .npz 训练数据逆向重建合法 PCAP 用于网络回放")
    parser.add_argument("--npz", default="data/dataset/mixed_44_train.npz",
                        help="训练数据 .npz 路径")
    parser.add_argument("--output", default="output/pcaps",
                        help="PCAP 输出目录")
    parser.add_argument("--per-class", type=int, default=1,
                        help="每类生成的流数 (默认1)")
    parser.add_argument("--classes", type=str, default=None,
                        help="指定类别, 逗号分隔, 如 '15,30,2'. 默认=全部")

    args = parser.parse_args()

    target_classes = None
    if args.classes:
        target_classes = [int(c.strip()) for c in args.classes.split(',')]

    print(f"Generating PCAPs from {args.npz}")
    print(f"Output: {args.output}")
    print(f"Per class: {args.per_class}")
    print(f"Classes: {target_classes or 'ALL (44)'}")
    print()

    generate_pcaps(
        npz_path=args.npz,
        output_dir=args.output,
        per_class=args.per_class,
        target_classes=target_classes,
    )


if __name__ == "__main__":
    main()
