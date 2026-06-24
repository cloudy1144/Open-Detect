#!/usr/bin/env python3
"""
PCAP 网络回放脚本

读取出 npz_to_pcap.py 生成的 PCAP 文件，通过 loopback 网卡发送，
配合捕获管线的 --training-compat 模式实现训练兼容的实时检测。

用法:
    # 回放单个类别
    python replay_pcap.py --pcap output/pcaps/15_CobaltStrike_000.pcap

    # 回放所有 CRITICAL 类别的 PCAP
    python replay_pcap.py --level CRITICAL --pcaps-dir output/pcaps

    # 回放所有 PCAP
    python replay_pcap.py --all --pcaps-dir output/pcaps

    # 使用不同接口 (需要两个独立网卡或 veth pair)
    python replay_pcap.py --pcap output/pcaps/15_CobaltStrike_000.pcap --iface eth0

拓扑:
    [replay_pcap.py] --sendp()--> [lo] --sniff()--> [frontend/server.py --training-compat --iface lo]

关键:
    - 使用 loopback (lo) 网卡，支持单机发送+捕获
    - 自动启动 dummy TCP listener 防止内核 RST 干扰
    - 替换 PCAP 中的 IP 为 loopback 地址 (127.0.0.x)
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from scapy.all import (
    Ether, IP, TCP, Raw,
    rdpcap, sendp, wrpcap,
)

ROOT_DIR = Path(__file__).resolve().parent


# ────────────────────────────────
# dummy TCP listener
# ────────────────────────────────

class DummyTCPListener:
    """在指定端口上 accept 所有连接并静默关闭，防止内核 RST 干扰."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(1.0)
        self._running = True

        def _accept_loop():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    conn.close()
                except socket.timeout:
                    continue
                except Exception:
                    break

        self._thread = threading.Thread(target=_accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


# ────────────────────────────────
# PCAP 地址改写
# ────────────────────────────────

LO_SRC_IP = "172.31.0.1"     # 客户端 IP (非 loopback, 避免内核 TCP 栈干扰)
LO_DST_IP = "172.31.0.2"     # 服务端 IP
DUMMY_PORT = 9999


def _find_client_port(packets: list) -> int | None:
    """从第一个 SYN 包中提取客户端源端口."""
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        data = bytes(pkt)
        ip_start = 14
        if len(data) < ip_start + 20 + 13:
            continue
        flags = data[ip_start + 20 + 13]
        if flags & 0x02 and not (flags & 0x10):
            return struct.unpack('>H', data[ip_start + 20:ip_start + 22])[0]
    return None


def rewrite_pcap_for_loopback(packets: list, dst_port: int = DUMMY_PORT) -> list:
    """将 PCAP 中的 IP 替换为 loopback 地址以在 lo 上回放.

    同时重算 IP 和 TCP checksum。
    """
    client_port = _find_client_port(packets)
    rewritten = []
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            rewritten.append(pkt)
            continue

        data = bytes(pkt)
        # 替换 IP 地址 (bytes 12-15 = src, 16-19 = dst in IP header after Ethernet)
        eth_hdr_len = 14  # Ethernet
        ip_start = eth_hdr_len
        data = bytearray(data)

        # 判断方向: 第一个 SYN 是 client→server
        flags = data[ip_start + 20 + 13]  # TCP flags byte

        if flags & 0x02 and not (flags & 0x10):
            # SYN (no ACK) → client → replace src=LO_SRC, dst=LO_DST
            src_ip = socket.inet_aton(LO_SRC_IP)
            dst_ip = socket.inet_aton(LO_DST_IP)
        elif (flags & 0x12) == 0x12:
            # SYN+ACK → server → replace src=LO_DST, dst=LO_SRC
            src_ip = socket.inet_aton(LO_DST_IP)
            dst_ip = socket.inet_aton(LO_SRC_IP)
        else:
            # Established → 通过源端口匹配 client_port 判断方向
            sp = struct.unpack('>H', data[ip_start + 20:ip_start + 22])[0]
            if client_port is not None and sp == client_port:
                src_ip = socket.inet_aton(LO_SRC_IP)
                dst_ip = socket.inet_aton(LO_DST_IP)
            elif client_port is not None:
                src_ip = socket.inet_aton(LO_DST_IP)
                dst_ip = socket.inet_aton(LO_SRC_IP)
            else:
                src_ip = socket.inet_aton(LO_SRC_IP)
                dst_ip = socket.inet_aton(LO_DST_IP)

        data[ip_start + 12:ip_start + 16] = src_ip
        data[ip_start + 16:ip_start + 20] = dst_ip

        # 替换 dst port
        struct.pack_into('>H', data, ip_start + 20 + 2, dst_port)

        # 重算 IP header checksum
        ip_ihl = data[ip_start] & 0x0F
        ip_hdr_len = ip_ihl * 4
        data[ip_start + 10:ip_start + 12] = b'\x00\x00'
        ip_csum = _ip_checksum(data[ip_start:ip_start + ip_hdr_len])
        struct.pack_into('>H', data, ip_start + 10, ip_csum)

        # 重算 TCP checksum
        tcp_start = ip_start + ip_hdr_len
        tcp_data_off = (data[tcp_start + 12] >> 4) & 0x0F
        tcp_hdr_len = tcp_data_off * 4
        tcp_len = len(data) - tcp_start
        data[tcp_start + 16:tcp_start + 18] = b'\x00\x00'

        # TCP pseudo-header
        pseudo = src_ip + dst_ip + b'\x00\x06' + struct.pack('>H', tcp_len)
        tcp_csum = _ones_complement_checksum(pseudo + data[tcp_start:])
        struct.pack_into('>H', data, tcp_start + 16, tcp_csum)

        rewritten.append(Ether(data))

    return rewritten


def _ones_complement_checksum(data: bytes) -> int:
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) + data[i + 1]
    if len(data) % 2 == 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip_checksum(header: bytes) -> int:
    return _ones_complement_checksum(header)


# ────────────────────────────────
# 回放逻辑
# ────────────────────────────────

def replay_pcap(pcap_path: str, iface: str = "lo",
                dst_port: int = DUMMY_PORT,
                pps: int = 20, inter_flow_delay: float = 2.0):
    """回放单个 PCAP 文件.

    Args:
        pcap_path: PCAP 文件路径
        iface: 发送接口
        dst_port: 目标端口 (需有 dummy listener)
        pps: 每秒发包数
        inter_flow_delay: 流之间间隔秒数
    """
    pkts = rdpcap(pcap_path)
    if not pkts:
        print(f"  [WARN] {pcap_path}: empty PCAP, skipping")
        return

    rewritten = rewrite_pcap_for_loopback(pkts, dst_port)
    delay = 1.0 / pps

    for i, pkt in enumerate(rewritten):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(delay)

    # 等待流被捕获处理
    time.sleep(inter_flow_delay)


def replay_from_manifest(manifest_path: str, pcaps_dir: str,
                          iface: str = "lo", level: Optional[str] = None,
                          single_class: Optional[str] = None):
    """根据 manifest.json 批量回放 PCAP.

    Args:
        manifest_path: manifest.json 路径
        pcaps_dir: PCAP 文件目录
        iface: 发送接口
        level: 仅回放指定级别 (CRITICAL/WARNING/INFO), None=全部
        single_class: 仅回放指定类别名, None=全部
    """
    with open(manifest_path) as f:
        manifest = json.load(f)

    entries = manifest
    if level:
        entries = [e for e in entries if e['alert_level'] == level]
    if single_class:
        entries = [e for e in entries if e['class_name'] == single_class]

    print(f"Replaying {len(entries)} flows via {iface}")
    print(f"  Level filter: {level or 'ALL'}")
    print(f"  Dummy listener: 127.0.0.1:{DUMMY_PORT}")
    print()

    # 启动 dummy listener
    listener = DummyTCPListener("127.0.0.1", DUMMY_PORT)
    listener.start()
    time.sleep(0.3)

    try:
        for i, entry in enumerate(entries):
            pcap_path = os.path.join(pcaps_dir, entry['file'])
            tag = f"[{entry['alert_level']:8s}]"
            print(f"  {i+1}/{len(entries)} {tag} {entry['class_name']:<20s} "
                  f"({entry['packets']} pkts)")

            if not os.path.exists(pcap_path):
                print(f"    [SKIP] file not found: {pcap_path}")
                continue

            replay_pcap(pcap_path, iface, DUMMY_PORT)

    finally:
        listener.stop()


def main():
    parser = argparse.ArgumentParser(
        description="PCAP 网络回放 — 配合 --training-compat 捕获管线使用")
    parser.add_argument("--pcap", default=None,
                        help="单个 PCAP 文件路径")
    parser.add_argument("--pcaps-dir", default="output/pcaps",
                        help="PCAP 文件目录 (批量模式)")
    parser.add_argument("--manifest", default=None,
                        help="manifest.json 路径 (默认: <pcaps-dir>/manifest.json)")
    parser.add_argument("--iface", default="lo",
                        help="发送接口 (默认: lo)")
    parser.add_argument("--level", default=None,
                        choices=["CRITICAL", "WARNING", "INFO"],
                        help="仅回放指定告警级别的流量")
    parser.add_argument("--class", dest="single_class", default=None,
                        help="仅回放指定类别 (如 CobaltStrike)")
    parser.add_argument("--all", action="store_true",
                        help="回放所有类别的 PCAP")
    parser.add_argument("--pps", type=int, default=20,
                        help="每秒发包数 (默认: 20)")
    parser.add_argument("--port", type=int, default=DUMMY_PORT,
                        help="dummy listener 端口 (默认: 9999)")

    args = parser.parse_args()

    if args.pcap:
        # 单文件模式
        print(f"Single-file replay: {args.pcap}")
        listener = DummyTCPListener("127.0.0.1", args.port)
        listener.start()
        time.sleep(0.3)
        try:
            replay_pcap(args.pcap, args.iface, args.port, args.pps)
        finally:
            listener.stop()
        return

    # 批量模式
    if not args.all and not args.level and not args.single_class:
        print("请指定 --pcap, --all, --level, 或 --class")
        sys.exit(1)

    manifest_path = args.manifest or os.path.join(args.pcaps_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        print(f"Manifest not found: {manifest_path}")
        sys.exit(1)

    replay_from_manifest(
        manifest_path=manifest_path,
        pcaps_dir=args.pcaps_dir,
        iface=args.iface,
        level=args.level,
        single_class=args.single_class,
    )


if __name__ == "__main__":
    main()
