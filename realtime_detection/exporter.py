"""Export abnormal flows to PCAP for traceability and offline review."""

from __future__ import annotations

from datetime import datetime
import os

from .flow_manager import FlowData


def export_abnormal_flow(flow: FlowData, save_dir: str = "./abnormal_flows") -> str:
    """Save a flow as a PCAP file using a simple synthetic packet wrapper.

    The implementation is intentionally isolated so teammate 1 can later swap
    the packet source without changing the surrounding pipeline.
    """

    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError as exc:  # pragma: no cover - depends on local environment
        raise RuntimeError("scapy is required for PCAP export") from exc

    os.makedirs(save_dir, exist_ok=True)
    time_str = datetime.fromtimestamp(flow.timestamp).strftime("%Y%m%d_%H%M%S")
    attack_type = flow.inference_result.get("attack_type", "unknown") if flow.inference_result else "unknown"
    filename = f"{attack_type}_{time_str}_{flow.src_ip}_{flow.dst_ip}.pcap"
    save_path = os.path.join(save_dir, filename)

    scapy_packets = []
    for packet_bytes in flow.packets_data:
        payload = packet_bytes if isinstance(packet_bytes, (bytes, bytearray)) else bytes(packet_bytes)
        scapy_packets.append(
            Ether() /
            IP(src=flow.src_ip, dst=flow.dst_ip) /
            TCP(sport=flow.src_port, dport=flow.dst_port) /
            Raw(load=payload)
        )

    wrpcap(save_path, scapy_packets)
    return save_path
