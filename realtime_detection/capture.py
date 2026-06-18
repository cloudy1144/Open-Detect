"""Live packet capture helper for teammate 1.

This script captures live traffic with Scapy, groups packets into 5-tuple flows,
keeps the first N packets per flow, builds a 32x32 grayscale image using the
existing `realtime_detection.preprocess.build_gray_image()` helper, and then
passes the assembled `FlowData` into the realtime detection pipeline.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

# Ensure the package root is importable when running this script directly.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scapy.all import IP, TCP, UDP, sniff, AsyncSniffer

from realtime_detection.flow_manager import FlowData
from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.preprocess import build_flow_id, build_gray_image


DEFAULT_MAX_PACKETS = 10
DEFAULT_IDLE_TIMEOUT = 2.0
DEFAULT_FILTER = "ip and (tcp or udp)"


def get_flow_key(packet: Any) -> tuple[str, str, int, int, str] | None:
    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "UNKNOWN"
    src_port = 0
    dst_port = 0

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    else:
        protocol = str(ip_layer.proto)

    return src_ip, dst_ip, src_port, dst_port, protocol


def resolve_windows_iface(iface: str | None) -> str | None:
    if iface is None:
        return None
    if iface.startswith("\\Device\\NPF_"):
        return iface

    query = iface.lower().strip()
    try:
        from scapy.arch import get_windows_if_list
    except Exception:
        return iface

    try:
        win_ifaces = get_windows_if_list()
    except Exception:
        return iface

    for entry in win_ifaces:
        guid = entry.get("guid")
        if guid is None:
            continue
        guid_normalized = guid.strip("{}")
        name = str(entry.get("name", "")).lower()
        description = str(entry.get("description", "")).lower()
        ips = [str(ip).lower() for ip in entry.get("ips", []) if ip]

        if query == guid.lower() or query == guid_normalized.lower():
            return f"\\Device\\NPF_{{{guid_normalized}}}"
        if query == name or query == description:
            return f"\\Device\\NPF_{{{guid_normalized}}}"
        if query in name or query in description:
            return f"\\Device\\NPF_{{{guid_normalized}}}"
        if query in ips:
            return f"\\Device\\NPF_{{{guid_normalized}}}"

    return iface


def make_flow_data(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    timestamp: float,
    packets: list[bytes],
) -> FlowData:
    gray_img = build_gray_image(packets)
    return FlowData(
        flow_id=build_flow_id(src_ip, src_port, dst_ip, dst_port, timestamp),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        timestamp=timestamp,
        packets_data=packets,
        gray_img=gray_img,
        metadata={"source": "scapy_capture", "packet_count": len(packets)},
    )


def process_and_maybe_flush(
    flow_key: tuple[str, str, int, int, str],
    flow_state: dict[tuple[str, str, int, int, str], dict],
    pipeline: DetectionPipeline,
    max_packets: int,
    no_pipeline: bool,
    debug: bool = False,
) -> None:
    state = flow_state.pop(flow_key, None)
    if state is None or not state["packets"]:
        return

    flow = make_flow_data(
        state["src_ip"],
        state["dst_ip"],
        state["src_port"],
        state["dst_port"],
        state["protocol"],
        state["start_time"],
        state["packets"],
    )

    if debug:
        _emit("flow_start", {
            "flow_id": flow.flow_id,
            "src": f"{flow.src_ip}:{flow.src_port}",
            "dst": f"{flow.dst_ip}:{flow.dst_port}",
            "proto": flow.protocol,
            "packets": len(flow.packets_data),
        })

    if no_pipeline:
        _emit("flow_skip", {"flow_id": flow.flow_id, "reason": "no_pipeline"})
        return

    try:
        result = pipeline.process_captured_flow(flow)
        ir = result.inference_result or {}
        _emit("flow_result", {
            "flow_id": result.flow_id,
            "src": f"{result.src_ip}:{result.src_port}",
            "dst": f"{result.dst_ip}:{result.dst_port}",
            "proto": result.protocol,
            "is_abnormal": result.is_abnormal,
            "class_name": ir.get("class_name"),
            "attack_type": ir.get("attack_type"),
            "alert_level": ir.get("alert_level"),
            "confidence": ir.get("confidence"),
            "distance": ir.get("distance"),
            "commit_ratio": ir.get("commit_ratio"),
        })
    except Exception as exc:
        _emit("flow_error", {
            "flow_id": flow.flow_id,
            "error": str(exc),
            "src": f"{flow.src_ip}:{flow.src_port}",
            "dst": f"{flow.dst_ip}:{flow.dst_port}",
        }, level="ERROR")


def _emit(event_type: str, data: dict, level: str = "INFO") -> None:
    """Emit a JSON line to stdout for downstream consumers (ELK, Fluentd, etc.)."""
    record = {
        "ts": time.time(),
        "event": event_type,
        "level": level,
        **data,
    }
    print(json.dumps(record, default=str), flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Realtime Scapy flow capture and FlowData emitter")
    parser.add_argument("--list-ifaces", action="store_true", help="List available capture interfaces and exit")
    parser.add_argument("--iface", default=None, help="Network interface to sniff on; accepts NPF GUID, adapter name, or local IP")
    parser.add_argument("--auto-iface", action="store_true", help="Auto-select an active Windows interface by local IP or Wi-Fi adapter name")
    parser.add_argument("--filter", default=DEFAULT_FILTER, help="BPF filter for Scapy sniff")
    parser.add_argument("--duration", type=float, default=None, help="Total capture duration in seconds")
    parser.add_argument("--count", type=int, default=None, help="Total number of packets to capture")
    parser.add_argument(
        "--max-packets-per-flow",
        type=int,
        default=DEFAULT_MAX_PACKETS,
        help="Maximum number of packets to keep for each flow",
    )
    parser.add_argument(
        "--flow-idle-timeout",
        type=float,
        default=DEFAULT_IDLE_TIMEOUT,
        help="Seconds of flow inactivity before flushing a partial flow",
    )
    parser.add_argument("--no-pipeline", action="store_true", help="Build FlowData only and skip the detection pipeline")
    parser.add_argument("--debug", action="store_true", help="Print debug information for packet handling")
    return parser


def get_default_windows_iface() -> str | None:
    try:
        from scapy.arch import get_windows_if_list
    except Exception:
        return None

    try:
        win_ifaces = get_windows_if_list()
    except Exception:
        return None

    # Find the host's primary outbound IP (best-effort) and match it to an iface
    def get_primary_outbound_ip() -> str | None:
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            return None

    primary_ip = get_primary_outbound_ip()
    if primary_ip:
        for entry in win_ifaces:
            ips = [str(ip) for ip in entry.get("ips", []) or []]
            if primary_ip in ips:
                guid = entry.get("guid")
                if guid:
                    return f"\\Device\\NPF_{{{guid.strip('{}')}}}"

    # Prefer wireless adapters by name/description if primary IP match not found
    for entry in win_ifaces:
        name = str(entry.get("name", "")).lower()
        desc = str(entry.get("description", "")).lower()
        if any(k in name or k in desc for k in ("wlan", "wi-fi", "wifi", "wireless", "intel")):
            guid = entry.get("guid")
            if guid:
                return f"\\Device\\NPF_{{{guid.strip('{}')}}}"

    # Fallback: pick first entry with a private IPv4
    for entry in win_ifaces:
        ips = [str(ip) for ip in entry.get("ips", []) or []]
        if any(ip.startswith("10.") or ip.startswith("192.") or ip.startswith("172.") for ip in ips):
            guid = entry.get("guid")
            if guid:
                return f"\\Device\\NPF_{{{guid.strip('{}')}}}"

    return None


def capture_flows(args: argparse.Namespace) -> None:
    pipeline = DetectionPipeline() if not args.no_pipeline else None
    flow_state: dict[tuple[str, str, int, int, str], dict] = {}

    # Diagnostics: print available interfaces and pcap/provider status
    try:
        import scapy.all as scapy
        if args.debug:
            print("[DIAG] scapy.conf.use_pcap:", getattr(scapy.conf, "use_pcap", None))
            try:
                if hasattr(scapy, "get_if_list"):
                    print("[DIAG] available interfaces:", scapy.get_if_list())
            except Exception:
                pass
    except Exception:
        if args.debug:
            print("[DIAG] scapy import failed or diagnostics unavailable")

    # On Windows, warn if not running as administrator
    try:
        import os
        if os.name == "nt":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False
            if args.debug and not is_admin:
                print("[DIAG] Warning: not running as administrator. Run the script from an elevated prompt for live capture on Windows.")
    except Exception:
        pass

    def flush_idle_flows() -> None:
        now = time.time()
        expired_keys = [
            key for key, state in flow_state.items() if now - state["last_seen"] >= args.flow_idle_timeout
        ]
        for key in expired_keys:
            process_and_maybe_flush(key, flow_state, pipeline, args.max_packets_per_flow, args.no_pipeline, args.debug)

    captured_packets = {"count": 0}

    def packet_callback(packet: Any) -> None:
        key = get_flow_key(packet)
        if key is None:
            return

        # global packet counter for honoring --count
        try:
            captured_packets["count"] += 1
        except Exception:
            pass

        now = time.time()
        state = flow_state.get(key)
        if state is None or now - state["last_seen"] >= args.flow_idle_timeout:
            state = {
                "src_ip": key[0],
                "dst_ip": key[1],
                "src_port": key[2],
                "dst_port": key[3],
                "protocol": key[4],
                "packets": [],
                "start_time": now,
                "last_seen": now,
            }
            flow_state[key] = state

        packet_bytes = bytes(packet)
        if len(state["packets"]) < args.max_packets_per_flow:
            state["packets"].append(packet_bytes)

        state["last_seen"] = now

        if args.debug:
            print(
                f"[PACKET] {key[0]}:{key[2]} -> {key[1]}:{key[3]} "
                f"proto={key[4]} packets={len(state['packets'])}"
            )

        if len(state["packets"]) >= args.max_packets_per_flow:
            process_and_maybe_flush(key, flow_state, pipeline, args.max_packets_per_flow, args.no_pipeline, args.debug)
        else:
            flush_idle_flows()

    if args.auto_iface and not args.iface:
        args.iface = resolve_windows_iface(get_default_windows_iface())

    resolved_iface = resolve_windows_iface(args.iface)
    if args.debug:
        print(f"[DIAG] requested iface={args.iface} resolved_iface={resolved_iface}")
    args.iface = resolved_iface

    _emit("capture_start", {
        "iface": args.iface,
        "filter": args.filter,
        "max_packets_per_flow": args.max_packets_per_flow,
        "flow_idle_timeout": args.flow_idle_timeout,
        "duration": args.duration,
        "count": args.count,
    })

    # Continuous capture using AsyncSniffer and a stop event so Ctrl+C stops immediately
    end_time = time.time() + args.duration if args.duration else None

    stop_event = threading.Event()

    def _handle_sigint(signum, frame):
        stop_event.set()

    # register SIGINT handler to set stop_event
    try:
        signal.signal(signal.SIGINT, _handle_sigint)
    except Exception:
        # signal may fail on some platforms/contexts; fallback to KeyboardInterrupt handling
        pass

    sniffer = AsyncSniffer(iface=args.iface, filter=args.filter, prn=packet_callback, store=False)
    sniffer.start()

    try:
        while not stop_event.is_set():
            if end_time and time.time() >= end_time:
                break
            if args.count and captured_packets.get("count", 0) >= args.count:
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        stop_event.set()

    try:
        sniffer.stop()
    except Exception as exc:
        print("[WARN] failed to stop sniffer cleanly:", exc)

    _emit("capture_stop", {"reason": "finished", "remaining_flows": len(flow_state)})
    for key in list(flow_state.keys()):
        process_and_maybe_flush(key, flow_state, pipeline, args.max_packets_per_flow, args.no_pipeline, args.debug)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "list_ifaces", False):
        try:
            from scapy.all import get_if_list
            print("Available interfaces:")
            for iface in get_if_list():
                print(" -", iface)
        except Exception as exc:
            print("Failed to list interfaces:", exc)
        return
    capture_flows(args)


if __name__ == "__main__":
    main()
