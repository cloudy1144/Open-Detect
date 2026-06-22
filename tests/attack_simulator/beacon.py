"""C2 Beaconing simulation — periodic TCP connections to mimic C2 heartbeat."""
from __future__ import annotations

import socket
import time

try:
    from . import log_attack
except ImportError:
    import sys
    from pathlib import Path
    _tests_dir = Path(__file__).resolve().parent.parent
    if str(_tests_dir) not in sys.path:
        sys.path.insert(0, str(_tests_dir))
    from attack_simulator import log_attack


def run_beacon(target: str = "192.168.17.1", port: int = 8443,
               interval: float = 30.0, count: int = 6,
               payload: bytes = b"\x16\x03\x01\x00\x20" + b"\x00" * 32) -> float:
    """Simulate C2 beaconing with periodic connections at fixed intervals.

    Sends count connections at the exact interval, with minimal jitter.
    The payload mimics a TLS ClientHello header.
    The BeaconingDetector should trigger when connection count >= 5
    and jitter < 20% in a 5-minute window.
    """
    start = time.time()
    for i in range(count):
        conn_start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((target, port))
            # Send small payload resembling TLS ClientHello
            sock.sendall(payload)
            # Read response (honeypot banner)
            try:
                sock.recv(1024)
            except socket.timeout:
                pass
            sock.close()
        except Exception as e:
            print(f"[beacon] Connection {i+1}/{count} failed: {e}")

        elapsed = time.time() - conn_start
        remaining = interval - elapsed
        if remaining > 0 and i < count - 1:
            time.sleep(remaining)

    duration = time.time() - start
    log_attack(
        attack_id=f"beacon-{int(start)}",
        attack_type="c2_beaconing",
        target=f"{target}:{port}",
        duration=duration,
        extra={
            "connections": count,
            "interval_s": interval,
            "expected_jitter": 0,
        },
    )
    return duration


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="192.168.17.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--interval", type=float, default=30.0)
    p.add_argument("--count", type=int, default=6)
    args = p.parse_args()
    run_beacon(args.target, args.port, args.interval, args.count)
