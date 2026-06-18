"""Port scanning simulation — triggers scanning correlation alert."""
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


def run_port_scan(target: str = "127.0.0.1", start_port: int = 20,
                  end_port: int = 50, delay: float = 0.05) -> float:
    """SYN-like scan by attempting TCP connections to many ports in rapid succession.

    Sends a TCP SYN (via connect) to each port, then immediately closes.
    This simulates a horizontal port scan that should trigger the
    ScanningDetector when >= 20 unique ports are contacted within 60s.
    """
    start = time.time()
    ports_scanned = 0
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((target, port))
            sock.close()
            ports_scanned += 1
        except (ConnectionRefusedError, socket.timeout, OSError):
            # Connection refused is fine — the SYN was sent
            ports_scanned += 1
        time.sleep(delay)

    duration = time.time() - start
    log_attack(
        attack_id=f"scan-{int(start)}",
        attack_type="port_scan",
        target=target,
        duration=duration,
        extra={"ports_scanned": ports_scanned, "range": f"{start_port}-{end_port}"},
    )
    return duration


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--start-port", type=int, default=20)
    p.add_argument("--end-port", type=int, default=50)
    args = p.parse_args()
    d = run_port_scan(args.target, args.start_port, args.end_port)
    print(f"Port scan completed in {d:.1f}s")
