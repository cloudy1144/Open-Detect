"""PCAP replay for offline malware/normal traffic testing."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

try:
    from . import log_attack
except ImportError:
    import sys
    from pathlib import Path
    _tests_dir = Path(__file__).resolve().parent.parent
    if str(_tests_dir) not in sys.path:
        sys.path.insert(0, str(_tests_dir))
    from attack_simulator import log_attack

# Look for PCAP files in tests/pcaps/ directory
PCAP_DIR = Path(__file__).resolve().parent.parent / "pcaps"


def run_replay(pcap_type: str, target: str = "192.168.17.1", iface: str = "eth0") -> float:
    """Replay a PCAP file matching the given type.

    Args:
        pcap_type: One of 'known_malware', 'unknown_attack', 'normal', 'tls13'
        target: Destination IP (for display only — tcpreplay sends as-is)
        iface: Network interface to replay on

    Returns the duration in seconds.

    Falls back to generating synthetic traffic if tcpreplay or PCAP not available.
    """
    mapping = {
        "known_malware": "malware_sample.pcap",
        "unknown_attack": "unknown_attack.pcap",
        "normal": "normal_traffic.pcap",
        "tls13": "tls13_encrypted.pcap",
    }

    filename = mapping.get(pcap_type)
    if not filename:
        raise ValueError(f"Unknown pcap_type: {pcap_type}")

    pcap_path = PCAP_DIR / filename

    start = time.time()

    if pcap_path.exists():
        # Use tcpreplay if available
        try:
            subprocess.run(
                ["tcpreplay", "--intf1", iface, "--topspeed", str(pcap_path)],
                timeout=30, capture_output=True,
            )
            duration = time.time() - start
        except FileNotFoundError:
            print(f"[replay] tcpreplay not found — generating synthetic {pcap_type} traffic")
            duration = _generate_synthetic(pcap_type, target)
        except subprocess.TimeoutExpired:
            duration = 30.0
    else:
        print(f"[replay] PCAP {pcap_path} not found — generating synthetic {pcap_type} traffic")
        duration = _generate_synthetic(pcap_type, target)

    log_attack(
        attack_id=f"replay-{pcap_type}-{int(start)}",
        attack_type=f"pcap_replay_{pcap_type}",
        target=target,
        duration=duration,
        extra={"pcap_file": filename, "synthetic": not pcap_path.exists()},
    )
    return duration


def _generate_synthetic(pcap_type: str, target: str) -> float:
    """Generate synthetic traffic that simulates the PCAP content."""
    import socket
    import random
    import time as _time

    start = _time.time()

    if pcap_type == "known_malware":
        # Simulate malware C2: repeated connections with distinctive payload
        payload = bytes([0x00, 0x04, 0x00, 0x01]) + bytes(random.randint(0, 255) for _ in range(60))
        for _ in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, 8443))
                s.sendall(payload)
                s.close()
            except Exception:
                pass
            _time.sleep(0.5)

    elif pcap_type == "unknown_attack":
        # Simulate unknown/novel attack pattern: random high-entropy data
        for _ in range(8):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, 3307))
                # Send random noise (unlike any known protocol)
                s.sendall(bytes(random.randint(0, 255) for _ in range(random.randint(200, 800))))
                s.close()
            except Exception:
                pass
            _time.sleep(0.3)

    elif pcap_type == "normal":
        # Simulate normal HTTP/DNS traffic
        for _ in range(15):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, 8080))
                s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                s.recv(1024)
                s.close()
            except Exception:
                pass
            _time.sleep(0.2)

    elif pcap_type == "tls13":
        # Simulate TLS 1.3 handshake payload
        tls13_client_hello = (
            b"\x16\x03\x01\x00\xd0"  # TLS record: handshake, TLS 1.0 (for compat)
            b"\x01\x00\x00\xcc"
            b"\x03\x04"  # TLS 1.3
            + bytes(random.randint(0, 255) for _ in range(32))  # random
            + b"\x00" + bytes(random.randint(0, 255) for _ in range(32))
            + b"\x00\x02\x13\x01"  # cipher suite: TLS_AES_128_GCM_SHA256
            + b"\x01\x00\x00\x8b"
        )
        for _ in range(6):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, 8443))
                s.sendall(tls13_client_hello)
                s.close()
            except Exception:
                pass
            _time.sleep(0.5)

    return _time.time() - start


def generate_sample_pcaps(output_dir: Path | None = None) -> dict[str, Path]:
    """Generate sample PCAP files for testing when real PCAPs unavailable."""
    if output_dir is None:
        output_dir = PCAP_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except ImportError:
        print("[replay] Scapy not available — skipping sample PCAP generation")
        return {}

    files = {}
    base_ip_src = "10.0.0.100"

    # Malware sample — repeated C2 communication pattern
    pkts = []
    for i in range(20):
        pkts.append(
            Ether() / IP(src=base_ip_src, dst="10.0.1.50") /
            TCP(sport=40000 + i, dport=443, flags="PA") /
            Raw(load=b"\x00\x04\x00\x01\x00\x00\x00\x10" + bytes([i] * 40))
        )
    path = output_dir / "malware_sample.pcap"
    wrpcap(str(path), pkts)
    files["known_malware"] = path

    # Unknown attack — high-entropy payloads
    import random as _r
    pkts = []
    for i in range(15):
        pkts.append(
            Ether() / IP(src=base_ip_src, dst="10.0.1.50") /
            TCP(sport=50000 + i, dport=3307, flags="PA") /
            Raw(load=bytes(_r.randint(0, 255) for _ in range(300)))
        )
    path = output_dir / "unknown_attack.pcap"
    wrpcap(str(path), pkts)
    files["unknown_attack"] = path

    # Normal traffic — HTTP requests
    pkts = []
    for i in range(30):
        pkts.append(
            Ether() / IP(src=base_ip_src, dst="10.0.1.50") /
            TCP(sport=30000 + i, dport=80, flags="PA") /
            Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
    path = output_dir / "normal_traffic.pcap"
    wrpcap(str(path), pkts)
    files["normal"] = path

    # TLS 1.3 — simulated encrypted C2
    pkts = []
    for i in range(10):
        pkts.append(
            Ether() / IP(src=base_ip_src, dst="10.0.1.50") /
            TCP(sport=60000 + i, dport=8443, flags="PA") /
            Raw(load=b"\x16\x03\x01" + bytes([0, 100]) +
                b"\x01\x00\x00\x96\x03\x04" + bytes(_r.randint(0, 255) for _ in range(50)))
        )
    path = output_dir / "tls13_encrypted.pcap"
    wrpcap(str(path), pkts)
    files["tls13"] = path

    print(f"[replay] Generated {len(files)} sample PCAP files in {output_dir}")
    return files


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--type", choices=["known_malware", "unknown_attack", "normal", "tls13", "generate"],
                   default="normal")
    p.add_argument("--target", default="192.168.17.1")
    args = p.parse_args()

    if args.type == "generate":
        generate_sample_pcaps()
    else:
        run_replay(args.type, args.target)
