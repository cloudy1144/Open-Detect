"""
Lightweight multi-service honeypot for testing Open-Detect.

Listens on multiple ports and logs all connections, acting as a realistic
attack surface for automated testing.
"""
from __future__ import annotations

import asyncio
import json
import signal
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class HoneypotConfig:
    """Configuration for honeypot services."""
    ssh_port: int = 2222          # mimic SSH (Cowrie-style)
    http_port: int = 8080         # mimic HTTP server
    ftp_port: int = 2121          # mimic FTP
    mysql_port: int = 3307        # mimic MySQL
    smtp_port: int = 2525          # mimic SMTP
    https_port: int = 8443        # mimic HTTPS/TLS
    log_file: str = "honeypot_connections.jsonl"
    banner: bool = True           # send service banners


class MultiServiceHoneypot:
    """Runs multiple TCP honeypot listeners concurrently."""

    def __init__(self, config: Optional[HoneypotConfig] = None):
        self.config = config or HoneypotConfig()
        self._servers: list[socket.socket] = []
        self._running = False
        self._conn_count = 0
        self._log_path = Path(self.config.log_file)
        self._log_fh = None

    def start(self) -> None:
        """Start all honeypot listeners in background threads."""
        import threading

        self._running = True
        self._log_fh = open(self._log_path, "a")

        services = [
            ("SSH", self.config.ssh_port, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"),
            ("HTTP", self.config.http_port, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"),
            ("FTP", self.config.ftp_port, "220 ProFTPD 1.3.5 Server ready\r\n"),
            ("MySQL", self.config.mysql_port, "\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36"),
            ("SMTP", self.config.smtp_port, "220 mail.example.com ESMTP Postfix\r\n"),
            ("HTTPS", self.config.https_port, ""),  # TLS — no plaintext banner
        ]

        self._threads = []
        for name, port, banner in services:
            t = threading.Thread(
                target=self._run_listener,
                args=(name, port, banner),
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        print(f"[honeypot] Started {len(services)} listeners on ports: "
              f"{', '.join(str(p) for _, p, _ in services)}")

    def _run_listener(self, name: str, port: int, banner: str) -> None:
        """Run a single TCP listener."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sock.settimeout(1.0)
        except OSError as e:
            print(f"[honeypot] WARN: cannot bind {name} on port {port}: {e}")
            return

        self._servers.append(sock)
        print(f"[honeypot] {name} listener on 0.0.0.0:{port}")

        while self._running:
            try:
                conn, addr = sock.accept()
                self._conn_count += 1
                ts = time.time()
                print(f"[honeypot] {name} connection #{self._conn_count} from {addr[0]}:{addr[1]}")

                # Send banner
                if banner:
                    try:
                        conn.sendall(banner.encode("utf-8", errors="replace") if isinstance(banner, str) else banner)
                    except Exception:
                        pass

                # Receive some data
                try:
                    conn.settimeout(3.0)
                    data = conn.recv(4096)
                except socket.timeout:
                    data = b""

                # Log connection
                self._log_connection(name, addr, ts, data)

                # Small response to keep connection alive briefly
                try:
                    if name == "HTTP":
                        conn.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                        )
                    elif name == "SSH":
                        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
                except Exception:
                    pass

                conn.close()

            except socket.timeout:
                continue
            except Exception:
                continue

    def _log_connection(self, name: str, addr: tuple, ts: float, data: bytes) -> None:
        record = {
            "ts": ts,
            "service": name,
            "src_ip": addr[0],
            "src_port": addr[1],
            "data_len": len(data),
            "data_hex": data[:64].hex() if data else "",
        }
        try:
            self._log_fh.write(json.dumps(record) + "\n")
            self._log_fh.flush()
        except Exception:
            pass

    def stop(self) -> None:
        """Stop all listeners."""
        self._running = False
        for sock in self._servers:
            try:
                sock.close()
            except Exception:
                pass
        if self._log_fh:
            self._log_fh.close()
        print(f"[honeypot] Stopped. Total connections: {self._conn_count}")

    @property
    def connection_count(self) -> int:
        return self._conn_count


def main():
    """Run honeypot standalone for manual testing."""
    config = HoneypotConfig()
    hp = MultiServiceHoneypot(config)

    def _shutdown(sig, frame):
        hp.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    hp.start()
    print("[honeypot] Running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hp.stop()


if __name__ == "__main__":
    main()
