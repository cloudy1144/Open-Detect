"""Multi-flow correlation analysis for detecting behavioral anomalies.

Detects patterns that are invisible when analyzing single flows:
  - C2 Beaconing: periodic connections at regular intervals
  - Port Scanning: single source hitting many unique destinations/ports
  - Data Exfiltration: sustained high-volume outbound traffic
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Optional

import numpy as np

from .flow_manager import FlowData
from .logger import get_logger

logger = get_logger()


# ============================================================
# Configuration
# ============================================================
@dataclass
class CorrelationConfig:
    # Beaconing detection
    beacon_window_seconds: int = 300           # 观察窗口 (5 minutes)
    beacon_min_connections: int = 5             # 最少连接数才触发检测
    beacon_max_jitter_ratio: float = 0.2        # 间隔抖动 < 20% 均值 → beaconing
    beacon_min_interval_seconds: float = 1.0    # 最小间隔, 排除 burst

    # Scanning detection
    scan_window_seconds: int = 60               # 观察窗口 (1 minute)
    scan_unique_dst_threshold: int = 10         # 目标 IP 数 ≥ 10  → 扫描
    scan_unique_port_threshold: int = 20        # 目标端口数 ≥ 20 → 端口扫描

    # Data exfiltration
    exfil_window_seconds: int = 300             # 观察窗口 (5 minutes)
    exfil_volume_bytes: int = 10 * 1024 * 1024  # 10MB 阈值

    # Bidirectional pairing
    bidirectional_window_seconds: int = 60      # pair (A→B) with (B→A) within this window

    # Cleanup
    stale_window_multiplier: float = 3.0        # 超过 N 倍窗口没有新数据则清理


# ============================================================
# Correlation Events
# ============================================================
@dataclass
class CorrelationAlert:
    alert_id: str
    alert_type: str                  # "beaconing" | "scanning" | "exfiltration"
    src_ip: str
    description: str
    evidence: dict[str, Any]         # 证据详情
    timestamp: float
    alert_level: str = "WARNING"


# ============================================================
# Beaconing Detector
# ============================================================
class BeaconingDetector:
    """Detect periodic C2 beaconing by analyzing inter-connection intervals."""

    def __init__(self, config: CorrelationConfig):
        self.config = config
        # src_ip -> dst_ip -> list[timestamp]
        self._history: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        self._lock = threading.Lock()

    def feed(self, flow: FlowData) -> Optional[CorrelationAlert]:
        with self._lock:
            src_key = flow.src_ip
            dst_key = flow.dst_ip
            self._history[src_key][dst_key].append(flow.timestamp)
            return self._check_beaconing(src_key, dst_key)

    def _check_beaconing(self, src_ip: str, dst_ip: str) -> Optional[CorrelationAlert]:
        timestamps = self._history[src_ip][dst_ip]
        cutoff = time.time() - self.config.beacon_window_seconds
        timestamps = [t for t in timestamps if t >= cutoff]
        self._history[src_ip][dst_ip] = timestamps

        if len(timestamps) < self.config.beacon_min_connections:
            return None

        timestamps.sort()
        intervals = np.diff(timestamps)

        # Filter out bursts (sub-second intervals)
        intervals = intervals[intervals >= self.config.beacon_min_interval_seconds]
        if len(intervals) < 2:
            return None

        mean_interval = float(np.mean(intervals))
        if mean_interval == 0:
            return None

        std_interval = float(np.std(intervals))
        jitter = std_interval / mean_interval

        if jitter < self.config.beacon_max_jitter_ratio:
            return CorrelationAlert(
                alert_id=f"beacon-{src_ip}-{dst_ip}-{int(time.time())}",
                alert_type="beaconing",
                src_ip=src_ip,
                description=(
                    f"C2 Beaconing detected: {src_ip} -> {dst_ip}, "
                    f"{len(timestamps)} connections in {self.config.beacon_window_seconds}s, "
                    f"interval={mean_interval:.1f}s ±{std_interval:.1f}s (jitter={jitter:.2%})"
                ),
                evidence={
                    "dst_ip": dst_ip,
                    "connection_count": len(timestamps),
                    "mean_interval": round(mean_interval, 2),
                    "std_interval": round(std_interval, 2),
                    "jitter_ratio": round(jitter, 4),
                    "window_seconds": self.config.beacon_window_seconds,
                },
                timestamp=time.time(),
                alert_level="WARNING",
            )
        return None

    def cleanup(self) -> int:
        removed = 0
        with self._lock:
            cutoff = time.time() - self.config.beacon_window_seconds * self.config.stale_window_multiplier
            empty_dsts = []
            for src_ip, dst_map in self._history.items():
                empty_ips = []
                for dst_ip, timestamps in dst_map.items():
                    self._history[src_ip][dst_ip] = [t for t in timestamps if t >= cutoff]
                    if not self._history[src_ip][dst_ip]:
                        empty_ips.append(dst_ip)
                        removed += 1
                for dst_ip in empty_ips:
                    del self._history[src_ip][dst_ip]
                if not self._history[src_ip]:
                    empty_dsts.append(src_ip)
            for src_ip in empty_dsts:
                del self._history[src_ip]
        return removed


# ============================================================
# Scanning Detector
# ============================================================
class ScanningDetector:
    """Detect port scans and lateral movement by tracking unique destinations."""

    def __init__(self, config: CorrelationConfig):
        self.config = config
        # src_ip -> set[dst_ip]
        self._dst_history: dict[str, set[str]] = defaultdict(set)
        # src_ip -> set[dst_port]
        self._port_history: dict[str, set[int]] = defaultdict(set)
        # src_ip -> list[(dst_ip, dst_port, timestamp)]
        self._detail_history: dict[str, list[tuple[str, int, float]]] = defaultdict(list)
        self._lock = threading.Lock()
        self._alerted: set[str] = set()  # 避免重复告警

    def feed(self, flow: FlowData) -> Optional[CorrelationAlert]:
        with self._lock:
            src_key = flow.src_ip
            self._dst_history[src_key].add(flow.dst_ip)
            self._port_history[src_key].add(flow.dst_port)
            self._detail_history[src_key].append((flow.dst_ip, flow.dst_port, flow.timestamp))

            cutoff = time.time() - self.config.scan_window_seconds
            self._detail_history[src_key] = [
                (d, p, t) for d, p, t in self._detail_history[src_key] if t >= cutoff
            ]
            # Rebuild sets from recent data only
            recent_dsts = set(d for d, _, _ in self._detail_history[src_key])
            recent_ports = set(p for _, p, _ in self._detail_history[src_key])
            self._dst_history[src_key] = recent_dsts
            self._port_history[src_key] = recent_ports

            alert = self._check_scanning(src_key)

            # Reset after alert to allow re-detection
            if alert:
                alert_key = f"{alert.alert_type}-{src_key}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    return alert
        return None

    def _check_scanning(self, src_ip: str) -> Optional[CorrelationAlert]:
        unique_dsts = len(self._dst_history[src_ip])
        unique_ports = len(self._port_history[src_ip])
        total_conns = len(self._detail_history[src_ip])

        if unique_dsts >= self.config.scan_unique_dst_threshold:
            return CorrelationAlert(
                alert_id=f"scan-{src_ip}-{int(time.time())}",
                alert_type="scanning",
                src_ip=src_ip,
                description=(
                    f"Host Scan detected: {src_ip} contacted {unique_dsts} unique IPs "
                    f"({total_conns} connections) in {self.config.scan_window_seconds}s"
                ),
                evidence={
                    "unique_dst_ips": unique_dsts,
                    "unique_ports": unique_ports,
                    "total_connections": total_conns,
                    "window_seconds": self.config.scan_window_seconds,
                },
                timestamp=time.time(),
                alert_level="WARNING",
            )

        if unique_ports >= self.config.scan_unique_port_threshold:
            return CorrelationAlert(
                alert_id=f"portscan-{src_ip}-{int(time.time())}",
                alert_type="scanning",
                src_ip=src_ip,
                description=(
                    f"Port Scan detected: {src_ip} contacted {unique_ports} unique ports "
                    f"({total_conns} connections) in {self.config.scan_window_seconds}s"
                ),
                evidence={
                    "unique_dst_ips": unique_dsts,
                    "unique_ports": unique_ports,
                    "total_connections": total_conns,
                    "window_seconds": self.config.scan_window_seconds,
                },
                timestamp=time.time(),
                alert_level="WARNING",
            )
        return None

    def cleanup(self) -> int:
        removed = 0
        with self._lock:
            cutoff = time.time() - self.config.scan_window_seconds * self.config.stale_window_multiplier
            empty_ips = []
            for src_ip in list(self._dst_history.keys()):
                self._detail_history[src_ip] = [
                    (d, p, t) for d, p, t in self._detail_history[src_ip] if t >= cutoff
                ]
                if not self._detail_history[src_ip]:
                    del self._dst_history[src_ip]
                    del self._port_history[src_ip]
                    del self._detail_history[src_ip]
                    empty_ips.append(src_ip)
                    removed += 1
        return removed


# ============================================================
# Main Correlation Engine
# ============================================================
class FlowCorrelationEngine:
    """Aggregate multi-flow detectors and emit correlation alerts."""

    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()
        self.beacon_detector = BeaconingDetector(self.config)
        self.scan_detector = ScanningDetector(self.config)
        self.bidir_pairer = BidirectionalPairer(
            window_seconds=getattr(self.config, 'bidirectional_window_seconds', 60)
        )

        self._alert_callbacks: list = []
        self._alert_history: list[CorrelationAlert] = []
        self._lock = threading.Lock()

        # Background cleanup
        self._stop_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None
        self._start_cleanup()

    def register_alert_callback(self, callback) -> None:
        self._alert_callbacks.append(callback)

    def feed_flow(self, flow: FlowData) -> list[CorrelationAlert]:
        """Feed a single flow and return any correlation alerts triggered."""
        alerts: list[CorrelationAlert] = []

        beacon_alert = self.beacon_detector.feed(flow)
        if beacon_alert:
            alerts.append(beacon_alert)

        scan_alert = self.scan_detector.feed(flow)
        if scan_alert:
            alerts.append(scan_alert)

        # Only pair post-inference (need inference results)
        if flow.inference_result:
            bidir_alert = self.bidir_pairer.feed(flow)
            if bidir_alert:
                alerts.append(bidir_alert)

        for alert in alerts:
            with self._lock:
                self._alert_history.append(alert)
            logger.warning(alert.description, alert_type=alert.alert_type)
            for cb in self._alert_callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass

        return alerts

    def get_alerts(self, start_time: float | None = None, end_time: float | None = None) -> list[CorrelationAlert]:
        with self._lock:
            alerts = list(self._alert_history)
        if start_time is not None:
            alerts = [a for a in alerts if a.timestamp >= start_time]
        if end_time is not None:
            alerts = [a for a in alerts if a.timestamp <= end_time]
        return alerts

    def snapshot(self) -> dict[str, Any]:
        return {
            "beaconing_alerts": sum(1 for a in self._alert_history if a.alert_type == "beaconing"),
            "scanning_alerts": sum(1 for a in self._alert_history if a.alert_type == "scanning"),
            "total_alerts": len(self._alert_history),
        }

    def _start_cleanup(self) -> None:
        def _cleanup_loop():
            while not self._stop_event.wait(120):
                b = self.beacon_detector.cleanup()
                s = self.scan_detector.cleanup()
                if b or s:
                    logger.debug(f"Correlation cleanup: beacon={b} scan={s}")

        self._cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def stop(self) -> None:
        self._stop_event.set()


# ============================================================
# Bidirectional Flow Pairer
# ============================================================
class BidirectionalPairer:
    """Pair (A→B) flow results with (B→A) flow results for the same TCP connection.

    In real traffic, a single TCP session generates two independent flow
    records (one per direction).  If one direction is classified as normal
    and the other as unknown, we want to surface that asymmetry as an
    alert because it may indicate protocol-level manipulation (e.g. a C2
    client that mimics normal traffic while the server sends backdoor
    commands).

    Pairs are matched by swapped 5-tuple: (src↔dst, src_port↔dst_port).
    """

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        # key = frozenset{(ip_a, port_a), (ip_b, port_b)}
        # value = list[FlowData]  (max 2 per key)
        self._pending: dict[frozenset, list[FlowData]] = {}
        self._lock = threading.Lock()

    def feed(self, flow: FlowData) -> Optional[CorrelationAlert]:
        """Feed a processed flow; returns alert if a pair with asymmetry is found."""
        with self._lock:
            self._expire_stale()

            a_key = (flow.src_ip, flow.src_port)
            b_key = (flow.dst_ip, flow.dst_port)
            pair_key = frozenset({a_key, b_key})

            if pair_key not in self._pending:
                self._pending[pair_key] = [flow]
                return None

            partner = self._pending[pair_key][0]
            del self._pending[pair_key]

        # We have both directions — check for asymmetry
        return self._check_asymmetry(partner, flow)

    def _check_asymmetry(self, flow_a: FlowData, flow_b: FlowData) -> Optional[CorrelationAlert]:
        ir_a = flow_a.inference_result or {}
        ir_b = flow_b.inference_result or {}

        a_abnormal = ir_a.get("is_abnormal", False)
        b_abnormal = ir_b.get("is_abnormal", False)
        a_class = ir_a.get("class_name", "?")
        b_class = ir_b.get("class_name", "?")

        # Only interesting if exactly one direction is abnormal
        if a_abnormal == b_abnormal:
            return None

        abnormal_flow = flow_a if a_abnormal else flow_b
        normal_flow = flow_b if a_abnormal else flow_a
        abnormal_ir = ir_a if a_abnormal else ir_b
        normal_ir = ir_b if a_abnormal else ir_a

        return CorrelationAlert(
            alert_id=f"bidir-{abnormal_flow.flow_id}-{int(time.time())}",
            alert_type="bidirectional_asymmetry",
            src_ip=abnormal_flow.src_ip,
            description=(
                f"Bidirectional asymmetry: {normal_flow.src_ip}:{normal_flow.src_port} "
                f"↔ {normal_flow.dst_ip}:{normal_flow.dst_port} — "
                f"one direction classified as {normal_ir.get('class_name','?')} "
                f"(normal), the other as {abnormal_ir.get('class_name','?')} "
                f"({abnormal_ir.get('attack_type','?')}, dist={abnormal_ir.get('distance','?')})"
            ),
            evidence={
                "normal_direction": {
                    "src": f"{normal_flow.src_ip}:{normal_flow.src_port}",
                    "dst": f"{normal_flow.dst_ip}:{normal_flow.dst_port}",
                    "class": normal_ir.get("class_name"),
                    "distance": normal_ir.get("distance"),
                },
                "abnormal_direction": {
                    "src": f"{abnormal_flow.src_ip}:{abnormal_flow.src_port}",
                    "dst": f"{abnormal_flow.dst_ip}:{abnormal_flow.dst_port}",
                    "class": abnormal_ir.get("class_name"),
                    "distance": abnormal_ir.get("distance"),
                    "attack_type": abnormal_ir.get("attack_type"),
                },
            },
            timestamp=time.time(),
            alert_level="WARNING",
        )

    def _expire_stale(self) -> None:
        cutoff = time.time() - self.window_seconds
        expired = [k for k, v in self._pending.items() if v and v[0].timestamp < cutoff]
        for k in expired:
            del self._pending[k]

    def cleanup(self) -> int:
        with self._lock:
            before = len(self._pending)
            self._expire_stale()
            return before - len(self._pending)
