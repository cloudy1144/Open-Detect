"""Health check and metrics collection for the realtime detection pipeline.

Design: file-based health check (no HTTP dependency).
- health file: JSON on disk updated every N seconds with system status.
- Metrics: counters and histograms for throughput, latency, errors.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ============================================================
# Metrics
# ============================================================

@dataclass
class MetricsSnapshot:
    """Point-in-time metrics values."""
    flows_total: int = 0
    flows_abnormal: int = 0
    models_inference_count: int = 0
    models_inference_errors: int = 0
    models_inference_latency_ms_sum: float = 0.0
    models_inference_latency_ms_max: float = 0.0
    capture_packets_total: int = 0
    correlation_alerts_total: int = 0
    uptime_seconds: float = 0.0
    flow_manager_current_flows: int = 0
    alert_manager_current_alerts: int = 0


class MetricsCollector:
    """Thread-safe metrics collector with counters and timing."""

    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = time.time()

        # Counters
        self.flows_total = 0
        self.flows_abnormal = 0
        self.inference_count = 0
        self.inference_errors = 0
        self.capture_packets = 0
        self.correlation_alerts = 0

        # Latency
        self.inference_latency_ms_sum = 0.0
        self.inference_latency_ms_max = 0.0

    # ---- Counter increments ----
    def inc_flows_total(self, n: int = 1) -> None:
        with self._lock:
            self.flows_total += n

    def inc_flows_abnormal(self, n: int = 1) -> None:
        with self._lock:
            self.flows_abnormal += n

    def inc_inference_count(self, n: int = 1) -> None:
        with self._lock:
            self.inference_count += n

    def inc_inference_errors(self, n: int = 1) -> None:
        with self._lock:
            self.inference_errors += n

    def inc_capture_packets(self, n: int = 1) -> None:
        with self._lock:
            self.capture_packets += n

    def inc_correlation_alerts(self, n: int = 1) -> None:
        with self._lock:
            self.correlation_alerts += n

    def record_inference_latency_ms(self, latency_ms: float) -> None:
        with self._lock:
            self.inference_latency_ms_sum += latency_ms
            if latency_ms > self.inference_latency_ms_max:
                self.inference_latency_ms_max = latency_ms

    # ---- Snapshot ----
    def snapshot(self, flow_count: int = 0, alert_count: int = 0) -> MetricsSnapshot:
        with self._lock:
            elapsed = time.time() - self._start_time
            total = self.inference_count
            avg_ms = self.inference_latency_ms_sum / total if total > 0 else 0.0
            return MetricsSnapshot(
                flows_total=self.flows_total,
                flows_abnormal=self.flows_abnormal,
                models_inference_count=self.inference_count,
                models_inference_errors=self.inference_errors,
                models_inference_latency_ms_sum=round(self.inference_latency_ms_sum, 2),
                models_inference_latency_ms_max=round(self.inference_latency_ms_max, 2),
                capture_packets_total=self.capture_packets,
                correlation_alerts_total=self.correlation_alerts,
                uptime_seconds=round(elapsed, 1),
                flow_manager_current_flows=flow_count,
                alert_manager_current_alerts=alert_count,
            )


# ============================================================
# Health Check
# ============================================================

@dataclass
class HealthConfig:
    health_file: str = "./health.json"
    update_interval_seconds: int = 10


class HealthChecker:
    """Periodically updates a health file with system status.

    Usage:
        checker = HealthChecker(
            get_status=lambda: {"flow_count": 42, "alerts": 0},
            config=HealthConfig(health_file="./health.json"),
        )
        checker.start()
        # ... system runs ...
        checker.stop()
    """

    def __init__(
        self,
        get_status: Callable[[], dict[str, Any]],
        get_metrics: Callable[[], MetricsSnapshot] | None = None,
        config: HealthConfig | None = None,
    ):
        self._get_status = get_status
        self._get_metrics = get_metrics
        self.config = config or HealthConfig()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def health_file(self) -> str:
        return self.config.health_file

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        os.makedirs(os.path.dirname(self.health_file) or ".", exist_ok=True)

        def _loop():
            while not self._stop_event.wait(self.config.update_interval_seconds):
                try:
                    status = self._get_status()
                    status["timestamp"] = time.time()
                    status["healthy"] = True

                    if self._get_metrics:
                        m = self._get_metrics()
                        status["metrics"] = {
                            "flows_total": m.flows_total,
                            "flows_abnormal": m.flows_abnormal,
                            "inference_count": m.models_inference_count,
                            "inference_errors": m.models_inference_errors,
                            "inference_avg_ms": round(
                                m.models_inference_latency_ms_sum / m.models_inference_count, 2
                            ) if m.models_inference_count else 0,
                            "correlation_alerts": m.correlation_alerts_total,
                            "uptime_seconds": m.uptime_seconds,
                            "current_flows": m.flow_manager_current_flows,
                            "current_alerts": m.alert_manager_current_alerts,
                        }

                    tmp_path = self.health_file + ".tmp"
                    with open(tmp_path, "w") as f:
                        json.dump(status, f, default=str)
                    os.replace(tmp_path, self.health_file)
                except Exception:
                    pass

        self._stop_event.clear()
        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)


def read_health(health_file: str = "./health.json") -> dict[str, Any] | None:
    """Read the current health status from file."""
    try:
        with open(health_file) as f:
            return json.load(f)
    except Exception:
        return None
