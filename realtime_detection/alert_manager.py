"""Alert record management and callback dispatch."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Optional

from .flow_manager import FlowData


@dataclass
class Alert:
    """Structured alert message used by the realtime detection chain."""

    alert_id: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    alert_level: str
    attack_type: str
    timestamp: float
    class_name: str
    confidence: float
    kl_distance: float
    extra: dict[str, Any]


class AlertManager:
    """Store and publish alerts in a thread-safe way."""

    def __init__(self):
        self.alert_history: list[Alert] = []
        self.lock = threading.Lock()
        self.alert_callback: Optional[Callable[[Alert], None]] = None

    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a downstream consumer, such as a Streamlit view."""

        self.alert_callback = callback

    def trigger_alert(self, flow: FlowData, inference_result: dict[str, Any]) -> Optional[Alert]:
        """Create and store an alert if the flow is abnormal."""

        if not inference_result.get("is_abnormal", False):
            return None

        attack_type = inference_result.get("attack_type", "unknown_attack")
        alert_level = "CRITICAL" if attack_type == "known_attack" else "WARNING"
        alert = Alert(
            alert_id=f"{flow.flow_id}-{int(time.time() * 1000)}",
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            alert_level=alert_level,
            attack_type=attack_type,
            timestamp=time.time(),
            class_name=inference_result.get("class_name", "Unknown Attack"),
            confidence=float(inference_result.get("confidence", 0.0)),
            kl_distance=float(inference_result.get("distance", 0.0)),
            extra={
                "origin": inference_result.get("origin", "unknown"),
                "is_unknown": inference_result.get("is_unknown", True),
            },
        )

        with self.lock:
            self.alert_history.append(alert)

        if self.alert_callback:
            self.alert_callback(alert)

        return alert

    def get_alert_history(self, start_time: float | None = None, end_time: float | None = None) -> list[Alert]:
        """Return stored alerts with optional time filtering."""

        with self.lock:
            alerts = list(self.alert_history)

        if start_time is not None:
            alerts = [alert for alert in alerts if alert.timestamp >= start_time]
        if end_time is not None:
            alerts = [alert for alert in alerts if alert.timestamp <= end_time]
        return alerts
