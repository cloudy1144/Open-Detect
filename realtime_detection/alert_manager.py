"""Alert record management with multi-callback dispatch and SQLite persistence."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
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
    """Store and publish alerts in a thread-safe way.

    Supports multiple callbacks (visualization + SIEM + logging simultaneously)
    and optional SQLite persistence for crash-safe alert storage.
    """

    def __init__(self, db_path: str | None = None):
        self.alert_history: list[Alert] = []
        self.alert_callbacks: list[Callable[[Alert], None]] = []
        self.lock = threading.Lock()
        self.db_path = db_path
        self._db_conn: Optional[sqlite3.Connection] = None
        if self.db_path:
            self._init_db()

    # ── SQLite persistence ──────────────────────────────────────────────

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._db_conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id    TEXT PRIMARY KEY,
                flow_id     TEXT,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                alert_level TEXT,
                attack_type TEXT,
                timestamp   REAL,
                class_name  TEXT,
                confidence  REAL,
                kl_distance REAL,
                extra       TEXT
            )
        """)
        self._db_conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
        self._db_conn.commit()

    def _insert_alert(self, alert: Alert) -> None:
        if not self._db_conn:
            return
        self._db_conn.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                alert.alert_id,
                alert.flow_id,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.alert_level,
                alert.attack_type,
                alert.timestamp,
                alert.class_name,
                alert.confidence,
                alert.kl_distance,
                json.dumps(alert.extra, default=str),
            ),
        )
        self._db_conn.commit()

    def _query_alerts(self, start_time: float | None, end_time: float | None, limit: int = 500) -> list[Alert]:
        if not self._db_conn:
            return []
        conditions = []
        params: list = []
        if start_time is not None:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time is not None:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = self._db_conn.execute(
            f"SELECT * FROM alerts{where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [
            Alert(
                alert_id=r[0], flow_id=r[1], src_ip=r[2], dst_ip=r[3],
                src_port=r[4], dst_port=r[5], alert_level=r[6], attack_type=r[7],
                timestamp=r[8], class_name=r[9], confidence=r[10], kl_distance=r[11],
                extra=json.loads(r[12]) if r[12] else {},
            )
            for r in rows
        ]

    # ── Callback registration ───────────────────────────────────────────

    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register a downstream consumer (visualization, SIEM, logging etc.).

        Multiple callbacks are supported — each receives every alert.
        """
        self.alert_callbacks.append(callback)

    # ── Alert creation ──────────────────────────────────────────────────

    def trigger_alert(self, flow: FlowData, inference_result: dict[str, Any]) -> Optional[Alert]:
        """Create and store an alert if the flow is abnormal.

        Uses the alert_level computed by model_adapter (CRITICAL/WARNING/INFO).
        Only creates alerts for traffic classified as abnormal (known_malware,
        unknown_attack, suspicious_tool).
        """
        if not inference_result.get("is_abnormal", False):
            return None

        attack_type = inference_result.get("attack_type", "unknown_attack")
        alert_level = inference_result.get("alert_level", "WARNING")
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
                "commit_ratio": inference_result.get("commit_ratio"),
                "bg_distance": inference_result.get("bg_distance"),
                "recon_error": inference_result.get("recon_error"),
                "protocol": flow.metadata.get("protocol", {}),
            },
        )

        with self.lock:
            self.alert_history.append(alert)
            if self.db_path:
                try:
                    self._insert_alert(alert)
                except Exception:
                    pass  # non-critical

        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    # ── Query ───────────────────────────────────────────────────────────

    def trigger_correlation_alert(self, alert: Any) -> None:
        """Accept a correlation alert (beaconing/scanning/bidir) for unified query."""
        # CorrelationAlert is a different type — store as a dict in extra
        alert_dict = {
            "alert_id": f"corr-{getattr(alert, 'alert_id', '?')}-{int(time.time()*1000)}",
            "flow_id": "correlation",
            "src_ip": getattr(alert, "src_ip", ""),
            "dst_ip": "-",
            "src_port": 0,
            "dst_port": 0,
            "alert_level": getattr(alert, "alert_level", "WARNING"),
            "attack_type": getattr(alert, "alert_type", "correlation"),
            "timestamp": getattr(alert, "timestamp", time.time()),
            "class_name": "",
            "confidence": 0.0,
            "kl_distance": 0.0,
            "extra": {
                "description": getattr(alert, "description", ""),
                "evidence": getattr(alert, "evidence", {}),
                "source": "correlation_engine",
            },
        }
        try:
            a = Alert(**alert_dict)
            with self.lock:
                self.alert_history.append(a)
                if self.db_path and self._db_conn:
                    self._insert_alert(a)
            for cb in self.alert_callbacks:
                try:
                    cb(a)
                except Exception:
                    pass
        except Exception:
            pass

    def get_alert_history(
        self, start_time: float | None = None, end_time: float | None = None
    ) -> list[Alert]:
        """Return stored alerts with optional time filtering.

        Prefers SQLite if persistence is enabled (survives restart),
        falls back to in-memory list.
        """
        if self.db_path:
            return self._query_alerts(start_time, end_time)

        with self.lock:
            alerts = list(self.alert_history)
        if start_time is not None:
            alerts = [a for a in alerts if a.timestamp >= start_time]
        if end_time is not None:
            alerts = [a for a in alerts if a.timestamp <= end_time]
        return alerts
