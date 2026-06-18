"""Flow data structures and in-memory flow lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time
from typing import Any, Optional

import numpy as np


@dataclass
class FlowData:
    """Unified flow record handed off between teammate 1, 2, and 3."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float
    packets_data: list[bytes]
    gray_img: Optional[np.ndarray] = None
    inference_result: Optional[dict[str, Any]] = None
    is_abnormal: bool = False
    processed_at: Optional[float] = None
    export_path: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class FlowManager:
    """Thread-safe flow store with duplicate suppression and expiry cleanup."""

    def __init__(self, expire_minutes: int = 5, cooldown_seconds: int = 60,
                 cleanup_interval_seconds: int = 30, auto_start_cleaner: bool = True):
        self.flow_storage: dict[str, FlowData] = {}
        self.expire_delta = expire_minutes * 60
        self.cooldown_seconds = cooldown_seconds
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self._clean_thread: Optional[threading.Thread] = None

        if auto_start_cleaner:
            self.start_cleaner()

    def start_cleaner(self) -> None:
        """Start the background cleaner thread once."""

        if self._clean_thread and self._clean_thread.is_alive():
            return

        def clean_expired_flows() -> None:
            while not self._stop_event.wait(self.cleanup_interval_seconds):
                self.cleanup_expired()

        self._clean_thread = threading.Thread(target=clean_expired_flows, daemon=True)
        self._clean_thread.start()

    def stop_cleaner(self) -> None:
        """Stop the background cleaner thread."""

        self._stop_event.set()

    def add_flow(self, flow: FlowData) -> FlowData:
        """Insert or replace a flow record."""

        with self.lock:
            self.flow_storage[flow.flow_id] = flow
            return flow

    def mark_processed(self, flow_id: str, inference_result: dict[str, Any], is_abnormal: bool = False, export_path: Optional[str] = None) -> None:
        """Store processing results for an existing flow."""

        with self.lock:
            flow = self.flow_storage.get(flow_id)
            if flow is None:
                return
            flow.inference_result = inference_result
            flow.is_abnormal = is_abnormal
            flow.processed_at = time.time()
            flow.export_path = export_path

    def get_flow(self, flow_id: str) -> Optional[FlowData]:
        """Return a single flow by id."""

        with self.lock:
            return self.flow_storage.get(flow_id)

    def get_all_flows(self) -> list[FlowData]:
        """Return all currently stored flows."""

        with self.lock:
            return list(self.flow_storage.values())

    def is_flow_processed(self, flow_id: str) -> bool:
        """Check whether a flow already has inference results within cooldown window."""

        with self.lock:
            flow = self.flow_storage.get(flow_id)
            if flow is None or flow.processed_at is None:
                return False
            return (time.time() - flow.processed_at) < self.cooldown_seconds

    def cleanup_expired(self) -> int:
        """Remove stale flows and return the number removed."""

        with self.lock:
            now = time.time()
            expired_ids = [
                flow_id for flow_id, flow in self.flow_storage.items()
                if now - flow.timestamp > self.expire_delta
            ]
            for flow_id in expired_ids:
                self.flow_storage.pop(flow_id, None)
            return len(expired_ids)
