"""
pytest fixtures for Open-Detect automated testing.

Manages:
  - Honeypot lifecycle (start/stop background process)
  - DetectionPipeline instance with direct inference
  - Attack orchestration and alert collection
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import sqlite3
import threading
import time
from pathlib import Path

import pytest

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from realtime_detection.flow_manager import FlowData
from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.preprocess import build_gray_image

TEST_DIR = Path(__file__).resolve().parent
ALERTS_DB = TEST_DIR / "alerts.db"
HEALTH_FILE = TEST_DIR / "health.json"
ATTACK_LOG = TEST_DIR / "attack_log.jsonl"


# ── Honeypot Fixture ───────────────────────────────────────────────

@pytest.fixture(scope="session")
def honeypot():
    """Start honeypot as a background process for the test session."""
    hp_script = TEST_DIR / "honeypot.py"
    proc = subprocess.Popen(
        [sys.executable, str(hp_script)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(2)  # wait for listeners to bind

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ── Pipeline Fixture ────────────────────────────────────────────────

@pytest.fixture(scope="session")
def pipeline():
    """Create a DetectionPipeline for direct inference testing.

    Uses CPU device (no GPU in CI), with health checker enabled.
    """
    # Clean previous test outputs
    for f in [ALERTS_DB, HEALTH_FILE, ATTACK_LOG]:
        if f.exists():
            f.unlink()

    pipe = DetectionPipeline(
        model_path=str(PROJECT_ROOT / "save_model" / "mixed_44_split_0.pt"),
        threshold=2.24,
        top_k=1,
        device="cpu",
        db_path=str(ALERTS_DB),
        enable_health=True,
        enable_correlation=True,
        enable_export=False,
    )
    yield pipe
    pipe.stop()
    # Remove SQLite WAL files
    for f in [ALERTS_DB, str(ALERTS_DB) + "-wal", str(ALERTS_DB) + "-shm"]:
        p = Path(f)
        if p.exists():
            p.unlink()


# ── Alert Helpers ───────────────────────────────────────────────────

def get_alerts(db_path: str | None = None) -> list[dict]:
    """Read all alerts from the SQLite database."""
    db = db_path or str(ALERTS_DB)
    if not Path(db).exists():
        return []
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_health(file_path: str | None = None) -> dict:
    """Read health.json."""
    fp = file_path or str(HEALTH_FILE)
    try:
        with open(fp) as f:
            return json.load(f)
    except Exception:
        return {}


def get_attack_log(file_path: str | None = None) -> list[dict]:
    """Read attack_log.jsonl."""
    fp = file_path or str(ATTACK_LOG)
    if not Path(fp).exists():
        return []
    records = []
    with open(fp) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


# ── Flow Construction Helpers ───────────────────────────────────────

def make_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
              protocol: str, payloads: list[bytes]) -> FlowData:
    """Build a FlowData from raw packet payloads."""
    return FlowData(
        flow_id=f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{int(time.time()*1000)}",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol,
        timestamp=time.time(),
        packets_data=payloads,
        metadata={"source": "pytest"},
    )


def feed_pipeline(pipeline: DetectionPipeline, flow: FlowData) -> FlowData:
    """Feed a flow through the pipeline and return the processed result."""
    flow.gray_img = build_gray_image(flow.packets_data)
    return pipeline.process_captured_flow(flow)


# ── Dashboard Flask Client Fixture ──────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """Create a Flask test client for the dashboard app."""
    from tests.dashboard.app import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
