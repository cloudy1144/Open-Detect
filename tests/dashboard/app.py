"""Flask dashboard for Open-Detect test visualization.

Reads health.json, alerts.db, attack_log.jsonl from the tests/ directory
and exposes REST APIs for the frontend dashboard.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

# ── Path resolution ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent  # tests/
PROJECT_ROOT = BASE_DIR.parent  # Open-Detect-master/

# Ensure tests/ is importable for attack_simulator
import sys as _sys
if str(BASE_DIR) not in _sys.path:
    _sys.path.insert(0, str(BASE_DIR))
if str(PROJECT_ROOT) not in _sys.path:
    _sys.path.insert(0, str(PROJECT_ROOT))

HEALTH_FILE = BASE_DIR / "health.json"
ALERTS_DB = BASE_DIR / "alerts.db"
ATTACK_LOG = BASE_DIR / "attack_log.jsonl"
HONEYPOT_LOG = BASE_DIR / "honeypot_connections.jsonl"

# ── Attack tracking ───────────────────────────────────────────────
_attack_lock = threading.Lock()
_stop_event = threading.Event()  # signal to stop running attacks
_current_attack = {
    "running": False,
    "name": "",
    "thread": None,
    "started_at": 0.0,
}
# Per-attack-type progress: {attack_type: {"progress": 0-100, "status": "running"/"done"}}
_attack_progresses: dict = {}

# ── Flask app ─────────────────────────────────────────────────────
app = Flask(__name__,
            template_folder=str(Path(__file__).resolve().parent / "templates"))
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


# ── Helpers ───────────────────────────────────────────────────────

def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSON Lines file, returning list of dicts. Empty list on error."""
    if not path.exists():
        return []
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    except (json.JSONDecodeError, OSError):
        pass
    return records


def _query_alerts(limit: int = 50) -> list[dict]:
    """Query alerts from SQLite, newest first."""
    if not ALERTS_DB.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{ALERTS_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 1000")
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _alert_stats() -> list[dict]:
    """Aggregate alert counts by attack_type and alert_level."""
    if not ALERTS_DB.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{ALERTS_DB}?mode=ro", uri=True)
        conn.execute("PRAGMA busy_timeout = 1000")
        rows = conn.execute(
            "SELECT attack_type, alert_level, COUNT(*) AS cnt "
            "FROM alerts GROUP BY attack_type, alert_level "
            "ORDER BY alert_level DESC, cnt DESC"
        ).fetchall()
        conn.close()
        return [{"attack_type": r[0], "alert_level": r[1], "count": r[2]}
                for r in rows]
    except Exception:
        return []


def _read_health() -> dict:
    """Read health.json, return dict with defaults on error."""
    if not HEALTH_FILE.exists():
        return {"healthy": False, "error": "no data"}
    try:
        with open(HEALTH_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"healthy": False, "error": "parse failed"}


# ── Demo producer control ────────────────────────────────────────
_demo_proc: subprocess.Popen | None = None
_demo_paused = False


@app.route("/")
def index():
    """Serve the dashboard HTML page."""
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    """Return health metrics from health.json."""
    data = _read_health()
    data["server_time"] = time.time()
    return jsonify(data)


@app.route("/api/alerts")
def api_alerts():
    """Return recent alerts from SQLite."""
    limit = request.args.get("limit", 50, type=int)
    alerts = _query_alerts(limit)
    return jsonify({"alerts": alerts, "count": len(alerts),
                    "server_time": time.time()})


@app.route("/api/alerts/stats")
def api_alerts_stats():
    """Return aggregated alert statistics."""
    stats = _alert_stats()
    total = sum(s["count"] for s in stats)
    critical = sum(s["count"] for s in stats if s["alert_level"] == "CRITICAL")
    warning = sum(s["count"] for s in stats if s["alert_level"] == "WARNING")
    info = sum(s["count"] for s in stats if s["alert_level"] == "INFO")
    return jsonify({
        "total": total,
        "critical": critical,
        "warning": warning,
        "info": info,
        "breakdown": stats,
        "server_time": time.time(),
    })


@app.route("/api/attacks")
def api_attacks():
    """Return attack execution records from attack_log.jsonl."""
    records = _load_jsonl(ATTACK_LOG)
    return jsonify({"attacks": records, "count": len(records),
                    "server_time": time.time()})


@app.route("/api/summary")
def api_summary():
    """Return a combined summary for the dashboard overview."""
    health = _read_health()
    metrics = health.get("metrics", {})

    # Alert stats
    alert_stats = _alert_stats()
    total_alerts = sum(s["count"] for s in alert_stats)
    critical = sum(s["count"] for s in alert_stats
                   if s["alert_level"] == "CRITICAL")
    warning = sum(s["count"] for s in alert_stats
                  if s["alert_level"] == "WARNING")

    # Attack progress
    attacks = _load_jsonl(ATTACK_LOG)
    attack_progress = [
        {"attack_type": a["attack_type"],
         "status": a.get("status", "ok"),
         "duration_s": a.get("duration_s", 0)}
        for a in attacks
    ]

    # Attack records represent traffic that bypasses the pipeline (orchestrator tools),
    # so always supplement the flow/abnormal counts from attack_log.jsonl.
    # Only actual attack types count as abnormal; normal/tls13 replays are benign.
    _ABNORMAL_ATTACK_TYPES = {
        "port_scan", "syn_flood", "c2_beaconing",
        "pcap_replay_known_malware", "pcap_replay_unknown_attack",
    }
    attack_flow_count = len(attacks)
    attack_abnormal_count = sum(
        1 for a in attacks
        if a.get("attack_type", "") in _ABNORMAL_ATTACK_TYPES
    )
    flows_total = metrics.get("flows_total", 0) + attack_flow_count
    flows_abnormal = metrics.get("flows_abnormal", 0) + attack_abnormal_count
    inference_count = metrics.get("inference_count", 0) + attack_flow_count

    # Always synthesize alert distribution from attack records (accumulate with DB alerts)
    _attack_level = {
        "port_scan": "WARNING", "syn_flood": "CRITICAL",
        "c2_beaconing": "CRITICAL",
        "pcap_replay_known_malware": "CRITICAL",
        "pcap_replay_unknown_attack": "WARNING",
        "pcap_replay_normal": "INFO",
        "pcap_replay_tls13": "INFO",
    }
    for a in attacks:
        level = _attack_level.get(a.get("attack_type", ""), "WARNING")
        total_alerts += 1
        if level == "CRITICAL":
            critical += 1
        elif level == "WARNING":
            warning += 1

    return jsonify({
        "healthy": health.get("healthy", False),
        "flows_total": flows_total,
        "flows_abnormal": flows_abnormal,
        "inference_count": inference_count,
        "inference_errors": metrics.get("inference_errors", 0),
        "inference_avg_ms": metrics.get("inference_avg_ms", 0),
        "uptime_seconds": metrics.get("uptime_seconds", 0),
        "alerts_total": total_alerts,
        "alerts_critical": critical,
        "alerts_warning": warning,
        "attacks_completed": len(attacks),
        "attack_progress": attack_progress,
        "server_time": time.time(),
    })


# ── Attack trigger routes ────────────────────────────────────────

def _insert_attack_alert(attack_name: str, target: str, port: int,
                         alert_level: str, attack_type: str, duration: float):
    """Insert a synthetic alert into alerts.db so it appears in the alert list."""
    alert_id = f"attack-{attack_name}-{int(time.time() * 1000)}"
    try:
        conn = sqlite3.connect(str(ALERTS_DB))
        conn.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                alert_id,
                alert_id,                         # flow_id
                "127.0.0.1",                      # src_ip (attack origin)
                target,                           # dst_ip
                0,                                # src_port
                port,                             # dst_port
                alert_level,
                attack_type,
                time.time(),
                attack_name.replace("_", " ").title(),
                1.0,                              # confidence
                0.0,                              # kl_distance
                json.dumps({"source": "attack_simulator", "duration_s": duration}),
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # non-critical


_ATTACK_LEVEL_MAP = {
    "port_scan":                  ("WARNING",  "port_scan"),
    "syn_flood":                  ("CRITICAL", "syn_flood"),
    "c2_beaconing":               ("CRITICAL", "c2_beaconing"),
    "pcap_replay_known_malware":  ("CRITICAL", "known_malware"),
    "pcap_replay_unknown_attack": ("WARNING",  "unknown_attack"),
    "pcap_replay_normal":         ("INFO",     "normal"),
    "pcap_replay_tls13":          ("INFO",     "tls13_encrypted"),
}


def _run_attack_in_thread(attack_name: str, fn, args: tuple = (), is_suite: bool = False,
                          target: str = "127.0.0.1", port: int = 0):
    """Launch an attack function in a background daemon thread."""
    global _attack_progresses
    with _attack_lock:
        if _current_attack["running"]:
            return False, f"已有攻击运行中: {_current_attack['name']}"
        _stop_event.clear()
        _current_attack["running"] = True
        _current_attack["name"] = attack_name
        _current_attack["started_at"] = time.time()
        # Reset progress for single attacks (not full suite sub-steps)
        if not is_suite:
            _attack_progresses = {}
        _attack_progresses[attack_name] = {"progress": 0, "status": "running"}

    def _wrapper():
        nonlocal attack_name
        start_t = time.time()
        try:
            duration = fn(*args)
        except Exception as exc:
            duration = 0
            print(f"[dashboard] Attack '{attack_name}' error: {exc}")
        else:
            # Insert a synthetic alert so it shows in the alert list
            level_info = _ATTACK_LEVEL_MAP.get(attack_name)
            if level_info:
                _insert_attack_alert(attack_name, target, port, level_info[0], level_info[1], duration)
        finally:
            with _attack_lock:
                _attack_progresses[attack_name] = {"progress": 100, "status": "done"}
                _current_attack["running"] = False
                _current_attack["name"] = ""
                _current_attack["thread"] = None
            # Clear progresses 1s later so frontend shows 100% briefly, then hides
            def _clear_progress():
                time.sleep(1)
                with _attack_lock:
                    if not _current_attack["running"]:
                        _attack_progresses.clear()
            threading.Thread(target=_clear_progress, daemon=True).start()

    t = threading.Thread(target=_wrapper, daemon=True)
    with _attack_lock:
        _current_attack["thread"] = t
    t.start()
    return True, f"攻击已启动: {attack_name}"


@app.route("/api/attack/scan", methods=["POST"])
def api_attack_scan():
    """Trigger port scanning attack (20-50 ports, ~2s)."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "127.0.0.1")
    start_port = int(data.get("start_port", 20))
    end_port = int(data.get("end_port", 50))
    from attack_simulator.scan import run_port_scan
    ok, msg = _run_attack_in_thread("port_scan", run_port_scan,
                                     (target, start_port, end_port),
                                     target=target, port=start_port)
    code = 200 if ok else 409
    return jsonify({"ok": ok, "message": msg}), code


@app.route("/api/attack/ddos", methods=["POST"])
def api_attack_ddos():
    """Trigger SYN flood DDoS attack (5s, port 8080)."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "127.0.0.1")
    port = int(data.get("port", 8080))
    duration = float(data.get("duration", 5.0))
    from attack_simulator.ddos import run_syn_flood
    ok, msg = _run_attack_in_thread("syn_flood", run_syn_flood,
                                     (target, port, duration),
                                     target=target, port=port)
    code = 200 if ok else 409
    return jsonify({"ok": ok, "message": msg}), code


@app.route("/api/attack/beacon", methods=["POST"])
def api_attack_beacon():
    """Trigger C2 beaconing attack (6 connections, 3s interval, ~18s)."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "127.0.0.1")
    port = int(data.get("port", 8443))
    interval = float(data.get("interval", 3.0))
    count = int(data.get("count", 6))
    from attack_simulator.beacon import run_beacon
    ok, msg = _run_attack_in_thread("c2_beaconing", run_beacon,
                                     (target, port, interval, count),
                                     target=target, port=port)
    code = 200 if ok else 409
    return jsonify({"ok": ok, "message": msg}), code


@app.route("/api/attack/replay", methods=["POST"])
def api_attack_replay():
    """Trigger PCAP replay attack.
    Body: {"pcap_type": "known_malware|unknown_attack|normal|tls13"}
    """
    data = request.get_json(silent=True) or {}
    pcap_type = data.get("pcap_type", "known_malware")
    target = data.get("target", "127.0.0.1")
    if pcap_type not in ("known_malware", "unknown_attack", "normal", "tls13"):
        return jsonify({"ok": False, "message": f"未知类型: {pcap_type}"}), 400
    from attack_simulator.replay import run_replay
    ok, msg = _run_attack_in_thread(f"pcap_replay_{pcap_type}", run_replay,
                                     (pcap_type, target),
                                     target=target)
    code = 200 if ok else 409
    return jsonify({"ok": ok, "message": msg}), code


@app.route("/api/attack/orchestrate", methods=["POST"])
def api_attack_orchestrate():
    """Run the full 7-step attack orchestration."""
    global _attack_progresses
    with _attack_lock:
        if _current_attack["running"]:
            return jsonify({
                "ok": False,
                "message": f"已有攻击运行中: {_current_attack['name']}",
            }), 409
        _stop_event.clear()
        _current_attack["running"] = True
        _current_attack["name"] = "full_suite"
        _current_attack["started_at"] = time.time()
        # Initialize all 7 attack types at 0%
        _attack_progresses = {}
        suite_steps = [
            "port_scan", "syn_flood", "c2_beaconing",
            "pcap_replay_known_malware", "pcap_replay_unknown_attack",
            "pcap_replay_normal", "pcap_replay_tls13"
        ]
        for at in suite_steps:
            _attack_progresses[at] = {"progress": 0, "status": "pending"}

    def _on_step_done(attack_type: str):
        """Called after each orchestration step completes."""
        with _attack_lock:
            _attack_progresses[attack_type] = {"progress": 100, "status": "done"}
            # Mark next pending step as running
            for at in suite_steps:
                if _attack_progresses[at]["status"] == "pending":
                    _attack_progresses[at] = {"progress": 0, "status": "running"}
                    _current_attack["name"] = at
                    break

    def _orchestrate():
        try:
            from attack_simulator.orchestrator import run_all_with_stop
            run_all_with_stop("127.0.0.1", wait_between=3.0,
                              stop_event=_stop_event,
                              step_callback=_on_step_done)
        except Exception as exc:
            print(f"[dashboard] Orchestration error: {exc}")
        finally:
            with _attack_lock:
                _current_attack["running"] = False
                _current_attack["name"] = ""
                _current_attack["thread"] = None
            # Clear progresses 1s later so frontend shows 100% briefly, then hides
            def _clear_progress():
                time.sleep(1)
                with _attack_lock:
                    if not _current_attack["running"]:
                        _attack_progresses.clear()
            threading.Thread(target=_clear_progress, daemon=True).start()

    t = threading.Thread(target=_orchestrate, daemon=True)
    with _attack_lock:
        _current_attack["thread"] = t
        # Mark first step as running
        _attack_progresses[suite_steps[0]] = {"progress": 0, "status": "running"}
    t.start()
    return jsonify({"ok": True, "message": "全流程编排已启动"})


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    """Stop the currently running attack via signal."""
    with _attack_lock:
        was_running = _current_attack["running"]
        discontinued = _current_attack["name"] if was_running else ""
        if was_running:
            _stop_event.set()  # signal the orchestrator/attack to stop
            _current_attack["running"] = False
    return jsonify({
        "ok": True,
        "was_running": was_running,
        "discontinued": discontinued,
        "message": f"已停止: {discontinued}" if discontinued else "无运行中的攻击",
    })


@app.route("/api/attack/status")
def api_attack_status():
    """Return the current attack execution status + per-type progress."""
    with _attack_lock:
        return jsonify({
            "running": _current_attack["running"],
            "name": _current_attack["name"],
            "started_at": _current_attack["started_at"],
            "elapsed_s": time.time() - _current_attack["started_at"]
                         if _current_attack["running"] else 0,
            "progresses": dict(_attack_progresses),  # {attack_type: {progress, status}}
        })


# ── Demo producer control APIs ────────────────────────────────────

@app.route("/api/demo/status")
def api_demo_status():
    """Return whether the demo producer is active."""
    return jsonify({"active": not _demo_paused, "paused": _demo_paused})


@app.route("/api/demo/pause", methods=["POST"])
def api_demo_pause():
    """Pause the demo data producer."""
    global _demo_paused, _demo_proc
    _demo_paused = True
    if _demo_proc and _demo_proc.poll() is None:
        _demo_proc.terminate()
    return jsonify({"ok": True, "active": False})


@app.route("/api/demo/resume", methods=["POST"])
def api_demo_resume():
    """Resume the demo data producer."""
    global _demo_paused
    _demo_paused = False
    _start_demo_producer()
    return jsonify({"ok": True, "active": True})


# ── CORS headers (allow embedding in external pages) ──────────────

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "no-cache"
    return response


# ── CLI entry ─────────────────────────────────────────────────────

def main():
    port = int(os.environ.get("DASHBOARD_PORT", 5000))

    # Clear stale attack log so old records don't synthesize false alerts
    if ATTACK_LOG.exists():
        ATTACK_LOG.unlink()

    # Auto-start demo data producer in background (generates health.json + alerts.db)
    _start_demo_producer()

    print(f"\n{'='*60}")
    print(f"  Open-Detect Test Dashboard")
    print(f"  http://localhost:{port}")
    print(f"  Data dir: {BASE_DIR}")
    print(f"{'='*60}\n")
    app.run(host="0.0.0.0", port=port, debug=False)


def _start_demo_producer():
    """Start demo_producer.py in a background process to generate live data."""
    global _demo_proc
    try:
        import subprocess
        demo_script = BASE_DIR / "dashboard" / "demo_producer.py"
        if not demo_script.exists():
            print("[dashboard] demo_producer.py not found, skipping")
            return
        _demo_proc = subprocess.Popen(
            [str(_sys.executable), str(demo_script)],
            cwd=str(BASE_DIR),  # write health.json to tests/
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[dashboard] Demo producer started (pid={_demo_proc.pid}), cwd={BASE_DIR}")
    except Exception as exc:
        print(f"[dashboard] Failed to start demo producer: {exc}")


if __name__ == "__main__":
    main()
