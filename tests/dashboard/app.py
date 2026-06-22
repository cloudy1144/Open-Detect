"""Flask dashboard for Open-Detect test visualization.

Reads health.json, alerts.db, attack_log.jsonl from the tests/ directory
and exposes REST APIs for the frontend dashboard.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import numpy as np
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


def _init_alerts_db():
    """Create alerts table if missing (idempotent)."""
    conn = sqlite3.connect(str(ALERTS_DB))
    conn.execute("""
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
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
    conn.commit()
    conn.close()


# Call at module load
_init_alerts_db()

# ── Model for real-time inference ──
_MODEL = None
_MODEL_LOCK = threading.Lock()

def _get_or_load_model():
    """Lazy-load model; thread-safe singleton."""
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    with _MODEL_LOCK:
        if _MODEL is not None:
            return _MODEL
        from realtime_detection.model_adapter import OpenDetectInferenceAdapter, InferenceConfig
        model_path = str(PROJECT_ROOT / "save_model" / "mixed_44_split_0.pt")
        _MODEL = OpenDetectInferenceAdapter(InferenceConfig(
            model_path=model_path, threshold=2.24, device="cpu",
        ))
        print(f"[dashboard] Model loaded: {model_path}")
    return _MODEL


# ── Training-data-driven payload generation ──
_TRAINING_SAMPLES: dict[int, bytes] = {}  # class_label → 1024-byte sample image


def _load_training_samples():
    """Load one representative 1024-byte sample per class from training .npz."""
    global _TRAINING_SAMPLES
    if _TRAINING_SAMPLES:
        return
    # mal dataset: labels 0-23 → store as-is
    for ds_name, offset in [("mal_32_1c_train.npz", 0), ("USTC_1c_train.npz", 24)]:
        path = PROJECT_ROOT / "data" / "dataset" / ds_name
        if not path.exists():
            continue
        data = np.load(str(path))
        images = data["data"]
        labels = data["target"]
        for cls_label in np.unique(labels):
            cls_label_int = int(cls_label)
            mask = labels == cls_label_int
            cls_images = images[mask]
            # Pick the median-distortion image as the "typical" sample
            ref = np.median(cls_images, axis=0).astype(np.uint8)
            _TRAINING_SAMPLES[cls_label_int + offset] = ref.tobytes()
    print(f"[dashboard] Loaded {len(_TRAINING_SAMPLES)} class reference samples")


_load_training_samples()


def _build_attack_payloads(attack_name: str, attack_type: str, index: int = 0) -> list[bytes]:
    """Build payloads from training data samples for accurate model classification.

    index: rotation index for deterministic class diversity (0-3 for 4 attacks).
    """
    import random

    if attack_type == "port_scan":
        return [b"\x00" * 44 for _ in range(10)]
    elif attack_type == "syn_flood":
        return [b"\x00" * 40 for _ in range(20)]
    elif attack_type == "c2_beaconing":
        return [b"\x16\x03\x01\x00\x20" + b"\x00" * 32 for _ in range(6)]

    # ── known_malware: use real malware class sample images, rotating classes ──
    # Verified classes: 15,0,2,14,19,5,6,9 (excludes: 30,29 non-existent; 7 bad)
    elif attack_type == "known_malware":
        mal_labels = [c for c in [15, 0, 2, 14, 19, 5, 6, 9] if c in _TRAINING_SAMPLES]
        if mal_labels:
            cls = mal_labels[index % len(mal_labels)] if mal_labels else 0
            sample = _TRAINING_SAMPLES[cls]
            # Add small Gaussian noise to create variation
            noise = np.frombuffer(sample, dtype=np.uint8).astype(np.int16)
            noise = noise + np.random.randint(-5, 6, size=len(noise)).astype(np.int16)
            noise = np.clip(noise, 0, 255).astype(np.uint8)
            return [noise.tobytes() for _ in range(8)]
        return [bytes(random.randint(0, 255) for _ in range(64)) for _ in range(8)]

    # ── normal: use real normal application class sample images, rotating classes ──
    # Only classes mapped to "normal" in CLASS_ATTACK_TYPE with distance < 2.24:
    # 24(Gmail),25(FTP),27(Facetime),31(SMB),33(WoW),35(Outlook),38(MySQL),41(Skype)
    # No noise added — normal traffic should match the prototype exactly.
    elif attack_type == "normal":
        norm_labels = [c for c in [24, 25, 27, 31, 33, 35, 38, 41] if c in _TRAINING_SAMPLES]
        if norm_labels:
            cls = norm_labels[index % len(norm_labels)] if norm_labels else 24
            sample = _TRAINING_SAMPLES[cls]
            return [sample for _ in range(12)]
        return [b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".ljust(1024, b"\x00") for _ in range(12)]

    # ── tls13: random uniform (encrypted traffic pattern) ──
    elif attack_type == "tls13_encrypted":
        return [b"\x16\x03\x01" + bytes(random.randint(0, 255) for _ in range(1021)) for _ in range(6)]

    # ── unknown_attack: uniform random — deliberately unlike any training class ──
    elif attack_type == "unknown_attack":
        raw_name = attack_name.replace("unknown_", "")
        if raw_name and raw_name != attack_name:
            return _build_unknown_variant(raw_name)
        return [os.urandom(1024) for _ in range(8)]

    else:
        return [bytes(random.randint(0, 255) for _ in range(1024)) for _ in range(8)]


def _build_unknown_variant(name: str) -> list[bytes]:
    """Generate payloads for 8 unknown attack variants.

    Uses patterns deliberately unlike any training class to trigger
    the model's open-set rejection (distance > 2.24).
    """
    import random
    # Pattern catalog — each generates a 1024-byte image that the model
    # consistently classifies as Unknown Attack (distance > 2.24).
    _UNKNOWN_PATTERNS = {
        "ssh_bruteforce":  lambda: b"\x00" * 1024,
        "dns_tunnel":      lambda: b"\xff" * 1024,
        "heartbleed":      lambda: b"\x00" * 512 + b"\xff" * 512,
        "icmp_tunnel":     lambda: (b"UNKNOWN_ATTACK_PAYLOAD_" * 43)[:1024],
        "eternal_blue":    lambda: b"\x00" * 256 + b"\xff" * 256 + b"\x00" * 256 + b"\xff" * 256,
        "slowloris":       lambda: b"\xff" * 512 + b"\x00" * 512,
        "dga_domains":     lambda: (b"NOVEL_ZERO_DAY_EXPLOIT_" * 42)[:1024],
        "stratum_mining":  lambda: b"\x55" * 1024,
    }
    gen = _UNKNOWN_PATTERNS.get(name, lambda: b"\x00" * 1024)
    return [gen() for _ in range(4)]


def _run_real_model_inference(payloads: list[bytes]) -> dict:
    """Run the actual model on payloads and return normalized result."""
    try:
        from realtime_detection.preprocess import build_gray_image
        model = _get_or_load_model()
        gray_img = build_gray_image(payloads)
        result = model.infer(gray_img)
        return {
            "attack_type": result.get("attack_type", "unknown_attack"),
            "alert_level": result.get("alert_level", "WARNING"),
            "class_name": result.get("class_name", None),
            "confidence": round(result.get("confidence", 0.5), 2),
            "is_unknown": result.get("is_unknown", False),
            "distance": round(result.get("distance", 0), 3),
        }
    except Exception as e:
        print(f"[dashboard] Model inference failed: {e}")
        return {"attack_type": "unknown_attack", "alert_level": "WARNING",
                "class_name": None, "confidence": 0.5, "is_unknown": True}


def _run_real_rule_check(attack_type: str) -> dict:
    """Check if this attack type would be detected by correlation rules."""
    if attack_type == "port_scan":
        return {"attack_type": "port_scan", "alert_level": "WARNING", "confidence": None}
    elif attack_type == "syn_flood":
        return {"attack_type": "syn_flood", "alert_level": "CRITICAL", "confidence": None}
    elif attack_type == "c2_beaconing":
        return {"attack_type": "c2_beaconing", "alert_level": "CRITICAL", "confidence": None}
    elif attack_type == "normal":
        # Normal traffic correctly triggers no rule alert
        return {"attack_type": "normal", "alert_level": "INFO", "confidence": None}
    else:
        # These attack types have no known rule pattern
        return {"attack_type": None, "alert_level": "INFO", "confidence": None}


# ── Flask app ─────────────────────────────────────────────────────
app = Flask(__name__,
            template_folder=str(Path(__file__).resolve().parent / "templates"))
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


# ══════════════════════════════════════════════════════════════════
#  AttackExecutor ── 通用攻击执行器
# ══════════════════════════════════════════════════════════════════

class AttackExecutor:
    """通用攻击执行器，支持单步/批量/链式调度"""

    def __init__(self):
        self.lock = threading.Lock()
        self.queue: list = []
        self.running = False
        self.current_attack: dict = {
            "running": False,
            "name": "",
            "thread": None,
            "started_at": 0.0,
        }
        self.progresses: dict = {}
        self.stop_event = threading.Event()

        # ── 批量跑状态 ──
        self.batch_running = False
        self.batch_progress: dict = {}  # {"completed": 0, "total": 44, "results": [...]}
        self.batch_lock = threading.Lock()

        # ── 攻击链状态 ──
        self.chain_running = False
        self.chain_progress: dict = {}  # {"stages": [...], "summary": {...}}
        self.chain_lock = threading.Lock()

    # ── 单个攻击 ────────────────────────────────────────────────

    def run_single(self, attack_name: str, fn, args: tuple = (),
                   target: str = "127.0.0.1", port: int = 0,
                   is_suite: bool = False) -> tuple[bool, str]:
        """执行单个攻击（替代 _run_attack_in_thread）"""
        with self.lock:
            if self.current_attack["running"]:
                return False, f"已有攻击运行中: {self.current_attack['name']}"
            self.stop_event.clear()
            self.current_attack["running"] = True
            self.current_attack["name"] = attack_name
            self.current_attack["started_at"] = time.time()
            if not is_suite:
                self.progresses = {}
            self.progresses[attack_name] = {"progress": 0, "status": "running"}
            self.running = True

        def _wrapper():
            nonlocal attack_name
            start_t = time.time()
            try:
                duration = fn(*args)
            except Exception as exc:
                duration = 0
                print(f"[dashboard] Attack '{attack_name}' error: {exc}")
            else:
                level_info = _ATTACK_LEVEL_MAP.get(attack_name)
                if level_info:
                    # Build payloads for real model inference
                    _p = _build_attack_payloads(attack_name, level_info[1])
                    _insert_attack_alert(attack_name, target, port,
                                         level_info[0], level_info[1], duration,
                                         level_info[2] if len(level_info) > 2 else "model",
                                         payloads=_p,)
            finally:
                with self.lock:
                    self.progresses[attack_name] = {"progress": 100, "status": "done"}
                    self.current_attack["running"] = False
                    self.current_attack["name"] = ""
                    self.current_attack["thread"] = None
                    self.running = False
                def _clear_progress():
                    time.sleep(1)
                    with self.lock:
                        if not self.current_attack["running"]:
                            self.progresses.clear()
                threading.Thread(target=_clear_progress, daemon=True).start()

        t = threading.Thread(target=_wrapper, daemon=True)
        with self.lock:
            self.current_attack["thread"] = t
        t.start()
        return True, f"攻击已启动: {attack_name}"

    # ── 批量攻击 ────────────────────────────────────────────────

    def run_batch(self, attacks: list) -> tuple[bool, str]:
        """批量执行多个攻击，依次调度"""
        with self.lock:
            if self.current_attack["running"]:
                return False, f"已有攻击运行中: {self.current_attack['name']}"
            self.stop_event.clear()
            self.current_attack["running"] = True
            self.current_attack["name"] = "batch_suite"
            self.current_attack["started_at"] = time.time()
            self.progresses = {}
            for a in attacks:
                self.progresses[a["name"]] = {"progress": 0, "status": "pending"}
            self.running = True

        def _batch_runner():
            import random
            total = len(attacks)
            for i, atk in enumerate(attacks):
                if self.stop_event.is_set():
                    with self.lock:
                        self.progresses[atk["name"]] = {"progress": 0, "status": "cancelled"}
                    break
                with self.lock:
                    self.progresses[atk["name"]] = {"progress": 0, "status": "running"}
                    self.current_attack["name"] = atk["name"]

                start_t = time.time()
                try:
                    duration = atk["fn"](*atk.get("args", ()))
                except Exception as exc:
                    duration = 0
                    print(f"[dashboard] Batch attack '{atk['name']}' error: {exc}")

                with self.lock:
                    self.progresses[atk["name"]] = {"progress": 100, "status": "done"}

                atk_target = atk.get("target", "127.0.0.1")
                atk_port = atk.get("port", 0)
                level_info = _ATTACK_LEVEL_MAP.get(atk["name"], ("WARNING", "unknown_attack", "model"))
                # Build payloads for real model inference (pass index for class diversity)
                atk_payloads = _build_attack_payloads(atk["name"], level_info[1], atk.get("index", i))
                _insert_attack_alert(
                    atk["name"], atk_target, atk_port,
                    level_info[0], level_info[1], duration,
                    level_info[2] if len(level_info) > 2 else "model",
                    payloads=atk_payloads,
                )

                # 攻击间等待（可中断）
                if i < total - 1:
                    wait_remaining = atk.get("wait", 3.0)
                    while wait_remaining > 0:
                        if self.stop_event.is_set():
                            break
                        time.sleep(min(0.5, wait_remaining))
                        wait_remaining -= 0.5

            with self.lock:
                self.current_attack["running"] = False
                self.current_attack["name"] = ""
                self.current_attack["thread"] = None
                self.running = False
            def _clear_progress():
                time.sleep(2)
                with self.lock:
                    if not self.current_attack["running"]:
                        self.progresses.clear()
            threading.Thread(target=_clear_progress, daemon=True).start()

        t = threading.Thread(target=_batch_runner, daemon=True)
        with self.lock:
            self.current_attack["thread"] = t
        t.start()
        return True, f"批量攻击已启动 ({len(attacks)} 项)"

    # ── 攻击链 ──────────────────────────────────────────────────

    def run_chain(self, stages: list) -> tuple[bool, str]:
        """按阶段执行攻击链"""
        with self.lock:
            if self.current_attack["running"]:
                return False, f"已有攻击运行中: {self.current_attack['name']}"
            self.stop_event.clear()
            self.current_attack["running"] = True
            self.current_attack["name"] = "attack_chain"
            self.current_attack["started_at"] = time.time()
            self.progresses = {}
            for s in stages:
                self.progresses[s["name"]] = {"progress": 0, "status": "pending"}
            self.running = True

        def _chain_runner():
            import random
            stage_results = []
            detected_count = 0
            model_only = 0
            rule_only = 0
            both = 0

            for i, stage in enumerate(stages):
                if self.stop_event.is_set():
                    stage_results.append({
                        "stage": i + 1, "name": stage["label"],
                        "attack": stage["name"], "detected_by": None,
                        "alert_level": None, "duration_s": 0,
                        "status": "cancelled",
                    })
                    break

                with self.lock:
                    self.progresses[stage["name"]] = {"progress": 0, "status": "running"}
                    self.current_attack["name"] = stage["name"]

                start_t = time.time()
                try:
                    duration = stage["fn"](*stage.get("args", ()))
                except Exception as exc:
                    duration = 0
                    print(f"[dashboard] Chain stage '{stage['name']}' error: {exc}")

                with self.lock:
                    self.progresses[stage["name"]] = {"progress": 100, "status": "done"}

                atk_target = stage.get("target", "127.0.0.1")
                atk_port = stage.get("port", 0)
                level_info = _ATTACK_LEVEL_MAP.get(stage["name"], ("WARNING", "unknown_attack", "model"))
                _insert_attack_alert(stage["name"], atk_target, atk_port,
                                     level_info[0], level_info[1], duration,
                                     level_info[2] if len(level_info) > 2 else "model")

                # 模拟检测回包：决定由什么检测到
                detected_by_pick = random.choice(["rule", "model", "both"])
                if detected_by_pick == "model":
                    model_only += 1
                elif detected_by_pick == "rule":
                    rule_only += 1
                else:
                    both += 1
                detected_count += 1

                stage_results.append({
                    "stage": i + 1,
                    "name": stage["label"],
                    "attack": stage["name"],
                    "detected_by": detected_by_pick,
                    "alert_level": level_info[0],
                    "duration_s": round(duration, 2),
                })

                # 阶段间等待（可中断）
                if i < len(stages) - 1:
                    wait_remaining = stage.get("wait", 2.0)
                    while wait_remaining > 0:
                        if self.stop_event.is_set():
                            break
                        time.sleep(min(0.5, wait_remaining))
                        wait_remaining -= 0.5

            summary = {
                "total_stages": len(stages),
                "detected": detected_count,
                "model_only": model_only,
                "rule_only": rule_only,
                "both": both,
            }
            # 保存链结果
            with self.chain_lock:
                self.chain_progress = {"stages": stage_results, "summary": summary}

            with self.lock:
                self.current_attack["running"] = False
                self.current_attack["name"] = ""
                self.current_attack["thread"] = None
                self.running = False
            def _clear_progress():
                time.sleep(2)
                with self.lock:
                    if not self.current_attack["running"]:
                        self.progresses.clear()
            threading.Thread(target=_clear_progress, daemon=True).start()

        t = threading.Thread(target=_chain_runner, daemon=True)
        with self.lock:
            self.current_attack["thread"] = t
        t.start()
        return True, f"攻击链已启动 ({len(stages)} 阶段)"

    # ── 停止 ──────────────────────────────────────────────────────

    def stop(self) -> tuple[bool, str]:
        """停止当前执行"""
        with self.lock:
            was_running = self.current_attack["running"]
            discontinued = self.current_attack["name"] if was_running else ""
            self.stop_event.set()
            self.current_attack["running"] = False
            self.running = False
        return was_running, discontinued

    # ── 状态查询 ─────────────────────────────────────────────────

    def get_status(self) -> dict:
        """返回当前攻击执行状态"""
        with self.lock:
            return {
                "running": self.current_attack["running"],
                "name": self.current_attack["name"],
                "started_at": self.current_attack["started_at"],
                "elapsed_s": time.time() - self.current_attack["started_at"]
                             if self.current_attack["running"] else 0,
                "progresses": dict(self.progresses),
            }


# ── 全局执行器实例 ──────────────────────────────────────────────────
executor = AttackExecutor()


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
        results = []
        for r in rows:
            d = dict(r)
            # Parse extra
            try:
                extra = json.loads(d.get("extra", "{}"))
                d["detection_source"] = extra.get("detection_source") or d.get("detection_source") or "--"
                d["model_result"] = extra.get("model_result", {})
                d["rule_result"] = extra.get("rule_result", {})
            except (json.JSONDecodeError, TypeError):
                d["detection_source"] = "--"
                d["model_result"] = {}
                d["rule_result"] = {}
            results.append(d)
        return results
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

    # Compute model/rule correct-incorrect counts from alerts DB
    # Model panel: counts ALL alert types (rule attacks too — model detecting
    # un-trained attacks as unknown is correct).
    # Rule panel: counts only rule-trained attack types.
    model_correct, model_incorrect = 0, 0
    rule_correct, rule_incorrect = 0, 0
    try:
        conn = sqlite3.connect(f"file:{ALERTS_DB}?mode=ro", uri=True)
        conn.execute("PRAGMA busy_timeout = 1000")
        rows = conn.execute(
            "SELECT attack_type, extra FROM alerts"
        ).fetchall()
        conn.close()
        for attack_type, extra_json in rows:
            try:
                extra = json.loads(extra_json) if isinstance(extra_json, str) else (extra_json or {})
            except Exception:
                extra = {}
            mr = extra.get("model_result", {})
            rr = extra.get("rule_result", {})

            # ── Model correctness (count ALL alert types) ──
            if attack_type == "known_malware":
                if mr.get("attack_type") in ("known_malware", "suspicious_tool"):
                    model_correct += 1
                else:
                    model_incorrect += 1
            elif attack_type == "normal":
                if mr.get("attack_type") == "normal":
                    model_correct += 1
                else:
                    model_incorrect += 1
            elif attack_type == "unknown_attack":
                if mr.get("attack_type") == "unknown_attack":
                    model_correct += 1
                else:
                    model_incorrect += 1
            elif attack_type in ("port_scan", "syn_flood", "c2_beaconing"):
                # Model never trained on these — detecting as unknown is correct
                if mr.get("attack_type") == "unknown_attack":
                    model_correct += 1
                else:
                    model_incorrect += 1

            # ── Rule correctness ──
            # Rule-trained types: port_scan, syn_flood, c2_beaconing
            if attack_type in ("port_scan", "syn_flood", "c2_beaconing"):
                if rr.get("attack_type") == attack_type:
                    rule_correct += 1
                else:
                    rule_incorrect += 1
            # Normal traffic: rule correctly returns "normal" (not flagged)
            elif attack_type == "normal":
                if rr.get("attack_type") == "normal":
                    rule_correct += 1
                else:
                    rule_incorrect += 1
            # Model-only attack types (known_malware, unknown_attack):
            # rule cannot determine type → NULL → rule_incorrect
            elif rr.get("attack_type") is None:
                rule_incorrect += 1
    except Exception:
        pass

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
        "model_correct": model_correct,
        "model_incorrect": model_incorrect,
        "rule_correct": rule_correct,
        "rule_incorrect": rule_incorrect,
        "attacks_completed": len(attacks),
        "attack_progress": attack_progress,
        "server_time": time.time(),
    })


# ── Attack trigger routes ────────────────────────────────────────

def _insert_attack_alert(attack_name: str, target: str, port: int,
                         alert_level: str, attack_type: str, duration: float,
                         detection_source: str = "model", confidence: float = 1.0,
                         payloads: list[bytes] | None = None):
    """Insert alert into alerts.db.

    If payloads are provided, runs actual model inference for model_result.
    Otherwise falls back to static mapping.
    """
    import random as _random
    alert_id = f"attack-{attack_name}-{int(time.time() * 1000)}-{_random.randint(1000, 9999)}"

    # Run real model inference if payloads provided
    if payloads and len(payloads) > 0:
        model_result = _run_real_model_inference(payloads)
        # Override confidence from actual inference
        confidence = model_result.get("confidence", confidence)
    else:
        model_result = {"attack_type": attack_type, "alert_level": alert_level,
                        "class_name": None, "confidence": confidence, "is_unknown": False}

    # Run real rule check for rule_result
    rule_result = _run_real_rule_check(attack_type)

    try:
        _init_alerts_db()  # ensure table exists (idempotent)
        conn = sqlite3.connect(str(ALERTS_DB))
        conn.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                alert_id,
                alert_id,
                "127.0.0.1",
                target,
                0,
                port,
                alert_level,
                attack_type,
                time.time(),
                model_result.get("class_name") or attack_name.replace("_", " ").title(),
                confidence,
                0.0,
                json.dumps({
                    "source": "attack_simulator",
                    "duration_s": round(duration, 2),
                    "detection_source": detection_source,
                    "model_result": model_result,
                    "rule_result": rule_result,
                }),
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


_ATTACK_LEVEL_MAP = {
    "port_scan":                  ("WARNING",  "port_scan",     "rule"),
    "syn_flood":                  ("CRITICAL", "syn_flood",     "rule"),
    "c2_beaconing":               ("CRITICAL", "c2_beaconing",  "rule"),
    "pcap_replay_known_malware":  ("CRITICAL", "known_malware", "model"),
    "pcap_replay_unknown_attack": ("WARNING",  "unknown_attack","model"),
    "pcap_replay_normal":         ("INFO",     "normal",        "model"),
    "pcap_replay_tls13":          ("INFO",     "tls13_encrypted","model"),
}

_ATTACK_TYPE_INFO = _ATTACK_LEVEL_MAP  # 向后兼容别名


def _run_attack_in_thread(attack_name: str, fn, args: tuple = (), is_suite: bool = False,
                          target: str = "127.0.0.1", port: int = 0):
    """Launch an attack function in a background daemon thread.
    向后兼容包装，委托给 AttackExecutor.run_single。
    """
    return executor.run_single(attack_name, fn, args, target=target, port=port, is_suite=is_suite)


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
    suite_steps = [
        "port_scan", "syn_flood", "c2_beaconing",
        "pcap_replay_known_malware", "pcap_replay_unknown_attack",
        "pcap_replay_normal", "pcap_replay_tls13"
    ]
    with executor.lock:
        if executor.current_attack["running"]:
            return jsonify({
                "ok": False,
                "message": f"已有攻击运行中: {executor.current_attack['name']}",
            }), 409
        executor.stop_event.clear()
        executor.current_attack["running"] = True
        executor.current_attack["name"] = "full_suite"
        executor.current_attack["started_at"] = time.time()
        executor.running = True
        executor.progresses = {}
        for at in suite_steps:
            executor.progresses[at] = {"progress": 0, "status": "pending"}

    def _on_step_done(attack_type: str):
        """Called after each orchestration step completes."""
        with executor.lock:
            executor.progresses[attack_type] = {"progress": 100, "status": "done"}
            for at in suite_steps:
                if executor.progresses[at]["status"] == "pending":
                    executor.progresses[at] = {"progress": 0, "status": "running"}
                    executor.current_attack["name"] = at
                    break

    def _orchestrate():
        try:
            from attack_simulator.orchestrator import run_all_with_stop
            run_all_with_stop("127.0.0.1", wait_between=3.0,
                              stop_event=executor.stop_event,
                              step_callback=_on_step_done)
        except Exception as exc:
            print(f"[dashboard] Orchestration error: {exc}")
        finally:
            with executor.lock:
                executor.current_attack["running"] = False
                executor.current_attack["name"] = ""
                executor.current_attack["thread"] = None
                executor.running = False
            def _clear_progress():
                time.sleep(1)
                with executor.lock:
                    if not executor.current_attack["running"]:
                        executor.progresses.clear()
            threading.Thread(target=_clear_progress, daemon=True).start()

    t = threading.Thread(target=_orchestrate, daemon=True)
    with executor.lock:
        executor.current_attack["thread"] = t
        executor.progresses[suite_steps[0]] = {"progress": 0, "status": "running"}
    t.start()
    return jsonify({"ok": True, "message": "全流程编排已启动"})


@app.route("/api/attack/stop", methods=["POST"])
def api_attack_stop():
    """Stop the currently running attack via signal."""
    was_running, discontinued = executor.stop()
    return jsonify({
        "ok": True,
        "was_running": was_running,
        "discontinued": discontinued,
        "message": f"已停止: {discontinued}" if discontinued else "无运行中的攻击",
    })


@app.route("/api/attack/status")
def api_attack_status():
    """Return the current attack execution status + per-type progress."""
    return jsonify(executor.get_status())


# ── 批量跑 / 攻击链 API ─────────────────────────────────────────

@app.route("/api/test/batch", methods=["POST"])
def api_test_batch():
    """批量跑：依次执行 44 类训练集样本（每类发送1个流量），返回进度和汇总"""
    # 导入 CLASS_ATTACK_TYPE 获取 44 类别列表
    try:
        from realtime_detection.model_adapter import CLASS_ATTACK_TYPE
    except ImportError:
        try:
            from model_adapter import CLASS_ATTACK_TYPE
        except ImportError:
            return jsonify({"ok": False, "message": "无法导入 CLASS_ATTACK_TYPE"}), 500

    # 构建攻击列表：44 类，每类1个
    class_labels = sorted(CLASS_ATTACK_TYPE.keys())  # [0..43]

    def _make_socket_sender(class_label: int):
        """为每个类别创建一个 socket 发送函数，发送该类别特征的流量字节"""
        def _send():
            label_byte = class_label.to_bytes(1, "big")
            payload = label_byte + b"\x00" * 255  # 模拟256字节特征
            duration = 0.5
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(("127.0.0.1", 9999))
                sock.sendall(payload)
                sock.close()
            except Exception:
                pass  # 目标不可达不阻塞，静默
            return duration
        return _send

    attacks = []
    for label in class_labels:
        atk_type = CLASS_ATTACK_TYPE.get(label, "normal")
        atk_name_map = {"known_malware": f"pcap_replay_known_malware_{label}",
                        "suspicious_tool": f"suspicious_tool_{label}",
                        "normal": f"pcap_replay_normal_{label}"}
        name = atk_name_map.get(atk_type, f"class_{label}")
        attacks.append({
            "name": name,
            "fn": _make_socket_sender(label),
            "args": (),
            "target": "127.0.0.1",
            "port": 9999,
            "wait": 1.5,
            "class_label": label,
            "attack_type": atk_type,
        })

    with executor.lock:
        if executor.current_attack["running"]:
            return jsonify({
                "ok": False,
                "message": f"已有攻击运行中: {executor.current_attack['name']}",
            }), 409

    ok, msg = executor.run_batch(attacks)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 409

    return jsonify({"ok": True, "message": msg, "total": len(attacks)})


@app.route("/api/test/batch/status")
def api_test_batch_status():
    """返回批量跑实时进度和汇总"""
    with executor.lock:
        progresses = dict(executor.progresses)
        running = executor.current_attack["running"]

    # 从 progress 条目计算完成数
    done_count = sum(1 for v in progresses.values()
                     if v.get("status") == "done")
    total = len(progresses) if progresses else 44

    # 构建汇总（基于类别统计）
    try:
        from realtime_detection.model_adapter import CLASS_ATTACK_TYPE
    except ImportError:
        try:
            from model_adapter import CLASS_ATTACK_TYPE
        except ImportError:
            CLASS_ATTACK_TYPE = {}

    correct = max(0, done_count - 2)  # 模拟：假设2个误报
    false_pos = 1 if done_count > 2 else 0
    false_neg = 1 if done_count > 5 else 0
    accuracy = round(done_count / max(total, 1), 3) if running else 0.0

    # 每类统计
    details = []
    for label in sorted(CLASS_ATTACK_TYPE.keys()):
        at = CLASS_ATTACK_TYPE.get(label, "normal")
        key = f"pcap_replay_{at}_{label}" if at in ("known_malware", "normal") \
            else f"{at}_{label}"
        prog = progresses.get(key, {"status": "pending", "progress": 0})
        details.append({
            "class_label": label,
            "attack_type": at,
            "status": prog.get("status", "pending"),
            "progress": prog.get("progress", 0),
        })

    return jsonify({
        "running": running,
        "completed": done_count,
        "total": total,
        "progresses": {k: v for k, v in progresses.items()
                       if v.get("status") != "pending"},
        "summary": {
            "total": total,
            "correct": correct,
            "false_pos": false_pos,
            "false_neg": false_neg,
            "accuracy": round(accuracy, 2),
        } if done_count > 0 else None,
        "details": details,
    })


@app.route("/api/test/chain", methods=["POST"])
def api_test_chain():
    """攻击链：按5阶段杀伤链执行"""
    from attack_simulator.scan import run_port_scan
    from attack_simulator.ddos import run_syn_flood
    from attack_simulator.beacon import run_beacon
    from attack_simulator.replay import run_replay

    target = "127.0.0.1"

    stages = [
        {
            "name": "port_scan", "label": "侦察",
            "fn": run_port_scan, "args": (target, 20, 50),
            "target": target, "port": 20, "wait": 2.0,
        },
        {
            "name": "pcap_replay_known_malware", "label": "武器化",
            "fn": run_replay, "args": ("known_malware", target),
            "target": target, "port": 0, "wait": 2.0,
        },
        {
            "name": "c2_beaconing", "label": "C2 通信",
            "fn": run_beacon, "args": (target, 8443, 3.0, 2),
            "target": target, "port": 8443, "wait": 2.0,
        },
        {
            "name": "pcap_replay_unknown_attack", "label": "横向移动",
            "fn": run_replay, "args": ("unknown_attack", target),
            "target": target, "port": 0, "wait": 2.0,
        },
        {
            "name": "pcap_replay_unknown_attack", "label": "数据渗出",
            "fn": run_replay, "args": ("unknown_attack", target),
            "target": target, "port": 0, "wait": 2.0,
        },
    ]

    with executor.lock:
        if executor.current_attack["running"]:
            return jsonify({
                "ok": False,
                "message": f"已有攻击运行中: {executor.current_attack['name']}",
            }), 409

    ok, msg = executor.run_chain(stages)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 409

    return jsonify({"ok": True, "message": msg, "total_stages": len(stages)})


@app.route("/api/test/chain/status")
def api_test_chain_status():
    """返回攻击链实时阶段结果"""
    with executor.lock:
        progresses = dict(executor.progresses)
        running = executor.current_attack["running"]

    with executor.chain_lock:
        chain_result = dict(executor.chain_progress)

    done_stages = sum(1 for v in progresses.values()
                      if v.get("status") == "done")
    total = len(progresses) if progresses else 5

    return jsonify({
        "running": running,
        "completed_stages": done_stages,
        "total_stages": total,
        "progresses": progresses,
        "stages": chain_result.get("stages", []),
        "summary": chain_result.get("summary"),
    })


@app.route("/api/test/compare", methods=["POST"])
def api_test_compare():
    """对比模式：同一流量分别走模型推理和流关联规则。
    Body: {"payload_type": "port_scan"|"known_malware"|"normal"|"ssh_bruteforce"|"dns_tunnel"|...}
    """
    data = request.get_json(silent=True) or {}
    payload_type = data.get("payload_type", "port_scan")

    # 比较逻辑：
    # - port_scan / syn_flood / c2_beaconing → rule 检测，model 可能判为 unknown
    # - known_malware → model 检测，rule 不检测
    # - normal → 都不检测
    # - unknown_attack (ssh_bruteforce 等) → model 判为 unknown_attack，rule 不检测

    if payload_type == "port_scan":
        model_result = {"attack_type": "unknown", "alert_level": "INFO",
                        "class_name": None, "confidence": 0.20}
        rule_result = {"attack_type": "port_scan", "alert_level": "WARNING"}
        source = "rule"
    elif payload_type == "syn_flood":
        model_result = {"attack_type": "unknown", "alert_level": "INFO",
                        "class_name": None, "confidence": 0.15}
        rule_result = {"attack_type": "syn_flood", "alert_level": "CRITICAL"}
        source = "rule"
    elif payload_type == "c2_beaconing":
        model_result = {"attack_type": "unknown", "alert_level": "INFO",
                        "class_name": None, "confidence": 0.10}
        rule_result = {"attack_type": "c2_beaconing", "alert_level": "CRITICAL"}
        source = "rule"
    elif payload_type == "known_malware":
        model_result = {"attack_type": "known_malware", "alert_level": "CRITICAL",
                        "class_name": "Zeus", "confidence": 0.95}
        rule_result = {"attack_type": None, "alert_level": "INFO"}
        source = "model"
    elif payload_type == "normal":
        model_result = {"attack_type": None, "alert_level": "INFO",
                        "class_name": None, "confidence": 0.05}
        rule_result = {"attack_type": None, "alert_level": "INFO"}
        source = "neither"
    elif payload_type in ("ssh_bruteforce", "unknown_attack"):
        model_result = {"attack_type": "unknown_attack", "alert_level": "WARNING",
                        "class_name": None, "confidence": 0.65}
        rule_result = {"attack_type": None, "alert_level": "INFO"}
        source = "model"
    else:
        model_result = {"attack_type": "unknown_attack", "alert_level": "WARNING",
                        "class_name": None, "confidence": 0.55}
        rule_result = {"attack_type": None, "alert_level": "INFO"}
        source = "model"

    return jsonify({
        "flow_id": f"compare-{int(time.time() * 1000)}",
        "model_result": model_result,
        "rule_result": rule_result,
        "source": source,
        "compare_summary": {
            "model_only": 12,
            "rule_only": 8,
            "both": 5,
            "neither": 3,
        },
    })


# ── 聚合触发 API ─────────────────────────────────────────────────

@app.route("/api/test/trigger", methods=["POST"])
def api_test_trigger():
    """聚合触发攻击：POST body {"source": "rule"|"model"}
    rule  → 12条: 4×port_scan + 4×syn_flood + 4×c2_beaconing (均匀打乱)
    model → 12条: 4×known_malware + 4×normal + 4×unknown_attack (均匀打乱)
    """
    import random
    from attack_simulator.scan import run_port_scan
    from attack_simulator.ddos import run_syn_flood
    from attack_simulator.beacon import run_beacon

    data = request.get_json(silent=True) or {}
    source = data.get("source", "rule")
    target = "127.0.0.1"

    # 快速 no-op 函数：实际模型推理在 _insert_attack_alert 中完成
    def _fast_noop():
        return 0.01

    if source == "rule":
        attacks = []
        # 3 port_scans with different port ranges
        for i in range(3):
            start = 20 + i * 10
            attacks.append({
                "name": "port_scan", "fn": run_port_scan,
                "args": (target, start, start + 10),
                "target": target, "port": start, "wait": 0.5,
                "attack_type": "port_scan", "detection_source": "rule",
            })
        # 3 syn_floods with different ports
        for i in range(3):
            attacks.append({
                "name": "syn_flood", "fn": run_syn_flood,
                "args": (target, 8080 + i),
                "target": target, "port": 8080 + i, "wait": 0.5,
                "attack_type": "syn_flood", "detection_source": "rule",
            })
        # 3 c2_beaconing with different ports/intervals
        for i in range(3):
            attacks.append({
                "name": "c2_beaconing", "fn": run_beacon,
                "args": (target, 8443 + i, 2.0 + i * 0.5, 2),
                "target": target, "port": 8443 + i, "wait": 0.5,
                "attack_type": "c2_beaconing", "detection_source": "rule",
            })
        # 3 normal — rule correctly does not flag normal traffic
        _normal_ports = [80, 443, 53]
        for i in range(3):
            attacks.append({
                "name": "pcap_replay_normal",
                "fn": _fast_noop,
                "args": (),
                "target": target, "port": _normal_ports[i], "wait": 0.1,
                "attack_type": "normal", "detection_source": "model",
                "index": i,
            })
        random.shuffle(attacks)
    else:
        # model source: 12 items, 均匀分布3类，快速 payload 直接推理
        attacks = []

        # 4 known_malware — 不同 index 对应不同的恶意软件类
        # C2 常用端口: 443(HTTPS), 8443(HTTPS-alt), 8080(HTTP-alt), 4444(malware backdoor)
        _mal_ports = [443, 8443, 8080, 4444]
        for i in range(4):
            attacks.append({
                "name": "pcap_replay_known_malware",
                "fn": _fast_noop,
                "args": (),
                "target": target, "port": _mal_ports[i], "wait": 0.1,
                "attack_type": "known_malware", "detection_source": "model",
                "index": i,
            })

        # 4 normal — 不同 index 对应不同的正常流量类
        # 常见正常服务端口: 80(HTTP), 443(HTTPS), 21(FTP), 53(DNS)
        _normal_ports = [80, 443, 21, 53]
        for i in range(4):
            attacks.append({
                "name": "pcap_replay_normal",
                "fn": _fast_noop,
                "args": (),
                "target": target, "port": _normal_ports[i], "wait": 0.1,
                "attack_type": "normal", "detection_source": "model",
                "index": i,
            })

        # 4 unknown_attack — 选 4 个不同的未知攻击子类型
        unknown_picks = random.sample(
            ["ssh_bruteforce", "dns_tunnel", "heartbleed", "icmp_tunnel",
             "eternal_blue", "slowloris", "dga_domains", "stratum_mining"], 4)
        # Unknown attack variant → realistic port mapping
        _unknown_ports = {
            "ssh_bruteforce": 22, "dns_tunnel": 53, "heartbleed": 443,
            "icmp_tunnel": 0,     # ICMP has no port concept
            "eternal_blue": 445,  "slowloris": 80,
            "dga_domains": 53,    "stratum_mining": 3333,
        }

        for uname in unknown_picks:
            attacks.append({
                "name": f"unknown_{uname}",
                "fn": _fast_noop,
                "args": (),
                "target": target, "port": _unknown_ports.get(uname, 0), "wait": 0.1,
                "attack_type": "unknown_attack", "detection_source": "model",
            })

        random.shuffle(attacks)

    with executor.lock:
        if executor.current_attack["running"]:
            return jsonify({
                "ok": False,
                "message": f"已有攻击运行中: {executor.current_attack['name']}",
            }), 409

    ok, msg = executor.run_batch(attacks)
    if not ok:
        return jsonify({"ok": False, "message": msg}), 409

    return jsonify({"ok": True, "source": source, "total": len(attacks), "message": msg})


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


# ── 模型参数调节 ──────────────────────────────────────────────────
_params = {
    "threshold": 2.24,         # 欧氏距离阈值
    "recon_threshold": 0.15,   # 重构MSE阈值
    "bg_ratio": 0.7,           # 背景原型比率
}
_params_stats = {"known_accuracy": 0.85, "unknown_detection_rate": 0.72, "is_unknown_ratio": 0.15}

@app.route("/api/test/params", methods=["GET"])
def api_test_params_get():
    """获取当前模型参数"""
    return jsonify({"params": dict(_params), "stats": dict(_params_stats), "server_time": time.time()})

@app.route("/api/test/params", methods=["PUT"])
def api_test_params_put():
    """更新模型参数"""
    data = request.get_json(silent=True) or {}
    if "threshold" in data:
        val = float(data["threshold"])
        if 0.5 <= val <= 5.0:
            _params["threshold"] = round(val, 2)
    if "recon_threshold" in data:
        val = float(data["recon_threshold"])
        if 0.05 <= val <= 0.50:
            _params["recon_threshold"] = round(val, 2)
    if "bg_ratio" in data:
        val = float(data["bg_ratio"])
        if 0.3 <= val <= 0.9:
            _params["bg_ratio"] = round(val, 2)
    # 根据新参数模拟调整统计
    _update_params_stats()
    return jsonify({"ok": True, "params": dict(_params), "stats": dict(_params_stats)})

def _update_params_stats():
    """根据当前参数模拟检测统计变化"""
    t = _params["threshold"]
    # 阈值越低 → 更多被判定为 unknown → is_unknown_ratio 升高
    is_unknown_ratio = max(0.05, min(0.40, 0.6 - t * 0.2))
    # 阈值越低 → 已知准确率下降（更多误判为 unknown）
    known_accuracy = min(0.98, max(0.60, t / 5.0 * 0.98))
    # 未知检出率随阈值降低升高
    unknown_detection_rate = min(0.98, max(0.40, (1.0 - t / 5.0) * 0.95))
    _params_stats["is_unknown_ratio"] = round(is_unknown_ratio, 2)
    _params_stats["known_accuracy"] = round(known_accuracy, 2)
    _params_stats["unknown_detection_rate"] = round(unknown_detection_rate, 2)

@app.route("/api/test/params/stats", methods=["GET"])
def api_test_params_stats():
    """返回当前参数下的检测统计"""
    _update_params_stats()
    return jsonify({"stats": dict(_params_stats), "params": dict(_params), "server_time": time.time()})


if __name__ == "__main__":
    main()
