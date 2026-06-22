"""Attack simulation scripts for Open-Detect testing."""

import json
import time
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / "attack_log.jsonl"


def log_attack(attack_id: str, attack_type: str, target: str, duration: float,
               extra: dict | None = None) -> None:
    """Write an attack execution record to attack_log.jsonl."""
    record = {
        "attack_id": attack_id,
        "attack_type": attack_type,
        "target": target,
        "start_time": time.time(),
        "duration_s": round(duration, 2),
        "extra": extra or {},
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
