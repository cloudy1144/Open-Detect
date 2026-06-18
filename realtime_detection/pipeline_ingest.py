"""Pipeline ingest: reads JSON Lines from stdin and pipes to DetectionPipeline.

Decouples capture (teammate 1) from detection (teammate 3):

  # Same machine (current mode):
  sudo python -m realtime_detection.capture --iface eth0 | python -m realtime_detection.pipeline_ingest

  # Cross-machine (production):
  ssh capture-box sudo python -m realtime_detection.capture --iface eth0 | python -m realtime_detection.pipeline_ingest

  # Replay recorded traffic:
  cat recorded.jsonl | python -m realtime_detection.pipeline_ingest

Input format (one JSON object per line from capture.py):
  {"ts": ..., "event": "flow_result", "flow_id": "x", "src": "ip:port",
   "dst": "ip:port", "proto": "TCP", ...}

Output (one JSON object per processed flow, to stdout):
  {"ts": ..., "event": "processed", "flow_id": "x", "is_abnormal": false,
   "attack_type": "normal", "alert_level": "INFO", ...}
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

# Ensure the package root is importable when run directly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from realtime_detection.flow_manager import FlowData
from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.preprocess import build_flow_id, build_gray_image


def parse_flow_from_line(line: str) -> Optional[FlowData]:
    """Parse a capture.py JSON line into a FlowData object.

    Supports capture.py events:
      - flow_result: has full metadata, extract what we need
      - flow_start:  lighter, just flow info + packets info (requires capture --debug)
    """
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    event = data.get("event", "")
    if event not in ("flow_result", "flow_start"):
        return None

    # Extract necessary fields (capture.py sends src/dst as "ip:port")
    src_ip, _, src_port_str = data.get("src", "0.0.0.0:0").partition(":")
    dst_ip, _, dst_port_str = data.get("dst", "0.0.0.0:0").partition(":")
    try:
        src_port = int(src_port_str)
        dst_port = int(dst_port_str)
    except ValueError:
        return None

    flow_id = data.get("flow_id", "")
    if not flow_id:
        flow_id = build_flow_id(src_ip, src_port, dst_ip, dst_port, time.time())

    proto = data.get("proto", "TCP")
    ts = data.get("ts", time.time())
    packet_count = data.get("packets", data.get("packet_count", 0))

    # Reconstruct minimal FlowData — packets_data is empty because
    # capture.py already consumed them.  When streams are piped in,
    # the detection result from capture.py is authoritative.
    flow = FlowData(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        timestamp=ts,
        packets_data=[],  # no raw packets in JSON mode
        metadata={
            "source": "pipeline_ingest",
            "packet_count": packet_count,
        },
    )

    # If capture.py already ran inference (flow_result), use existing results
    # This handles the case where capture.py already had --no-pipeline=False
    if event == "flow_result" and data.get("is_abnormal") is not None:
        flow.is_abnormal = data.get("is_abnormal")
        flow.inference_result = {
            "class_name": data.get("class_name"),
            "attack_type": data.get("attack_type"),
            "alert_level": data.get("alert_level"),
            "confidence": data.get("confidence"),
            "distance": data.get("distance"),
            "commit_ratio": data.get("commit_ratio"),
            "is_abnormal": data.get("is_abnormal"),
        }
        flow.processed_at = ts

    return flow


def main():
    """Read JSON Lines from stdin, process each, write results to stdout."""
    pipeline = DetectionPipeline(
        enable_export=False,  # export on capture side, not here
        enable_health=True,
    )

    processed = 0
    errors = 0
    abnormal = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        flow = parse_flow_from_line(line)
        if flow is None:
            continue

        try:
            # If already processed by capture.py, emit and skip
            if flow.processed_at is not None:
                ir = flow.inference_result or {}
                _emit_result(flow, ir, "skip")
                continue

            # Generate gray image — will fail gracefully (empty packets)
            if not flow.packets_data:
                _emit_result(flow, {}, "skip")
                continue

            flow.gray_img = build_gray_image(flow.packets_data)
            result = pipeline.process_captured_flow(flow)
            ir = result.inference_result or {}
            processed += 1
            if result.is_abnormal:
                abnormal += 1
            _emit_result(result, ir, "processed")

        except KeyboardInterrupt:
            raise
        except Exception as exc:
            errors += 1
            _emit_result(flow, {"error": str(exc)}, "error")

    pipeline.stop()

    # Final summary to stderr
    summary = {
        "event": "ingest_summary",
        "processed": processed,
        "abnormal": abnormal,
        "errors": errors,
        "ts": time.time(),
    }
    print(json.dumps(summary), file=sys.stderr, flush=True)


def _emit_result(flow: FlowData, ir: dict[str, Any], event: str) -> None:
    """Emit a processed result as JSON line."""
    record = {
        "ts": time.time(),
        "event": event,
        "flow_id": flow.flow_id,
        "src": f"{flow.src_ip}:{flow.src_port}",
        "dst": f"{flow.dst_ip}:{flow.dst_port}",
        "proto": flow.protocol,
        "is_abnormal": flow.is_abnormal,
        "class_name": ir.get("class_name"),
        "attack_type": ir.get("attack_type"),
        "alert_level": ir.get("alert_level"),
        "confidence": ir.get("confidence"),
        "distance": ir.get("distance"),
        "commit_ratio": ir.get("commit_ratio"),
        "error": ir.get("error"),
    }
    # Strip None values
    record = {k: v for k, v in record.items() if v is not None}
    print(json.dumps(record, default=str), flush=True)


if __name__ == "__main__":
    main()
