"""Command line demo for the realtime detection chain."""

from __future__ import annotations

import argparse
from pprint import pprint

from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.preprocess import mock_flow_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Team 3 realtime detection demo")
    parser.add_argument("--model", default="save_model/mixed_44_split_0.pt", help="model path")
    parser.add_argument("--threshold", type=float, default=5.0, help="unknown detection threshold")
    parser.add_argument("--top_k", type=int, default=1, help="top-k predictions")
    parser.add_argument("--temperature", type=float, default=1.0, help="softmax temperature")
    parser.add_argument("--export-dir", default="./abnormal_flows", help="pcap export directory")
    parser.add_argument("--no-export", action="store_true", help="disable pcap export")
    args = parser.parse_args()

    pipeline = DetectionPipeline(
        model_path=args.model,
        threshold=args.threshold,
        top_k=args.top_k,
        temperature=args.temperature,
        export_dir=args.export_dir,
        enable_export=not args.no_export,
    )

    def on_alert(alert):
        print("[ALERT]", alert.alert_level, alert.attack_type, alert.src_ip, "->", alert.dst_ip)

    pipeline.register_alert_callback(on_alert)

    flow = mock_flow_data()
    processed = pipeline.process_captured_flow(flow)

    print("\nFlow result:")
    pprint(processed.inference_result)
    print("\nAlert history:")
    pprint([alert.__dict__ for alert in pipeline.get_alert_history()])
    print("\nSnapshot:")
    pprint(pipeline.snapshot())


if __name__ == "__main__":
    main()
