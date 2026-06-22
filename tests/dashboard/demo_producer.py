"""
Generate live baseline traffic for the dashboard — normal flows only.
Attack traffic is injected by the orchestrator when user clicks attack buttons.
"""
import random
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.flow_manager import FlowData
from realtime_detection.preprocess import build_gray_image


# Diverse set of normal endpoints to avoid correlation false-positives
_INTERNAL_USERS = [f"192.168.1.{n}" for n in range(100, 120)]
_WEB_SERVERS = ["93.184.216.34", "142.250.80.46", "151.101.1.140", "104.16.132.229"]
_INTERNAL_SERVERS = [f"10.0.1.{n}" for n in range(50, 70)]


def make_flow(src_ip, dst_ip, src_port, dst_port, proto, payloads):
    return FlowData(
        flow_id=f"{src_ip}:{src_port}->{dst_ip}:{dst_port}-{int(time.time()*1000)}",
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=proto, timestamp=time.time(),
        packets_data=payloads, metadata={"source": "demo"},
    )


def main():
    test_dir = Path(__file__).resolve().parent.parent
    db_path = str(test_dir / "alerts.db")
    model_path = str(test_dir.parent / "save_model" / "mixed_44_split_0.pt")

    print("[demo] Starting DetectionPipeline...")
    pipe = DetectionPipeline(
        model_path=model_path, threshold=2.24, top_k=1,
        device="cpu", db_path=db_path,
        enable_health=True, enable_correlation=True, enable_export=False,
    )
    print("[demo] Pipeline ready. Dashboard: http://localhost:5000")
    print("[demo] Generating baseline normal traffic (attacks via dashboard buttons)...")

    # Emit normal background traffic to keep the dashboard alive.
    # Alert generation is suppressed for demo-source flows (see alert_manager.py)
    # — attack alerts come from the orchestrator when user clicks attack buttons.
    i = 0
    try:
        while True:
            src = random.choice(_INTERNAL_USERS)
            ep = random.randint(50000, 60000)
            kind = random.randint(0, 2)

            if kind == 0:
                # Normal HTTP GET
                dst = random.choice(_WEB_SERVERS)
                flow = make_flow(src, dst, ep, 80, "TCP",
                                 [b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"] * 8)
            elif kind == 1:
                # Normal HTTP POST
                dst = random.choice(_WEB_SERVERS)
                body = b"username=user&password=pass"
                flow = make_flow(src, dst, ep, 80, "TCP",
                                 [f"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body] * 4)
            else:
                # Normal FTP
                dst = random.choice(_INTERNAL_SERVERS)
                flow = make_flow(src, dst, ep, 21, "TCP",
                                 [b"USER anonymous\r\nPASS guest\r\nLIST\r\nQUIT\r\n"] * 6)

            flow.gray_img = build_gray_image(flow.packets_data)
            result = pipe.process_captured_flow(flow)
            ir = result.inference_result or {}

            corr_count = result.metadata.get("correlation_alerts", 0) if result.metadata else 0

            print(f"[demo] flow #{i:3d}: src={flow.src_ip:16s} -> dst={flow.dst_ip:16s} | "
                  f"type={ir.get('attack_type','?'):18s} "
                  f"class={ir.get('class_name','?')[:20]:20s} "
                  f"level={ir.get('alert_level','-')} "
                  f"corr_cnt={corr_count}")

            i += 1
            time.sleep(random.uniform(0.8, 2.5))
    except KeyboardInterrupt:
        print("\n[demo] Stopping...")
        pipe.stop()


if __name__ == "__main__":
    main()
