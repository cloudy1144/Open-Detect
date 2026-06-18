"""Orchestrator — runs all attack simulations sequentially."""
from __future__ import annotations

import threading
import time

try:
    from .scan import run_port_scan
    from .ddos import run_syn_flood
    from .beacon import run_beacon
    from .replay import run_replay, generate_sample_pcaps
    from . import LOG_FILE
except ImportError:
    import sys
    from pathlib import Path
    _tests_dir = Path(__file__).resolve().parent.parent
    if str(_tests_dir) not in sys.path:
        sys.path.insert(0, str(_tests_dir))
    from attack_simulator.scan import run_port_scan
    from attack_simulator.ddos import run_syn_flood
    from attack_simulator.beacon import run_beacon
    from attack_simulator.replay import run_replay, generate_sample_pcaps
    from attack_simulator import LOG_FILE


def run_all(target: str = "127.0.0.1", wait_between: float = 15.0) -> dict:
    """Execute all attack types in sequence, logging each to attack_log.jsonl.

    Args:
        target: Target IP (honeypot)
        wait_between: Seconds to wait between attacks for system to settle

    Returns:
        dict with results summary
    """
    # Clear previous log
    if LOG_FILE.exists():
        LOG_FILE.unlink()

    # Generate sample PCAPs if needed
    generate_sample_pcaps()

    results = {}
    # Maps orchestrator internal names to dashboard attack_type keys
    _type_map = {
        "port_scan": "port_scan", "syn_flood": "syn_flood",
        "c2_beaconing": "c2_beaconing",
        "known_malware": "pcap_replay_known_malware",
        "unknown_attack": "pcap_replay_unknown_attack",
        "normal_traffic": "pcap_replay_normal",
        "tls13_encrypted": "pcap_replay_tls13",
    }
    attacks = [
        ("port_scan", lambda: run_port_scan(target, 20, 50)),
        ("syn_flood", lambda: run_syn_flood(target, 8080, duration=5.0, rate=50)),
        ("c2_beaconing", lambda: run_beacon(target, 8443, interval=30.0, count=6)),
        ("known_malware", lambda: run_replay("known_malware", target)),
        ("unknown_attack", lambda: run_replay("unknown_attack", target)),
        ("normal_traffic", lambda: run_replay("normal", target)),
        ("tls13_encrypted", lambda: run_replay("tls13", target)),
    ]

    for name, attack_fn in attacks:
        print(f"\n{'='*50}")
        print(f"[orchestrator] Running: {name}")
        print(f"{'='*50}")
        # Notify dashboard this step is running
        if step_callback:
            step_callback(_type_map.get(name, name))
        try:
            duration = attack_fn()
            results[name] = {"status": "ok", "duration_s": round(duration, 2)}
            print(f"[orchestrator] {name} completed in {duration:.1f}s")
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)}
            print(f"[orchestrator] {name} FAILED: {e}")
            if step_callback:
                step_callback(_type_map.get(name, name))  # mark done even on error

        if name != "c2_beaconing":  # beacon runs 3 min, skip extra wait
            print(f"[orchestrator] Waiting {wait_between}s...")
            time.sleep(wait_between)

    print(f"\n{'='*50}")
    print("[orchestrator] All attacks complete. Summary:")
    for name, r in results.items():
        status = r["status"]
        dur = r.get("duration_s", "N/A")
        print(f"  {name:20s} -> {status:5s} ({dur}s)")
    print(f"{'='*50}")
    return results


def run_all_with_stop(target: str = "127.0.0.1", wait_between: float = 15.0,
                      stop_event: threading.Event | None = None,
                      step_callback=None) -> dict:
    """Same as run_all but checks stop_event between attacks to allow early termination."""
    # Clear previous log
    if LOG_FILE.exists():
        LOG_FILE.unlink()

    # Generate sample PCAPs if needed
    generate_sample_pcaps()

    _type_map = {
        "port_scan": "port_scan", "syn_flood": "syn_flood",
        "c2_beaconing": "c2_beaconing",
        "known_malware": "pcap_replay_known_malware",
        "unknown_attack": "pcap_replay_unknown_attack",
        "normal_traffic": "pcap_replay_normal",
        "tls13_encrypted": "pcap_replay_tls13",
    }

    results = {}
    attacks = [
        ("port_scan", lambda: run_port_scan(target, 20, 50)),
        ("syn_flood", lambda: run_syn_flood(target, 8080, duration=5.0, rate=50)),
        ("c2_beaconing", lambda: run_beacon(target, 8443, interval=3.0, count=2)),
        ("known_malware", lambda: run_replay("known_malware", target)),
        ("unknown_attack", lambda: run_replay("unknown_attack", target)),
        ("normal_traffic", lambda: run_replay("normal", target)),
        ("tls13_encrypted", lambda: run_replay("tls13", target)),
    ]

    for name, attack_fn in attacks:
        # Check stop signal before each attack
        if stop_event and stop_event.is_set():
            results[name] = {"status": "cancelled", "reason": "stop requested"}
            print(f"[orchestrator] {name} CANCELLED (stop signal)")
            if step_callback:
                step_callback(_type_map.get(name, name))
            break

        print(f"\n{'='*50}")
        print(f"[orchestrator] Running: {name}")
        print(f"{'='*50}")
        try:
            duration = attack_fn()
            results[name] = {"status": "ok", "duration_s": round(duration, 2)}
            print(f"[orchestrator] {name} completed in {duration:.1f}s")
        except Exception as e:
            results[name] = {"status": "error", "error": str(e)}
            print(f"[orchestrator] {name} FAILED: {e}")

        # Notify dashboard this step completed
        if step_callback:
            step_callback(_type_map.get(name, name))

        if name != "c2_beaconing":
            # Check stop signal during wait period too
            if stop_event and stop_event.is_set():
                remaining = [(n, f) for n, f in attacks if n not in results]
                for n, _ in remaining:
                    results[n] = {"status": "cancelled", "reason": "stop during wait"}
                    if step_callback:
                        step_callback(_type_map.get(n, n))
                break
            print(f"[orchestrator] Waiting {wait_between}s...")
            # Sleep in small chunks to be responsive to stop signal
            waited = 0.0
            while waited < wait_between:
                if stop_event and stop_event.is_set():
                    remaining = [(n, f) for n, f in attacks if n not in results]
                    for n, _ in remaining:
                        results[n] = {"status": "cancelled", "reason": "stop during wait"}
                        if step_callback:
                            step_callback(_type_map.get(n, n))
                    break
                time.sleep(0.5)
                waited += 0.5

    print(f"\n{'='*50}")
    print("[orchestrator] Complete. Summary:")
    for name, r in results.items():
        status = r["status"]
        dur = r.get("duration_s", "N/A")
        print(f"  {name:20s} -> {status:10s} ({dur}s)")
    print(f"{'='*50}")
    return results


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="127.0.0.1")
    p.add_argument("--wait", type=float, default=15.0)
    args = p.parse_args()
    run_all(args.target, args.wait)
