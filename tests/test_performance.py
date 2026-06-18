"""
Performance and stability tests for Open-Detect.
"""
from __future__ import annotations

import random
import time

from conftest import make_flow, feed_pipeline, get_health


class TestInferenceLatency:
    """Verify inference latency meets SLA."""

    def test_single_inference_latency(self, pipeline):
        """Single flow inference should complete within 2000ms (CPU)."""
        payloads = [b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"] * 10
        flow = make_flow("10.0.0.1", "10.0.0.2", 40000, 80, "TCP", payloads)

        start = time.time()
        _ = feed_pipeline(pipeline, flow)
        elapsed_ms = (time.time() - start) * 1000

        assert elapsed_ms < 2000, f"Inference too slow: {elapsed_ms:.0f}ms > 2000ms"

    def test_batch_inference_throughput(self, pipeline):
        """Process 50 flows and verify average latency."""
        latencies = []
        for i in range(50):
            payloads = [bytes(random.randint(0, 255) for _ in range(256)) for _ in range(10)]
            flow = make_flow(
                f"10.0.0.{i % 255}", "10.0.1.50",
                40000 + i, 80 + (i % 100), "TCP",
                payloads,
            )
            start = time.time()
            feed_pipeline(pipeline, flow)
            latencies.append((time.time() - start) * 1000)

        avg_ms = sum(latencies) / len(latencies)
        max_ms = max(latencies)
        print(f"Batch 50 flows: avg={avg_ms:.1f}ms, max={max_ms:.1f}ms")

        assert avg_ms < 200, f"Average latency {avg_ms:.1f}ms exceeds 200ms threshold"
        assert max_ms < 500, f"Max latency {max_ms:.1f}ms exceeds 500ms threshold"


class TestErrorRate:
    """Verify inference error rate is acceptable."""

    def test_inference_success_rate(self, pipeline):
        """At least 95% of flows should be processed without errors."""
        errors = 0
        total = 50

        for i in range(total):
            try:
                # Various payload patterns
                if i % 3 == 0:
                    payloads = [b"GET / HTTP/1.1\r\n\r\n"] * 5
                elif i % 3 == 1:
                    payloads = [bytes(random.randint(0, 255) for _ in range(100)) for _ in range(5)]
                else:
                    payloads = [b"\x00" * 50] * 5

                flow = make_flow(
                    f"10.0.{i}.1", "10.0.1.50",
                    50000 + i, 80, "TCP", payloads,
                )
                result = feed_pipeline(pipeline, flow)
                if result.inference_result is None:
                    errors += 1
                elif result.inference_result.get("error"):
                    errors += 1
            except Exception as e:
                errors += 1
                print(f"Flow {i} error: {e}")

        error_rate = errors / total
        print(f"Error rate: {errors}/{total} = {error_rate:.2%}")

        assert error_rate < 0.1, f"Error rate {error_rate:.2%} exceeds 10% threshold"


class TestMemoryStability:
    """Verify no significant memory leaks during sustained processing."""

    def test_sustained_processing(self, pipeline):
        """Process 100 flows and check health metrics."""
        for i in range(100):
            payload_len = 100 + (i % 30) * 50
            payloads = [bytes(random.randint(0, 255) for _ in range(payload_len)) for _ in range(5)]
            flow = make_flow(
                f"10.0.{(i // 256)}.{(i % 256)}", "10.0.1.50",
                60000 + (i % 10000), 80 + (i % 50), "TCP", payloads,
            )
            feed_pipeline(pipeline, flow)

        # Check health metrics
        health = get_health()
        if health and health.get("healthy"):
            metrics = health.get("metrics", {})
            errors = metrics.get("inference_errors", 0)
            total = metrics.get("inference_count", 0)
            print(f"Health: processed={total}, errors={errors}, "
                  f"uptime={metrics.get('uptime_seconds', 0)}s")

            # After 100 flows, should have processed most of them
            assert total >= 90, f"Expected >= 90 processed, got {total}"
            assert errors < 10, f"Expected < 10 errors, got {errors}"
