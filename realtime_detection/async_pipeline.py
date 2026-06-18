"""Async and batch processing extensions for high-performance scenarios."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, List, Optional, Tuple

import numpy as np

from .alert_manager import Alert, AlertManager
from .dynamic_threshold import DynamicThresholdManager, ThresholdConfig
from .exporter import export_abnormal_flow
from .flow_correlation import FlowCorrelationEngine, CorrelationAlert
from .flow_manager import FlowData, FlowManager
from .health import MetricsCollector
from .logger import get_logger
from .model_adapter import InferenceConfig, OpenDetectInferenceAdapter
from .preprocess import build_gray_image

logger = get_logger()


@dataclass
class BatchProcessingResult:
    """Result of batch processing."""
    processed_count: int = 0
    abnormal_count: int = 0
    total_time_ms: float = 0.0
    avg_time_per_flow_ms: float = 0.0
    errors: List[Tuple[str, str]] = field(default_factory=list)


class AsyncDetectionPipeline:
    """High-performance async pipeline for concurrent flow processing."""

    def __init__(
        self,
        model_path: str = "save_model/mixed_44_split_0.pt",
        threshold: float = 2.24,
        top_k: int = 1,
        temperature: float = 1.0,
        expire_minutes: int = 5,
        export_dir: str = "./abnormal_flows",
        enable_export: bool = True,
        device: Optional[str] = None,
        max_workers: int = 4,
        batch_size: int = 32,
        class_thresholds: dict[int, float] | None = None,
        recon_threshold: float = 0.15,
        bg_ratio: float = 0.7,
        enable_correlation: bool = True,
        enable_dynamic_threshold: bool = False,
        baseline_kl_distances: Optional[list[float]] = None,
    ):
        self.flow_manager = FlowManager(expire_minutes=expire_minutes)
        self.alert_manager = AlertManager()
        self.predictor = OpenDetectInferenceAdapter(
            InferenceConfig(
                model_path=model_path,
                threshold=threshold,
                top_k=top_k,
                temperature=temperature,
                device=device,
                class_thresholds=class_thresholds,
                recon_threshold=recon_threshold,
                bg_ratio=bg_ratio,
            )
        )
        self.export_dir = export_dir
        self.enable_export = enable_export
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.batch_size = batch_size
        self._lock = asyncio.Lock()

        # Dynamic threshold integration
        self.threshold_manager = DynamicThresholdManager(
            ThresholdConfig(baseline_kl_distances=baseline_kl_distances or [])
        )
        self.threshold_manager.register_update_callback(self._on_threshold_update)
        self.enable_dynamic_threshold = enable_dynamic_threshold

        # Multi-flow correlation engine
        self.correlation_engine = FlowCorrelationEngine() if enable_correlation else None

        # Metrics
        self.metrics = MetricsCollector()

    def _on_threshold_update(self, new_threshold: float):
        """Update predictor threshold when dynamic threshold changes."""
        self.predictor.config.threshold = new_threshold
        logger.info(f"Dynamic threshold updated: {new_threshold:.4f}")

    async def process_captured_flow_async(self, flow: FlowData) -> FlowData:
        """Process a single flow asynchronously."""
        loop = asyncio.get_event_loop()
        
        # Check for duplicates in async-safe manner
        async with self._lock:
            if self.flow_manager.is_flow_processed(flow.flow_id):
                return flow
            self.flow_manager.add_flow(flow)

        # Offload CPU-intensive operations to thread pool
        result = await loop.run_in_executor(self.executor, self._process_flow_sync, flow)
        return result

    def _process_flow_sync(self, flow: FlowData) -> FlowData:
        """Synchronous flow processing (runs in thread pool)."""
        start_time = time.time()
        
        try:
            # Preprocess
            if flow.gray_img is None:
                flow.gray_img = build_gray_image(flow.packets_data)

            # Inference
            try:
                inference_result = self.predictor.infer(flow.gray_img)
            except Exception:
                self.metrics.inc_inference_errors()
                flow.metadata["error"] = "inference_failed"
                return flow

            self.metrics.inc_inference_count()
            flow.inference_result = inference_result
            flow.is_abnormal = bool(inference_result.get("is_abnormal", False))

            if flow.is_abnormal:
                self.metrics.inc_flows_abnormal()

            # Export if abnormal
            export_path = None
            if flow.is_abnormal and self.enable_export:
                export_path = export_abnormal_flow(flow, self.export_dir)
                flow.export_path = export_path

            # Update flow manager
            self.flow_manager.mark_processed(
                flow.flow_id,
                inference_result,
                is_abnormal=flow.is_abnormal,
                export_path=export_path,
            )

            # Trigger alert
            alert = self.alert_manager.trigger_alert(flow, inference_result)
            if alert is not None:
                flow.metadata["alert_id"] = alert.alert_id
                logger.log_alert(asdict(alert))

            # Feed to multi-flow correlation engine
            if self.correlation_engine:
                corr_alerts = self.correlation_engine.feed_flow(flow)
                flow.metadata["correlation_alerts"] = len(corr_alerts)
                if corr_alerts:
                    self.metrics.inc_correlation_alerts(len(corr_alerts))

            processing_time = (time.time() - start_time) * 1000
            self.metrics.record_inference_latency_ms(processing_time)
            self.metrics.inc_flows_total()
            logger.log_flow_processed(flow.flow_id, flow.is_abnormal, processing_time)

        except Exception as e:
            logger.error(f"Error processing flow {flow.flow_id}: {str(e)}", exc_info=True)
            flow.metadata["error"] = str(e)
            self.metrics.inc_inference_errors()
            self.metrics.inc_flows_total()

        return flow

    async def process_batch_async(self, flows: List[FlowData]) -> BatchProcessingResult:
        """Process multiple flows concurrently with batching."""
        start_time = time.time()
        result = BatchProcessingResult()
        result.processed_count = len(flows)

        # Process flows in chunks
        for i in range(0, len(flows), self.batch_size):
            batch = flows[i:i+self.batch_size]
            tasks = [self.process_captured_flow_async(flow) for flow in batch]
            completed = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, flow_or_error in enumerate(completed):
                original_flow = batch[idx]
                if isinstance(flow_or_error, Exception):
                    result.errors.append((original_flow.flow_id, str(flow_or_error)))
                else:
                    if flow_or_error.is_abnormal:
                        result.abnormal_count += 1

        result.total_time_ms = (time.time() - start_time) * 1000
        result.avg_time_per_flow_ms = result.total_time_ms / len(flows) if flows else 0.0

        logger.info(
            f"Batch processing completed: {len(flows)} flows, "
            f"{result.abnormal_count} abnormal, "
            f"{result.total_time_ms:.2f}ms total, "
            f"{result.avg_time_per_flow_ms:.2f}ms avg"
        )

        return result

    async def process_raw_packets_async(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        timestamp: float,
        packets_data: list[bytes],
        metadata: Optional[dict[str, Any]] = None,
    ) -> FlowData:
        """Create and process a FlowData record from raw inputs asynchronously."""
        flow = FlowData(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp=timestamp,
            packets_data=packets_data,
            metadata=metadata or {},
        )
        return await self.process_captured_flow_async(flow)

    def update_dynamic_threshold(self, baseline_kl_distances: List[float]) -> float:
        """Update dynamic threshold using baseline data from teammate 2."""
        self.threshold_manager.update_baseline(baseline_kl_distances)
        return self.threshold_manager.get_threshold()

    def get_threshold_statistics(self) -> dict:
        """Get current dynamic threshold statistics."""
        return self.threshold_manager.get_statistics()

    def get_alert_history(self, start_time: Optional[float] = None, end_time: Optional[float] = None) -> List[Alert]:
        return self.alert_manager.get_alert_history(start_time, end_time)

    def get_flow_history(self) -> List[FlowData]:
        return self.flow_manager.get_all_flows()

    def register_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        self.alert_manager.register_alert_callback(callback)

    def register_correlation_callback(self, callback) -> None:
        """Register callback for correlation alerts (beaconing, scanning)."""
        if self.correlation_engine:
            self.correlation_engine.register_alert_callback(callback)

    async def close(self):
        """Cleanup resources."""
        self.executor.shutdown(wait=True)
        self.flow_manager.stop_cleaner()
        if self.correlation_engine:
            self.correlation_engine.stop()

    def snapshot(self) -> dict[str, Any]:
        """Return a simple serializable snapshot for monitoring."""
        return {
            "flow_count": len(self.flow_manager.get_all_flows()),
            "alert_count": len(self.alert_manager.get_alert_history()),
            "threshold_statistics": self.threshold_manager.get_statistics(),
            "correlation": self.correlation_engine.snapshot() if self.correlation_engine else {},
        }


class BatchInferenceAdapter:
    """Batch inference adapter for improved GPU throughput."""

    def __init__(self, predictor: OpenDetectInferenceAdapter, batch_size: int = 32):
        self.predictor = predictor
        self.batch_size = batch_size

    def infer_batch(self, gray_images: List[np.ndarray]) -> List[dict[str, Any]]:
        """Run true batched inference using predict_batch.

        Stacks images into a single tensor and invokes the model once
        per batch, yielding ~30x throughput improvement over sequential.
        """
        from predict import predict_batch

        all_results: List[dict[str, Any]] = []
        for i in range(0, len(gray_images), self.batch_size):
            batch = gray_images[i:i + self.batch_size]
            batch_results = predict_batch(
                self.predictor.model,
                batch,
                top_k=self.predictor.config.top_k,
                threshold=self.predictor.config.threshold,
                temperature=self.predictor.config.temperature,
                class_thresholds=self.predictor.config.class_thresholds,
                recon_threshold=self.predictor.config.recon_threshold,
                bg_ratio=self.predictor.config.bg_ratio,
            )
            # Flatten: each image has list[dict], take top1 for compatibility
            for results in batch_results:
                all_results.append(results[0] if results else {"error": "no results"})
        return all_results
