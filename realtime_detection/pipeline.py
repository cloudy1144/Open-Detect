"""End-to-end realtime detection pipeline for teammate 3."""

from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any, Optional

from .alert_manager import Alert, AlertManager
from .config import get_pipeline_config, get_model_config
from .dynamic_threshold import DynamicThresholdManager, ThresholdConfig
from .exporter import export_abnormal_flow
from .flow_correlation import FlowCorrelationEngine, CorrelationAlert
from .flow_manager import FlowData, FlowManager
from .health import HealthChecker, MetricsCollector
from .logger import get_logger
from .model_adapter import InferenceConfig, OpenDetectInferenceAdapter
from .preprocess import build_gray_image
from .protocol_parser import extract_protocol_metadata

logger = get_logger()


class DetectionPipeline:
    """Wire flow management, inference, alerting, and export together."""

    def __init__(
        self,
        model_path: str = "save_model/mixed_44_split_0.pt",
        threshold: float = 2.24,
        top_k: int = 1,
        temperature: float = 1.0,
        expire_minutes: int = 5,
        cooldown_seconds: int = 60,
        export_dir: str = "./abnormal_flows",
        enable_export: bool = True,
        device: Optional[str] = None,
        enable_dynamic_threshold: bool = False,
        baseline_kl_distances: Optional[list[float]] = None,
        enable_correlation: bool = True,
        enable_health: bool = True,
        class_thresholds: dict[int, float] | None = None,
        recon_threshold: float = 0.15,
        bg_ratio: float = 0.7,
        db_path: Optional[str] = None,
    ):
        # Load defaults from config.yaml for any unspecified parameter
        try:
            pipe_cfg = get_pipeline_config()
            model_cfg = get_model_config()
            if db_path is None:
                db_path = pipe_cfg.get("db_path") or None
        except Exception:
            pipe_cfg, model_cfg = {}, {}

        self.flow_manager = FlowManager(expire_minutes=expire_minutes, cooldown_seconds=cooldown_seconds)
        self.alert_manager = AlertManager(db_path=db_path)
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

        # Dynamic threshold integration
        self.threshold_manager = DynamicThresholdManager(
            ThresholdConfig(baseline_kl_distances=baseline_kl_distances or [])
        )
        self.threshold_manager.register_update_callback(self._on_threshold_update)
        self.enable_dynamic_threshold = enable_dynamic_threshold

        # Multi-flow correlation engine
        self.correlation_engine = FlowCorrelationEngine() if enable_correlation else None
        if self.correlation_engine:
            self.correlation_engine.register_alert_callback(self._on_correlation_alert)

        # Metrics & Health
        self.metrics = MetricsCollector()
        self.health_checker: Optional[HealthChecker] = None
        if enable_health:
            self.health_checker = HealthChecker(
                get_status=self._health_status,
                get_metrics=self.metrics.snapshot,
            )
            self.health_checker.start()

    def _on_threshold_update(self, new_threshold: float):
        """Update predictor threshold when dynamic threshold changes."""
        self.predictor.config.threshold = new_threshold
        logger.info(f"Dynamic threshold updated: {new_threshold:.4f}")

    def update_dynamic_threshold(self, baseline_kl_distances: list[float]) -> float:
        """Update dynamic threshold using baseline data from teammate 2."""
        self.threshold_manager.update_baseline(baseline_kl_distances)
        return self.threshold_manager.get_threshold()

    def get_threshold_statistics(self) -> dict:
        """Get current dynamic threshold statistics."""
        return self.threshold_manager.get_statistics()

    def register_alert_callback(self, callback):
        """Forward alert callbacks to the alert manager."""
        self.alert_manager.register_alert_callback(callback)

    def process_captured_flow(self, flow: FlowData) -> FlowData:
        """Process a flow created by teammate 1 or by local mock data."""
        start_time = time.time()

        self.flow_manager.add_flow(flow)
        if self.flow_manager.is_flow_processed(flow.flow_id):
            self.metrics.inc_flows_total()
            return flow

        if flow.gray_img is None:
            flow.gray_img = build_gray_image(flow.packets_data)

        # Extract protocol metadata for alert enrichment
        try:
            proto_meta = extract_protocol_metadata(flow)
            flow.metadata["protocol"] = proto_meta.to_dict()
        except Exception:
            pass  # non-critical

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
            # Demo baseline traffic is counted as "flowing" but not abnormal
            if flow.metadata.get("source") != "demo":
                self.metrics.inc_flows_abnormal()

        export_path = None
        if flow.is_abnormal and self.enable_export:
            export_path = export_abnormal_flow(flow, self.export_dir)
            flow.export_path = export_path

        self.flow_manager.mark_processed(
            flow.flow_id,
            inference_result,
            is_abnormal=flow.is_abnormal,
            export_path=export_path,
        )

        alert = self.alert_manager.trigger_alert(flow, inference_result)
        if alert is not None:
            flow.metadata["alert_id"] = alert.alert_id
            logger.log_alert(asdict(alert))
            if export_path is not None:
                flow.metadata["export_path"] = export_path

        # Feed to multi-flow correlation engine (skip demo baseline traffic)
        if self.correlation_engine and flow.metadata.get("source") != "demo":
            corr_alerts = self.correlation_engine.feed_flow(flow)
            flow.metadata["correlation_alerts"] = len(corr_alerts)
            if corr_alerts:
                self.metrics.inc_correlation_alerts(len(corr_alerts))

        # Log processing time
        processing_time_ms = (time.time() - start_time) * 1000
        self.metrics.record_inference_latency_ms(processing_time_ms)
        self.metrics.inc_flows_total()
        logger.log_flow_processed(flow.flow_id, flow.is_abnormal, processing_time_ms)

        return flow

    def process_raw_packets(
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
        """Create a FlowData record from raw teammate 1 style inputs."""
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
        return self.process_captured_flow(flow)

    def get_alert_history(self, start_time: float | None = None, end_time: float | None = None) -> list[Alert]:
        return self.alert_manager.get_alert_history(start_time, end_time)

    def get_flow_history(self) -> list[FlowData]:
        return self.flow_manager.get_all_flows()

    def snapshot(self) -> dict[str, Any]:
        """Return a simple serializable snapshot for UI or debugging."""
        flows = [asdict(flow) for flow in self.get_flow_history()]
        alerts = [asdict(alert) for alert in self.get_alert_history()]
        threshold_stats = self.get_threshold_statistics()
        correlation = self.correlation_engine.snapshot() if self.correlation_engine else {}
        
        return {
            "flows": flows,
            "alerts": alerts,
            "flow_count": len(flows),
            "alert_count": len(alerts),
            "threshold_statistics": threshold_stats,
            "correlation": correlation,
        }

    def _health_status(self) -> dict[str, Any]:
        """Generate health check status for HealthChecker."""
        return {
            "model_loaded": self.predictor.model is not None,
            "device": str(self.predictor.config.device or "auto"),
            "enable_dynamic_threshold": self.enable_dynamic_threshold,
            "enable_correlation": self.correlation_engine is not None,
            "enable_export": self.enable_export,
        }

    def _on_correlation_alert(self, alert) -> None:
        """Handle correlation alerts (beaconing, scanning, bidirectional asymmetry)."""
        logger.warning(
            f"[CORRELATION] {alert.alert_type}: {alert.description[:200]}",
            alert_type=alert.alert_type,
            src_ip=alert.src_ip,
        )
        # Also feed back to alert_manager for unified query interface
        self.alert_manager.trigger_correlation_alert(alert)

    def stop(self) -> None:
        """Gracefully stop all background threads."""
        self.flow_manager.stop_cleaner()
        self.threshold_manager.stop_auto_update()
        if self.health_checker:
            self.health_checker.stop()
        if self.correlation_engine:
            self.correlation_engine.stop()
