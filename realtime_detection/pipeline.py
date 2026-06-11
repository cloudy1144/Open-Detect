"""End-to-end realtime detection pipeline for teammate 3."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Optional

from .alert_manager import Alert, AlertManager
from .exporter import export_abnormal_flow
from .flow_manager import FlowData, FlowManager
from .model_adapter import InferenceConfig, OpenDetectInferenceAdapter
from .preprocess import build_gray_image


class DetectionPipeline:
    """Wire flow management, inference, alerting, and export together."""

    def __init__(
        self,
        model_path: str = "save_model/mixed_44_split_0.pt",
        threshold: float = 5.0,
        top_k: int = 1,
        temperature: float = 1.0,
        expire_minutes: int = 5,
        export_dir: str = "./abnormal_flows",
        enable_export: bool = True,
        device: Optional[str] = None,
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
            )
        )
        self.export_dir = export_dir
        self.enable_export = enable_export

    def register_alert_callback(self, callback):
        """Forward alert callbacks to the alert manager."""

        self.alert_manager.register_alert_callback(callback)

    def process_captured_flow(self, flow: FlowData) -> FlowData:
        """Process a flow created by teammate 1 or by local mock data."""

        self.flow_manager.add_flow(flow)
        if self.flow_manager.is_flow_processed(flow.flow_id):
            return flow

        if flow.gray_img is None:
            flow.gray_img = build_gray_image(flow.packets_data)

        inference_result = self.predictor.infer(flow.gray_img)
        flow.inference_result = inference_result
        flow.is_abnormal = bool(inference_result.get("is_abnormal", False))

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
        if alert is not None and export_path is not None:
            flow.metadata["alert_id"] = alert.alert_id
            flow.metadata["export_path"] = export_path

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
        return {
            "flows": flows,
            "alerts": alerts,
            "flow_count": len(flows),
            "alert_count": len(alerts),
        }
