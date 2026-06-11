"""A thin adaptation layer around teammate 2's inference API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import numpy as np

from predict import load_model, predict


@dataclass
class InferenceConfig:
    model_path: str = "save_model/mixed_44_split_0.pt"
    threshold: float = 5.0
    top_k: int = 1
    temperature: float = 1.0
    device: Optional[str] = None


class OpenDetectInferenceAdapter:
    """Wrap the repository model into a stable call surface for teammate 3."""

    def __init__(self, config: InferenceConfig | None = None):
        self.config = config or InferenceConfig()
        self.model = load_model(self.config.model_path, device=self.config.device)

    def infer(self, gray_img: np.ndarray) -> dict[str, Any]:
        """Run model inference and normalize the result for downstream modules."""

        results = predict(
            self.model,
            gray_img,
            top_k=self.config.top_k,
            threshold=self.config.threshold,
            temperature=self.config.temperature,
        )

        top1 = results[0]
        is_abnormal = bool(top1["is_unknown"])
        if is_abnormal:
            attack_type = "unknown_attack"
        else:
            attack_type = "known_attack" if top1.get("origin") == "mal" else "normal"

        return {
            "top_results": results,
            "top1": top1,
            "class_name": top1["class"],
            "label": top1["label"],
            "confidence": top1["confidence"],
            "distance": top1["distance"],
            "origin": top1.get("origin", "unknown"),
            "is_unknown": top1["is_unknown"],
            "is_abnormal": is_abnormal,
            "attack_type": attack_type,
            "alert_level": "CRITICAL" if attack_type == "known_attack" else ("WARNING" if is_abnormal else "INFO"),
        }


def model_inference(gray_img: np.ndarray, config: InferenceConfig | None = None) -> dict[str, Any]:
    """One-shot helper matching teammate 1 / teammate 3 integration expectations."""

    return OpenDetectInferenceAdapter(config).infer(gray_img)
