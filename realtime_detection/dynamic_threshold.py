"""Dynamic threshold calculation module - integrates with teammate 2's baseline data."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np


@dataclass
class ThresholdConfig:
    """Configuration for dynamic threshold calculation."""
    baseline_kl_distances: list[float] = None
    multiplier: float = 1.5  # 可调节的标准差倍数
    min_threshold: float = 0.0
    max_threshold: float = 10.0
    update_interval_seconds: int = 300  # 阈值自动更新间隔（默认5分钟）
    auto_update_enabled: bool = True  # 是否启用自动更新


class DynamicThresholdManager:
    """Manage adaptive threshold based on baseline KL distances from teammate 2."""

    def __init__(self, config: Optional[ThresholdConfig] = None):
        self.config = config or ThresholdConfig()
        self.current_threshold = self.config.min_threshold
        self.baseline_mean = 0.0
        self.baseline_std = 1.0
        self._update_callback: Optional[Callable[[float], None]] = None
        self._data_source_callback: Optional[Callable[[], list[float]]] = None
        
        # 定时更新相关
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None

        if self.config.baseline_kl_distances:
            self.update_baseline(self.config.baseline_kl_distances)
        
        # 启动定时更新线程
        if self.config.auto_update_enabled:
            self.start_auto_update()

    def update_baseline(self, kl_distances: list[float]) -> None:
        """Update baseline statistics from teammate 2's normal flow data."""
        if not kl_distances:
            return

        self.baseline_mean = float(np.mean(kl_distances))
        self.baseline_std = float(np.std(kl_distances))
        
        # 动态阈值 = 均值 + multiplier × 标准差
        new_threshold = self.baseline_mean + self.config.multiplier * self.baseline_std
        
        # 应用边界约束
        self.current_threshold = max(
            self.config.min_threshold,
            min(self.config.max_threshold, new_threshold)
        )

        if self._update_callback:
            self._update_callback(self.current_threshold)

    def get_threshold(self) -> float:
        """Return the current dynamic threshold."""
        return self.current_threshold

    def register_update_callback(self, callback: Callable[[float], None]) -> None:
        """Register callback for threshold updates."""
        self._update_callback = callback

    def register_data_source_callback(self, callback: Callable[[], list[float]]) -> None:
        """
        Register a callback to fetch latest baseline data from teammate 2.
        
        Args:
            callback: A function that returns a list of KL distances from normal flows.
                      This callback will be called periodically to update the threshold.
        """
        self._data_source_callback = callback

    def get_statistics(self) -> dict:
        """Return current baseline statistics."""
        return {
            "mean": self.baseline_mean,
            "std": self.baseline_std,
            "threshold": self.current_threshold,
            "multiplier": self.config.multiplier,
            "sample_count": len(self.config.baseline_kl_distances) if self.config.baseline_kl_distances else 0,
            "auto_update_enabled": self.config.auto_update_enabled,
            "update_interval_seconds": self.config.update_interval_seconds,
            "last_update_time": getattr(self, '_last_update_time', None),
        }

    def suggest_multiplier(self, target_fpr: float = 0.01) -> float:
        """
        Suggest a multiplier based on target false positive rate.
        Uses empirical normal distribution approximation.
        """
        if self.baseline_std == 0:
            return self.config.multiplier
        
        # 基于标准正态分布的近似
        # FPR = 0.01 ≈ multiplier = 2.33
        # FPR = 0.05 ≈ multiplier = 1.64
        # FPR = 0.10 ≈ multiplier = 1.28
        fpr_to_multiplier = {
            0.001: 3.29,
            0.005: 2.58,
            0.01: 2.33,
            0.025: 1.96,
            0.05: 1.64,
            0.10: 1.28,
            0.15: 1.04,
            0.20: 0.84,
        }
        
        # 查找最接近的目标FPR对应的multiplier
        closest_fpr = min(fpr_to_multiplier.keys(), key=lambda x: abs(x - target_fpr))
        return fpr_to_multiplier[closest_fpr]

    def start_auto_update(self) -> None:
        """Start the background thread for automatic threshold updates."""
        if self._update_thread and self._update_thread.is_alive():
            return
        
        def auto_update_loop():
            while not self._stop_event.wait(self.config.update_interval_seconds):
                if self._data_source_callback:
                    try:
                        # 从队员2获取最新基线数据
                        latest_kl_distances = self._data_source_callback()
                        if latest_kl_distances:
                            self.update_baseline(latest_kl_distances)
                            self._last_update_time = time.time()
                    except Exception as e:
                        # 静默处理数据源获取失败，避免影响主流程
                        pass
        
        self._stop_event.clear()
        self._update_thread = threading.Thread(target=auto_update_loop, daemon=True)
        self._update_thread.start()

    def stop_auto_update(self) -> None:
        """Stop the automatic threshold update thread."""
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=5)

    def trigger_manual_update(self) -> float:
        """
        Trigger an immediate manual update of the threshold.
        
        Returns:
            The new threshold value after update, or None if update failed.
        """
        if self._data_source_callback:
            try:
                latest_kl_distances = self._data_source_callback()
                if latest_kl_distances:
                    self.update_baseline(latest_kl_distances)
                    self._last_update_time = time.time()
                    return self.current_threshold
            except Exception as e:
                pass
        return None
