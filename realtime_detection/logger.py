"""Centralized logging system for realtime detection pipeline."""

from __future__ import annotations

import logging
import logging.handlers
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogConfig:
    """Configuration for logging system."""
    log_level: str = "INFO"
    log_dir: str = "./logs"
    max_file_size_mb: int = 50
    backup_count: int = 5
    console_output: bool = True
    json_format: bool = False


class DetectionLogger:
    """Unified logger for realtime detection module."""

    def __init__(self, config: Optional[LogConfig] = None):
        self.config = config or LogConfig()
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup centralized logger with file rotation and console output."""
        logger = logging.getLogger("realtime_detection")
        logger.setLevel(getattr(logging, self.config.log_level))
        logger.propagate = False

        # Clear existing handlers to avoid duplication
        logger.handlers.clear()

        # Create log directory
        os.makedirs(self.config.log_dir, exist_ok=True)

        # File handler with rotation
        log_filename = os.path.join(self.config.log_dir, f"detection_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.handlers.RotatingFileHandler(
            log_filename,
            maxBytes=self.config.max_file_size_mb * 1024 * 1024,
            backupCount=self.config.backup_count,
            encoding="utf-8"
        )

        # Console handler
        console_handler = logging.StreamHandler()

        # Formatters
        if self.config.json_format:
            formatter = JsonLogFormatter()
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s"
            )

        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        if self.config.console_output:
            logger.addHandler(console_handler)

        return logger

    def debug(self, message: str, **kwargs):
        """Log debug message."""
        extra = self._build_extra(**kwargs)
        self.logger.debug(message, extra=extra)

    def info(self, message: str, **kwargs):
        """Log info message."""
        extra = self._build_extra(**kwargs)
        self.logger.info(message, extra=extra)

    def warning(self, message: str, **kwargs):
        """Log warning message."""
        extra = self._build_extra(**kwargs)
        self.logger.warning(message, extra=extra)

    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message."""
        extra = self._build_extra(**kwargs)
        self.logger.error(message, exc_info=exc_info, extra=extra)

    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log critical message."""
        extra = self._build_extra(**kwargs)
        self.logger.critical(message, exc_info=exc_info, extra=extra)

    def log_alert(self, alert_data: dict):
        """Log alert-specific information."""
        message = (
            f"ALERT [{alert_data.get('alert_level', 'UNKNOWN')}]: "
            f"{alert_data.get('attack_type', 'unknown')} detected "
            f"from {alert_data.get('src_ip', 'unknown')} to {alert_data.get('dst_ip', 'unknown')} "
            f"(KL: {alert_data.get('kl_distance', 'N/A')}, Confidence: {alert_data.get('confidence', 'N/A')})"
        )
        self.info(message, **alert_data)

    def log_flow_processed(self, flow_id: str, is_abnormal: bool, processing_time_ms: float):
        """Log flow processing completion."""
        message = f"Flow processed: {flow_id} | Abnormal: {is_abnormal} | Time: {processing_time_ms:.2f}ms"
        self.debug(message, flow_id=flow_id, is_abnormal=is_abnormal, processing_time_ms=processing_time_ms)

    def _build_extra(self, **kwargs) -> dict:
        """Build extra context for structured logging."""
        return kwargs if kwargs else None


class JsonLogFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        
        log_entry = {
            "timestamp": self.formatTime(record),
            "logger": record.name,
            "level": record.levelname,
            "module": record.module,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        
        # Add extra fields if present
        if hasattr(record, "flow_id"):
            log_entry["flow_id"] = record.flow_id
        if hasattr(record, "is_abnormal"):
            log_entry["is_abnormal"] = record.is_abnormal
        if hasattr(record, "alert_level"):
            log_entry["alert_level"] = record.alert_level
        if hasattr(record, "attack_type"):
            log_entry["attack_type"] = record.attack_type
        
        return json.dumps(log_entry)


# Global logger instance
_global_logger: Optional[DetectionLogger] = None


def get_logger() -> DetectionLogger:
    """Get the global logger instance."""
    global _global_logger
    if _global_logger is None:
        _global_logger = DetectionLogger()
    return _global_logger


def init_logger(config: LogConfig) -> DetectionLogger:
    """Initialize the global logger with custom configuration."""
    global _global_logger
    _global_logger = DetectionLogger(config)
    return _global_logger
