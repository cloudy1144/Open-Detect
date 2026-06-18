"""Centralized configuration loader for realtime detection.

Loads from config.yaml (next to this file) with environment variable overrides.
Env vars: OD_<SECTION>_<KEY>  (e.g. OD_MODEL_threshold=3.0 → model.threshold=3.0)
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = CONFIG_DIR / "config.yaml"


def _load_raw() -> dict[str, Any]:
    if DEFAULT_CONFIG.exists():
        with open(DEFAULT_CONFIG) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    # Environment variable overrides: OD_MODEL_threshold=3.0 → model.threshold=3.0
    for key, value in os.environ.items():
        if not key.startswith("OD_"):
            continue
        parts = key[3:].lower().split("_", 1)
        if len(parts) != 2:
            continue
        section, field = parts
        if section not in raw:
            raw[section] = {}
        try:
            raw[section][field] = float(value)
        except ValueError:
            raw[section][field] = value
    return raw


@lru_cache(maxsize=1)
def get_config() -> dict[str, Any]:
    return _load_raw()


def get_model_config() -> dict[str, Any]:
    return get_config().get("model", {})


def get_pipeline_config() -> dict[str, Any]:
    return get_config().get("pipeline", {})


def get_capture_config() -> dict[str, Any]:
    return get_config().get("capture", {})


def get_correlation_config() -> dict[str, Any]:
    return get_config().get("correlation", {})


def get_logging_config() -> dict[str, Any]:
    return get_config().get("logging", {})


def get_dynamic_threshold_config() -> dict[str, Any]:
    return get_config().get("dynamic_threshold", {})
