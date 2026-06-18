"""Attack simulator payloads module.

Exports payload generation functions for use in app.py and orchestrator.
"""
from .payload_generator import (
    PayloadGenerator,
    CLASS_NAMES,
    BUILTIN_CLASS_FEATURES,
    get_payload_for_class,
    get_malware_payloads,
    get_normal_payloads,
    get_suspicious_tool_payloads,
    get_all_class_payloads,
    generate_and_save_all,
)

__all__ = [
    "PayloadGenerator",
    "CLASS_NAMES",
    "BUILTIN_CLASS_FEATURES",
    "get_payload_for_class",
    "get_malware_payloads",
    "get_normal_payloads",
    "get_suspicious_tool_payloads",
    "get_all_class_payloads",
    "generate_and_save_all",
]
