"""Unknown attack payload generators — 8 attack types not in the 44-class training set.

Each generator produces raw bytes payloads with protocol fingerprints
distinct from any traffic in the 44-class CIC-IDS/CSE-CIC training distribution.

Usage:
    from tests.attack_simulator.unknown_attacks import (
        generate_unknown_attack,
        get_unknown_attack_names,
        UNKNOWN_ATTACK_TYPES,
    )

    payloads = generate_unknown_attack("ssh_bruteforce", count=5)
"""

from __future__ import annotations

import json
import random
from pathlib import Path

# ---------------------------------------------------------------------------
# Global registry — populated via @register_attack decorator in sub-modules
# ---------------------------------------------------------------------------
UNKNOWN_ATTACK_TYPES: dict[str, callable] = {}


def register_attack(name: str):
    """Decorator: register an unknown attack generator function.

    Usage:
        @register_attack("ssh_bruteforce")
        def generate_ssh_bruteforce(count: int = 1) -> list[bytes]:
            ...
    """
    def _decorator(fn: callable) -> callable:
        UNKNOWN_ATTACK_TYPES[name] = fn
        fn._attack_name = name  # type: ignore[attr-defined]
        return fn

    # Support both @register_attack("name") and @register_attack usage
    if callable(name):
        fn = name
        fn_name = fn.__name__.replace("generate_", "")
        UNKNOWN_ATTACK_TYPES[fn_name] = fn
        fn._attack_name = fn_name  # type: ignore[attr-defined]
        return fn
    return _decorator


def get_unknown_attack_names() -> list[str]:
    """Return the list of all registered unknown attack type names."""
    return sorted(UNKNOWN_ATTACK_TYPES.keys())


def generate_unknown_attack(name: str, count: int = 1) -> list[bytes]:
    """Generate *count* payloads for the given unknown attack type.

    Args:
        name:  One of the registered attack names (see get_unknown_attack_names()).
        count: How many distinct payloads to produce.

    Returns:
        List of bytes payloads, each 200-2000 bytes.

    Raises:
        ValueError: If *name* is not a registered attack type.
    """
    if name not in UNKNOWN_ATTACK_TYPES:
        available = ", ".join(get_unknown_attack_names())
        raise ValueError(
            f"Unknown attack type '{name}'. Available: {available}"
        )
    generator = UNKNOWN_ATTACK_TYPES[name]
    payloads = generator(count)
    return payloads


def generate_all_unknown(count_per_type: int = 5) -> dict[str, list[bytes]]:
    """Generate payloads for every registered unknown attack type.

    Returns dict mapping attack_name -> list[bytes].
    """
    result = {}
    for name in get_unknown_attack_names():
        result[name] = generate_unknown_attack(name, count_per_type)
    return result


# ---------------------------------------------------------------------------
# Register all known attack generators by importing sub-modules
# (must be at the bottom to avoid circular imports, as each sub-module
#  does ``from . import register_attack``)
# ---------------------------------------------------------------------------
from . import ssh_bruteforce       # noqa: E402,F401
from . import dns_tunnel           # noqa: E402,F401
from . import heartbleed           # noqa: E402,F401
from . import icmp_tunnel          # noqa: E402,F401
from . import eternal_blue         # noqa: E402,F401
from . import slowloris            # noqa: E402,F401
from . import dga_domains          # noqa: E402,F401
from . import stratum_mining       # noqa: E402,F401
