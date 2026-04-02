"""Payload loading utilities for vulnerability scanners."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_PAYLOADS_DIR = Path(__file__).parent


@lru_cache(maxsize=16)
def load_payloads(name: str) -> dict:
    """Load a payload YAML file by name (without extension).

    Args:
        name: Payload file name without .yaml extension (e.g. 'sqli', 'xss').

    Returns:
        Parsed YAML as a dictionary.
    """
    path = _PAYLOADS_DIR / f"{name}.yaml"
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def list_payloads() -> list[str]:
    """List available payload file names."""
    return [p.stem for p in _PAYLOADS_DIR.glob("*.yaml")]
