"""Detector registry: auto-discovers and registers all vulnerability detectors."""

from vulnscan.detectors.base import BaseDetector, get_detectors, register  # noqa: F401

# Import concrete detectors so they self-register at import time
import vulnscan.detectors.sqli  # noqa: F401
import vulnscan.detectors.xss  # noqa: F401
import vulnscan.detectors.sensitive  # noqa: F401
