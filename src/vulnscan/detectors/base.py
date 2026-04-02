"""Base class for all vulnerability detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vulnscan.models import PageResult, Vulnerability

# Module-level registry (no circular imports — base.py imports nothing from detectors/)
_registry: list[BaseDetector] = []


def register(detector: BaseDetector) -> None:
    """Register a detector instance."""
    _registry.append(detector)


def get_detectors() -> list[BaseDetector]:
    """Return all registered detectors."""
    return list(_registry)


class BaseDetector(ABC):
    """Abstract base for vulnerability detectors.

    Subclass this and implement ``name`` and ``scan``.
    Import the subclass module in ``detectors/__init__.py`` so it is
    auto-registered at startup.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name (e.g. 'sqli', 'xss')."""

    @abstractmethod
    def scan(
        self,
        pages: list[PageResult],
        base_url: str,
        username: str = "admin",
        password: str = "password",
    ) -> list[Vulnerability]:
        """Run detection against crawled pages.

        Args:
            pages: Crawled page results from the crawler.
            base_url: Target base URL.
            username: Login username.
            password: Login password.

        Returns:
            List of discovered vulnerabilities.
        """
