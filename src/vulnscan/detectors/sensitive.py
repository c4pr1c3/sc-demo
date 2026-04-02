"""Sensitive information leakage detector adapter."""

from __future__ import annotations

import httpx

from vulnscan.detectors.base import BaseDetector, register
from vulnscan.models import PageResult, Vulnerability
from vulnscan.sensitive import scan_sensitive_paths


class SensitiveDetector(BaseDetector):
    """Detects sensitive information leakage via common path scanning."""

    @property
    def name(self) -> str:
        return "sensitive"

    def scan(
        self,
        pages: list[PageResult],
        base_url: str,
        username: str = "admin",
        password: str = "password",
    ) -> list[Vulnerability]:
        from vulnscan.crawler import login

        with httpx.Client(timeout=30, follow_redirects=True) as client:
            login(client, base_url, username, password)
            return scan_sensitive_paths(client, base_url)


register(SensitiveDetector())
