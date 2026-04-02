"""Reflected XSS detector adapter."""

from __future__ import annotations

from vulnscan.detectors.base import BaseDetector, register
from vulnscan.models import PageResult, Vulnerability
from vulnscan.xss import scan_xss as _scan_xss


class XSSDetector(BaseDetector):
    """Detects reflected XSS vulnerabilities."""

    @property
    def name(self) -> str:
        return "xss"

    def scan(
        self,
        pages: list[PageResult],
        base_url: str,
        username: str = "admin",
        password: str = "password",
    ) -> list[Vulnerability]:
        return _scan_xss(pages, base_url, username, password)


register(XSSDetector())
