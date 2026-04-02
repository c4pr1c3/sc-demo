"""SQL injection detector adapter."""

from __future__ import annotations

from vulnscan.detectors.base import BaseDetector, register
from vulnscan.models import PageResult, Vulnerability
from vulnscan.scanner import scan_site


class SQLiDetector(BaseDetector):
    """Detects error-based and boolean-blind SQL injection."""

    @property
    def name(self) -> str:
        return "sqli"

    def scan(
        self,
        pages: list[PageResult],
        base_url: str,
        username: str = "admin",
        password: str = "password",
    ) -> list[Vulnerability]:
        return scan_site(pages, base_url, username, password)


register(SQLiDetector())
