"""Tests for reflected XSS detection."""

from __future__ import annotations

import pytest

from vulnscan.models import VulnType
from vulnscan.xss import detect_xss


class TestReflectedXss:
    def test_detects_xss_reflected(self, client: pytest.fixture, dvwa_url: str) -> None:
        """Reflected XSS should be detected on DVWA xss_r page."""
        vulns = detect_xss(
            client,
            f"{dvwa_url}/vulnerabilities/xss_r/",
            "name",
            method="GET",
        )
        assert len(vulns) >= 1
        assert vulns[0].vuln_type == VulnType.XSS_REFLECTED

    def test_no_false_positive_csrf(self, client: pytest.fixture, dvwa_url: str) -> None:
        """CSRF page should not trigger XSS false positives."""
        vulns = detect_xss(
            client,
            f"{dvwa_url}/vulnerabilities/csrf/",
            "password_new",
            method="GET",
        )
        assert len(vulns) == 0
