"""Tests for SQL injection detection: error-based, boolean-blind, zero false positives."""

from __future__ import annotations

import pytest
import httpx

from vulnscan.models import PageResult, Form, FormField, VulnType
from vulnscan.scanner import detect_error_based, detect_boolean_blind, scan_page


class TestErrorBasedSqli:
    def test_detects_sqli_error(self, client: pytest.fixture, dvwa_url: str) -> None:
        """Error-based SQLi should be detected on DVWA sqli page."""
        vulns = detect_error_based(
            client,
            f"{dvwa_url}/vulnerabilities/sqli/?id=1&Submit=Submit",
            "id",
            method="GET",
        )
        assert len(vulns) >= 1
        assert vulns[0].vuln_type == VulnType.SQLI_ERROR

    def test_no_false_positive_csrf(self, client: pytest.fixture, dvwa_url: str) -> None:
        """CSRF page should not trigger SQLi false positives."""
        vulns = detect_error_based(
            client,
            f"{dvwa_url}/vulnerabilities/csrf/",
            "password_new",
            method="GET",
        )
        assert len(vulns) == 0


class TestBooleanBlindSqli:
    def test_detects_blind_sqli(self, client: pytest.fixture, dvwa_url: str) -> None:
        """Boolean-blind SQLi should be detected on DVWA sqli_blind page."""
        vulns = detect_boolean_blind(
            client,
            f"{dvwa_url}/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
            "id",
            method="GET",
        )
        assert len(vulns) >= 1
        assert vulns[0].vuln_type == VulnType.SQLI_BLIND
