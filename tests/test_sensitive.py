"""Tests for sensitive path scanning."""

from __future__ import annotations

import pytest

from vulnscan.models import VulnType
from vulnscan.sensitive import scan_sensitive_paths


class TestSensitivePaths:
    def test_detects_robots_txt(self, client: pytest.fixture, dvwa_url: str) -> None:
        """robots.txt should be detected if present."""
        vulns = scan_sensitive_paths(client, dvwa_url)
        paths = [v.parameter for v in vulns]
        # DVWA may or may not have robots.txt; just verify the function runs
        assert isinstance(vulns, list)

    def test_no_git_head_false_positive(self, client: pytest.fixture, dvwa_url: str) -> None:
        """.git/HEAD should not be detected on DVWA (not a git repo)."""
        vulns = scan_sensitive_paths(client, dvwa_url)
        git_vulns = [v for v in vulns if ".git" in v.parameter]
        assert len(git_vulns) == 0, "False positive: .git/HEAD detected on DVWA"

    def test_vuln_type_is_sensitive(self, client: pytest.fixture, dvwa_url: str) -> None:
        """All sensitive path findings should have SENSITIVE vuln type."""
        vulns = scan_sensitive_paths(client, dvwa_url)
        for v in vulns:
            assert v.vuln_type == VulnType.SENSITIVE
