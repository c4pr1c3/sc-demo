"""End-to-end integration tests: CLI pipeline + report validation."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from vulnscan.cli import main

pytestmark = pytest.mark.integration


class TestIntegration:
    @pytest.mark.timeout(300)
    def test_full_scan_produces_reports(self, dvwa_url: str) -> None:
        """Full scan via CLI should produce valid JSON and HTML reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            main([
                "scan",
                dvwa_url,
                "-u", "admin",
                "-p", "password",
                "-o", tmpdir,
                "--depth", "1",
            ])

            # JSON report should exist and be valid
            json_path = os.path.join(tmpdir, "vulnscan_report.json")
            assert os.path.exists(json_path), "JSON report not created"
            with open(json_path) as f:
                report = json.load(f)
            assert "target" in report
            assert "vulnerabilities" in report
            assert isinstance(report["vulnerabilities"], list)

            # HTML report should exist and be non-empty
            html_path = os.path.join(tmpdir, "vulnscan_report.html")
            assert os.path.exists(html_path), "HTML report not created"
            with open(html_path) as f:
                html = f.read()
            assert len(html) > 100
            assert "<html" in html.lower()

    @pytest.mark.timeout(300)
    def test_total_vulns_above_minimum(self, dvwa_url: str) -> None:
        """Full scan should find at least 3 vulnerabilities on DVWA."""
        with tempfile.TemporaryDirectory() as tmpdir:
            main([
                "scan",
                dvwa_url,
                "-u", "admin",
                "-p", "password",
                "-o", tmpdir,
                "--depth", "1",
            ])

            json_path = os.path.join(tmpdir, "vulnscan_report.json")
            with open(json_path) as f:
                report = json.load(f)
            assert len(report["vulnerabilities"]) >= 3, (
                f"Expected >= 3 vulns, got {len(report['vulnerabilities'])}"
            )
