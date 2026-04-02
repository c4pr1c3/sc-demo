"""Tests for payload YAML loading and structure validation."""

from __future__ import annotations

import pytest

from vulnscan.payloads import list_payloads, load_payloads


class TestPayloadLoading:
    """Verify all YAML payload files load and have valid structure."""

    @pytest.mark.parametrize("name", ["sqli", "xss", "sensitive"])
    def test_load_payload(self, name: str) -> None:
        data = load_payloads(name)
        assert isinstance(data, dict)
        assert "version" in data
        assert "description" in data

    def test_list_payloads(self) -> None:
        names = list_payloads()
        assert "sqli" in names
        assert "xss" in names
        assert "sensitive" in names

    def test_sqli_structure(self) -> None:
        data = load_payloads("sqli")
        assert "error_based" in data
        assert isinstance(data["error_based"]["payloads"], list)
        assert len(data["error_based"]["payloads"]) > 0
        assert isinstance(data["error_based"]["detection_patterns"], list)
        assert len(data["error_based"]["detection_patterns"]) > 0
        assert "boolean_blind" in data
        assert isinstance(data["boolean_blind"]["pairs"], list)
        for pair in data["boolean_blind"]["pairs"]:
            assert "true_payload" in pair
            assert "false_payload" in pair
        assert isinstance(data["boolean_blind"]["diff_threshold"], int)

    def test_xss_structure(self) -> None:
        data = load_payloads("xss")
        assert "reflected" in data
        assert isinstance(data["reflected"]["payloads"], list)
        for p in data["reflected"]["payloads"]:
            assert "payload" in p
            assert "marker" in p
        assert "reflection_markers" in data
        assert isinstance(data["reflection_markers"], list)
        assert len(data["reflection_markers"]) > 0

    def test_sensitive_structure(self) -> None:
        data = load_payloads("sensitive")
        assert "paths" in data
        assert isinstance(data["paths"], dict)
        for category, entries in data["paths"].items():
            assert isinstance(entries, list)
            for entry in entries:
                assert "path" in entry
                assert "keywords" in entry
                assert "severity" in entry
        assert "interesting_keywords" in data
        assert "severity_rules" in data
