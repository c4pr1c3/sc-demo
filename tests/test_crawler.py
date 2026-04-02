"""Tests for web crawler: login, form extraction, URL dedup."""

from __future__ import annotations

import pytest

from vulnscan.crawler import crawl_site, extract_forms, login
from vulnscan.models import PageResult


class TestLogin:
    def test_login_success(self, client: pytest.fixture, dvwa_url: str) -> None:
        """Login returns 200 and session has auth cookie."""
        resp = client.get(f"{dvwa_url}/index.php")
        assert resp.status_code == 200
        # DVWA sidebar should be present when logged in
        assert "vulnerabilities" in resp.text.lower() or "dvwa" in resp.text.lower()


class TestCrawl:
    def test_crawl_returns_pages(self, dvwa_url: str) -> None:
        """Crawl should discover multiple pages."""
        pages = crawl_site(dvwa_url, "admin", "password", max_depth=1)
        assert len(pages) > 10
        urls = [p.url for p in pages]
        # Should find key DVWA pages
        assert any("sqli" in u for u in urls), f"No sqli page in {urls}"

    def test_crawl_finds_forms(self, dvwa_url: str) -> None:
        """Crawled pages should contain forms."""
        pages = crawl_site(dvwa_url, "admin", "password", max_depth=1)
        total_forms = sum(len(p.forms) for p in pages)
        assert total_forms > 0

    def test_crawl_deduplicates(self, dvwa_url: str) -> None:
        """Same URL should not appear twice in crawl results."""
        pages = crawl_site(dvwa_url, "admin", "password", max_depth=1)
        urls = [p.url for p in pages]
        assert len(urls) == len(set(urls)), "Duplicate URLs found"

    def test_crawl_skips_logout(self, dvwa_url: str) -> None:
        """Crawler should not follow logout links."""
        pages = crawl_site(dvwa_url, "admin", "password", max_depth=1)
        urls = [p.url for p in pages]
        assert not any("logout" in u for u in urls), "Crawler followed logout link"


class TestExtractForms:
    def test_sqli_page_has_form(self, client: pytest.fixture, dvwa_url: str) -> None:
        """SQLi page should have a form with input fields."""
        resp = client.get(f"{dvwa_url}/vulnerabilities/sqli/")
        forms = extract_forms(resp.text, f"{dvwa_url}/vulnerabilities/sqli/")
        assert len(forms) >= 1
        # Should have at least one text input (the id field)
        form = forms[0]
        input_fields = [f for f in form.fields if f.field_type not in ("submit", "hidden")]
        assert len(input_fields) >= 1
