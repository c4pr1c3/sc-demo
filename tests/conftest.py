"""Shared fixtures for DVWA-based integration tests."""

from __future__ import annotations

import pytest
import httpx

BASE_URL = "http://localhost:8086"


@pytest.fixture(scope="session")
def dvwa_url() -> str:
    """Return DVWA base URL."""
    return BASE_URL


@pytest.fixture(scope="session")
def dvwa_ready(dvwa_url: str) -> None:
    """Wait until DVWA is accepting requests."""
    import time

    for i in range(30):
        try:
            resp = httpx.get(f"{dvwa_url}/login.php", timeout=5)
            if resp.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    pytest.skip("DVWA not available")


@pytest.fixture(scope="session")
def client(dvwa_url: str, dvwa_ready: None) -> httpx.Client:
    """Authenticated httpx.Client for DVWA."""
    from vulnscan.crawler import login

    c = httpx.Client(timeout=30, follow_redirects=True)
    login(c, dvwa_url, "admin", "password")
    yield c
    c.close()
