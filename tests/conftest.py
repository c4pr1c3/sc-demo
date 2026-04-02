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
    """Authenticated httpx.Client for DVWA with database initialized."""
    from vulnscan.crawler import login, setup_database

    c = httpx.Client(timeout=30, follow_redirects=True)
    login(c, dvwa_url, "admin", "password")
    setup_database(c, dvwa_url)
    # Re-login after database reset (DVWA may invalidate session)
    login(c, dvwa_url, "admin", "password")
    _set_dvwa_security(c, dvwa_url, "low")
    yield c
    c.close()


def _set_dvwa_security(client: httpx.Client, base_url: str, level: str) -> None:
    """Set DVWA security level (low/medium/high/impossible)."""
    from bs4 import BeautifulSoup

    url = f"{base_url}/security.php"
    resp = client.get(url)
    if resp.status_code != 200:
        return
    soup = BeautifulSoup(resp.text, "html.parser")
    token = ""
    for inp in soup.find_all("input", {"name": "user_token"}):
        token = inp.get("value", "")
        break
    client.post(url, data={
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token,
    })
