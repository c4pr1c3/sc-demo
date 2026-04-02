"""Web crawler module with DVWA login and form extraction."""

from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from vulnscan.models import Form, FormField, PageResult

logger = logging.getLogger(__name__)

# File extensions to skip during crawling
SKIP_EXTENSIONS = {
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".zip", ".tar", ".gz",
}

# URL path patterns to skip (session-breaking pages)
SKIP_PATHS = {"logout.php", "login.php"}


def _should_skip_url(url: str) -> bool:
    """Check if URL should be skipped (static resources or session-breaking pages)."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return True
    if any(skip in path for skip in SKIP_PATHS):
        return True
    return False


def _normalize_url(base: str, href: str) -> str | None:
    """Resolve a relative href against a base URL, returning None for external/invalid links."""
    if not href or href.startswith("#") or href.startswith("javascript:"):
        return None
    full = urljoin(base, href)
    parsed = urlparse(full)
    # Only keep http/https
    if parsed.scheme not in ("http", "https"):
        return None
    # Strip fragment
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" + (
        f"?{parsed.query}" if parsed.query else ""
    )


def extract_forms(html: str, page_url: str) -> list[Form]:
    """Parse all HTML forms from a page."""
    soup = BeautifulSoup(html, "html.parser")
    forms: list[Form] = []

    for form_tag in soup.find_all("form"):
        action = form_tag.get("action", "")
        method = form_tag.get("method", "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url

        fields: list[FormField] = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            if not name:
                continue
            field_type = inp.get("type", inp.name)  # textarea/select use tag name
            value = inp.get("value", "")
            fields.append(FormField(name=name, field_type=field_type, value=value))

        if fields:
            forms.append(Form(action=action_url, method=method, fields=fields))

    return forms


def _is_same_origin(base: str, url: str) -> bool:
    """Check if url belongs to the same origin as base."""
    b = urlparse(base)
    u = urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def login(client: httpx.Client, base_url: str, username: str, password: str) -> bool:
    """Login to DVWA, handling CSRF token automatically."""
    login_url = urljoin(base_url, "/login.php")

    # Step 1: GET login page to extract CSRF token
    resp = client.get(login_url, follow_redirects=True)
    resp.raise_for_status()

    # Check if already logged in
    if "index.php" in str(resp.url) and "login" not in str(resp.url).lower():
        logger.info("Already logged in")
        return True

    soup = BeautifulSoup(resp.text, "html.parser")

    # Find CSRF token (DVWA uses user_token hidden field)
    token = ""
    for inp in soup.find_all("input", {"name": "user_token"}):
        token = inp.get("value", "")
        break

    # Step 2: POST login credentials
    data = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }
    resp = client.post(login_url, data=data, follow_redirects=True)
    resp.raise_for_status()

    # Verify login success
    if "index.php" in str(resp.url) or "Welcome" in resp.text or "login" not in str(resp.url).lower():
        logger.info("Login successful: %s", base_url)
        return True

    logger.error("Login failed for %s", base_url)
    return False


def setup_database(client: httpx.Client, base_url: str) -> bool:
    """Detect DVWA database setup page and initialize if needed."""
    setup_url = urljoin(base_url, "/setup.php")
    resp = client.get(setup_url)
    if resp.status_code != 200:
        return True  # No setup page, probably already set up

    if "Database Setup" in resp.text or "Create / Reset Database" in resp.text:
        soup = BeautifulSoup(resp.text, "html.parser")
        token = ""
        for inp in soup.find_all("input", {"name": "user_token"}):
            token = inp.get("value", "")
            break

        data = {"create_db": "Create / Reset Database", "user_token": token}
        resp = client.post(setup_url, data=data, follow_redirects=True)
        if resp.status_code == 200:
            logger.info("DVWA database initialized")
            return True

    return False


def crawl_site(
    base_url: str,
    username: str = "admin",
    password: str = "password",
    max_depth: int = 1,
) -> list[PageResult]:
    """Crawl a target site, returning page results with links and forms.

    Handles DVWA login and database setup automatically.
    """
    base_url = base_url.rstrip("/")
    results: list[PageResult] = []
    visited: set[str] = set()

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        # Auto-setup DVWA database if needed
        setup_database(client, base_url)

        # Login
        if not login(client, base_url, username, password):
            logger.error("Cannot proceed without login")
            return results

        # BFS crawl
        queue: list[tuple[str, int]] = [(base_url, 0)]
        visited.add(base_url)

        while queue:
            url, depth = queue.pop(0)
            if depth > max_depth:
                continue

            logger.info("Crawling [depth=%d]: %s", depth, url)
            try:
                resp = client.get(url)
            except httpx.HTTPError as e:
                logger.warning("Failed to fetch %s: %s", url, e)
                continue

            forms = extract_forms(resp.text, url)

            # Extract links
            soup = BeautifulSoup(resp.text, "html.parser")
            links: list[str] = []
            for a_tag in soup.find_all("a", href=True):
                link = _normalize_url(url, a_tag["href"])
                if link and _is_same_origin(base_url, link) and not _should_skip_url(link):
                    links.append(link)
                    if link not in visited:
                        visited.add(link)
                        queue.append((link, depth + 1))

            page = PageResult(
                url=url,
                status_code=resp.status_code,
                forms=forms,
                links=links,
            )
            results.append(page)
            logger.info("  Found %d links, %d forms", len(links), len(forms))

    logger.info("Crawl complete: %d pages visited", len(results))
    return results
