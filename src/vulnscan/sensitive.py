"""Sensitive information leakage detection via common path scanning."""

from __future__ import annotations

import logging
from urllib.parse import urljoin

import httpx

from vulnscan.models import Severity, VulnType, Vulnerability
from vulnscan.payloads import load_payloads

logger = logging.getLogger(__name__)

# Load sensitive paths from YAML
_sensitive_data = load_payloads("sensitive")
SENSITIVE_PATHS: dict[str, list[str]] = {
    entry["path"]: entry["keywords"]
    for category in _sensitive_data["paths"].values()
    for entry in category
}
INTERESTING_KEYWORDS: dict[str, list[str]] = _sensitive_data["interesting_keywords"]


def scan_sensitive_paths(
    client: httpx.Client,
    base_url: str,
) -> list[Vulnerability]:
    """Scan target for sensitive information leakage on common paths."""
    vulns: list[Vulnerability] = []
    base_url = base_url.rstrip("/")

    for path, keywords in SENSITIVE_PATHS.items():
        url = f"{base_url}/{path}"
        try:
            resp = client.get(url, follow_redirects=True, timeout=10)
        except httpx.HTTPError:
            continue

        # Only interested in 200 responses
        if resp.status_code != 200:
            continue

        # Check if response is actually interesting (not a generic app page)
        text = resp.text
        is_interesting = False
        evidence = ""

        # Path-specific keyword matching
        if path in INTERESTING_KEYWORDS:
            for kw in INTERESTING_KEYWORDS[path]:
                if kw.lower() in text.lower():
                    is_interesting = True
                    evidence = f"Keyword '{kw}' found in response"
                    break
        elif keywords:
            for kw in keywords:
                if kw.lower() in text.lower():
                    is_interesting = True
                    evidence = f"Keyword '{kw}' found in response"
                    break

        # For paths without keywords, check if response is small (likely genuine content, not full page)
        if not is_interesting and not keywords and len(text) < 500:
            is_interesting = True
            evidence = f"Small response ({len(text)} bytes), likely genuine file"

        # Skip responses that are just the app's default page
        if not is_interesting:
            # Check if response looks like the main app (e.g., DVWA sidebar)
            if "vulnerabilities" in text.lower() and len(text) > 2000:
                continue
            # Accept if response is reasonably sized and returned 200
            if len(text) < 100000:
                is_interesting = True
                evidence = f"HTTP 200 with {len(text)} bytes response"

        if not is_interesting:
            continue

        # Determine severity
        if any(p in path for p in (".git", ".env", "backup", "dump", ".sql")):
            severity = Severity.HIGH
        elif any(p in path for p in ("phpinfo", "info.php", "server-status", "admin")):
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        vulns.append(Vulnerability(
            vuln_type=VulnType.SENSITIVE,
            url=url,
            parameter=path,
            payload="",
            evidence=evidence,
            severity=severity,
            response_snippet=text[:300],
        ))
        logger.info("  [SENSITIVE] %s (%s)", url, evidence[:80])

    return vulns
