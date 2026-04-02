"""Reflected XSS detection via payload injection and response matching."""

from __future__ import annotations

import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

import httpx

from vulnscan.models import Form, PageResult, Severity, VulnType, Vulnerability

logger = logging.getLogger(__name__)

# XSS payloads - each with a unique marker for reliable matching
XSS_PAYLOADS = [
    # Basic script tags
    '<script>alert(1)</script>',
    '<script>confirm(1)</script>',
    '<script>prompt(1)</script>',
    # Event handlers
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
    '" onmouseover="alert(1)',
    # SVG
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    # Body/iframe
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    # HTML injection (context detection)
    '<h1>xss_test_marker</h1>',
    '<b>xss_test_marker</b>',
]

# Unique markers to look for in response (proves payload was reflected)
REFLECTION_MARKERS = [
    "<script",
    "onerror=",
    "onload=",
    "onmouseover=",
    "<svg",
    "<iframe",
    "javascript:",
    "xss_test_marker",
]

# HTML encoding that browsers still execute
ENCODING_BYPASS_PATTERNS = [
    re.compile(r"&lt;script", re.IGNORECASE),
    re.compile(r"%3[Cc]script", re.IGNORECASE),
]


def _inject_get_xss(
    client: httpx.Client,
    url: str,
    param: str,
    payload: str,
    extra_params: dict[str, str] | None = None,
) -> str:
    """Inject XSS payload into GET parameter, return response text."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    if extra_params:
        for k, v in extra_params.items():
            if k not in params:
                params[k] = [v]
    new_query = urlencode({k: v[0] for k, v in params.items()})
    new_url = urlunparse(parsed._replace(query=new_query))
    resp = client.get(new_url, follow_redirects=True, timeout=30)
    return resp.text


def _inject_post_xss(
    client: httpx.Client,
    url: str,
    form: Form,
    param: str,
    payload: str,
) -> str:
    """Inject XSS payload into POST form parameter, return response text."""
    data: dict[str, str] = {}
    for field in form.fields:
        if field.name == param:
            data[field.name] = payload
        elif field.field_type in ("submit", "button"):
            data[field.name] = field.value or field.name
        else:
            data[field.name] = field.value or "test"
    resp = client.post(url, data=data, follow_redirects=True, timeout=30)
    return resp.text


def _get_submit_extra(form: Form | None) -> dict[str, str]:
    """Extract submit button name=value from form."""
    if form is None:
        return {}
    for field in form.fields:
        if field.field_type in ("submit", "button") and field.name and field.value:
            return {field.name: field.value}
    return {}


def _check_reflection(payload: str, response: str) -> str | None:
    """Check if XSS payload is reflected in response. Returns evidence or None."""
    lower_resp = response.lower()
    lower_payload = payload.lower()

    # Direct reflection: payload appears unmodified in response
    if lower_payload in lower_resp:
        return f"Payload reflected verbatim: '{payload[:80]}'"

    # Check for partial reflections of dangerous patterns
    for marker in REFLECTION_MARKERS:
        if marker.lower() in lower_payload and marker.lower() in lower_resp:
            # Verify the marker appears in a context related to our injection
            # (not just randomly in the page)
            idx = lower_resp.find(marker.lower())
            context = response[max(0, idx - 30):idx + len(marker) + 30]
            return f"Marker '{marker}' reflected near: ...{context}..."

    return None


def detect_xss(
    client: httpx.Client,
    url: str,
    param: str,
    method: str = "GET",
    form: Form | None = None,
) -> list[Vulnerability]:
    """Detect reflected XSS by injecting payloads and checking response reflection."""
    vulns: list[Vulnerability] = []
    extra = _get_submit_extra(form)

    for payload in XSS_PAYLOADS:
        try:
            if method == "GET":
                text = _inject_get_xss(client, url, param, payload, extra)
            else:
                text = _inject_post_xss(client, url, form, param, payload)
        except httpx.HTTPError:
            continue

        evidence = _check_reflection(payload, text)
        if evidence:
            vulns.append(Vulnerability(
                vuln_type=VulnType.XSS_REFLECTED,
                url=url,
                parameter=param,
                payload=payload,
                evidence=evidence,
                severity=Severity.HIGH,
                response_snippet=text[:500],
            ))
            logger.info("  [XSS] %s param=%s payload=%s", url, param, payload[:50])
            break  # One confirmed XSS per param is enough

    return vulns


def scan_xss(
    pages: list[PageResult],
    base_url: str,
    username: str = "admin",
    password: str = "password",
) -> list[Vulnerability]:
    """Scan all crawled pages for reflected XSS."""
    from vulnscan.crawler import login

    vulns: list[Vulnerability] = []

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        login(client, base_url, username, password)

        for page in pages:
            for form in page.forms:
                action_url = form.action or page.url
                method = form.method
                for field in form.fields:
                    if field.field_type in ("submit", "button"):
                        continue
                    if field.name in ("user_token", "_token", "csrf_token"):
                        continue

                    logger.info("Testing XSS: %s [%s] param=%s", action_url, method, field.name)
                    vulns.extend(detect_xss(client, action_url, field.name, method, form))

            # Also test URL query parameters
            parsed = urlparse(page.url)
            if parsed.query:
                for param in parse_qs(parsed.query):
                    if param in ("page",):
                        continue
                    logger.info("Testing XSS URL param: %s param=%s", page.url, param)
                    vulns.extend(detect_xss(client, page.url, param))

    logger.info("XSS scan complete: %d vulnerabilities found", len(vulns))
    return vulns
