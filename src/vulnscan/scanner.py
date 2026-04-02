"""SQL injection detection engine with error-based and boolean-blind detection."""

from __future__ import annotations

import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from vulnscan.models import Form, FormField, PageResult, Severity, VulnType, Vulnerability
from vulnscan.payloads import load_payloads

logger = logging.getLogger(__name__)

# Load payloads from YAML
_sqli_data = load_payloads("sqli")
SQL_ERROR_PATTERNS: list[str] = _sqli_data["error_based"]["detection_patterns"]
ERROR_PAYLOADS: list[str] = _sqli_data["error_based"]["payloads"]
BLIND_PAIRS: list[tuple[str, str]] = [
    (p["true_payload"], p["false_payload"]) for p in _sqli_data["boolean_blind"]["pairs"]
]
BLIND_DIFF_THRESHOLD: int = _sqli_data["boolean_blind"]["diff_threshold"]


def _inject_get(
    client: httpx.Client,
    url: str,
    param: str,
    payload: str,
    extra_params: dict[str, str] | None = None,
) -> str:
    """Inject a payload into a GET parameter and return response text."""
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


def _inject_post(
    client: httpx.Client,
    url: str,
    form: Form,
    param: str,
    payload: str,
) -> str:
    """Inject a payload into a POST form parameter and return response text."""
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
    """Extract submit button name=value from form for DVWA-style parameter checking."""
    if form is None:
        return {}
    for field in form.fields:
        if field.field_type in ("submit", "button") and field.name and field.value:
            return {field.name: field.value}
    return {}


def _contains_sql_error(text: str) -> str | None:
    """Check if response contains SQL error patterns. Returns matched pattern or None."""
    lower = text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in lower:
            return pattern
    return None


def detect_error_based(
    client: httpx.Client,
    url: str,
    param: str,
    method: str = "GET",
    form: Form | None = None,
) -> list[Vulnerability]:
    """Detect error-based SQL injection."""
    vulns: list[Vulnerability] = []
    extra = _get_submit_extra(form)

    # Get baseline response (no SQL error expected)
    try:
        if method == "GET":
            baseline = _inject_get(client, url, param, "1", extra)
        else:
            baseline = _inject_post(client, url, form, param, "test")
    except httpx.HTTPError:
        return vulns

    for payload in ERROR_PAYLOADS:
        try:
            if method == "GET":
                text = _inject_get(client, url, param, payload, extra)
            else:
                text = _inject_post(client, url, form, param, payload)
        except httpx.HTTPError:
            continue

        matched = _contains_sql_error(text)
        if matched and not _contains_sql_error(baseline):
            vulns.append(Vulnerability(
                vuln_type=VulnType.SQLI_ERROR,
                url=url,
                parameter=param,
                payload=payload,
                evidence=f"SQL error pattern found: '{matched}'",
                severity=Severity.HIGH,
                response_snippet=text[:500],
            ))
            logger.info("  [SQLI-ERROR] %s param=%s payload=%s", url, param, payload)
            break

    return vulns


def detect_boolean_blind(
    client: httpx.Client,
    url: str,
    param: str,
    method: str = "GET",
    form: Form | None = None,
) -> list[Vulnerability]:
    """Detect boolean-based blind SQL injection."""
    vulns: list[Vulnerability] = []
    extra = _get_submit_extra(form)

    for true_payload, false_payload in BLIND_PAIRS:
        try:
            if method == "GET":
                true_resp = _inject_get(client, url, param, true_payload, extra)
                false_resp = _inject_get(client, url, param, false_payload, extra)
                baseline = _inject_get(client, url, param, "1", extra)
            else:
                true_resp = _inject_post(client, url, form, param, true_payload)
                false_resp = _inject_post(client, url, form, param, false_payload)
                baseline = _inject_post(client, url, form, param, "test")
        except httpx.HTTPError:
            continue

        true_len = len(true_resp)
        false_len = len(false_resp)
        baseline_len = len(baseline)
        length_diff = abs(true_len - false_len)

        # Method 1: Length difference exceeds threshold
        length_match = length_diff > BLIND_DIFF_THRESHOLD and abs(true_len - baseline_len) < length_diff

        # Method 2: Content differs between true/false but true matches baseline
        # (catches cases where text changes but length is similar, e.g. "exists" vs "MISSING")
        content_diff = true_resp != false_resp
        true_near_baseline = abs(true_len - baseline_len) < abs(false_len - baseline_len)
        content_match = content_diff and true_near_baseline and length_diff > 0

        if length_match or content_match:
            evidence_detail = ""
            if length_diff > BLIND_DIFF_THRESHOLD:
                evidence_detail = f"Length diff: true={true_len}, false={false_len}, baseline={baseline_len}"
            else:
                # Find the differing text for evidence
                for i, (a, b) in enumerate(zip(true_resp, false_resp)):
                    if a != b:
                        start = max(0, i - 20)
                        evidence_detail = f"Content diff at pos {i}: true='...{true_resp[start:i+30]}...' false='...{false_resp[start:i+30]}...'"
                        break

            vulns.append(Vulnerability(
                vuln_type=VulnType.SQLI_BLIND,
                url=url,
                parameter=param,
                payload=f"{true_payload} vs {false_payload}",
                evidence=evidence_detail,
                severity=Severity.HIGH,
                response_snippet=f"True: {true_len} chars\nFalse: {false_len} chars",
            ))
            logger.info("  [SQLI-BLIND] %s param=%s length_diff=%d", url, param, length_diff)
            break

    return vulns


def scan_page(
    client: httpx.Client,
    page: PageResult,
) -> list[Vulnerability]:
    """Scan a single page for SQL injection vulnerabilities."""
    vulns: list[Vulnerability] = []

    for form in page.forms:
        action_url = form.action or page.url
        method = form.method
        for field in form.fields:
            if field.field_type in ("submit", "button"):
                continue
            if field.name in ("user_token", "_token", "csrf_token"):
                continue

            logger.info("Testing: %s [%s] param=%s", action_url, method, field.name)
            vulns.extend(detect_error_based(client, action_url, field.name, method, form))
            vulns.extend(detect_boolean_blind(client, action_url, field.name, method, form))

    # Scan URL query parameters
    parsed = urlparse(page.url)
    if parsed.query:
        for param in parse_qs(parsed.query):
            if param in ("page",):
                continue
            logger.info("Testing URL param: %s param=%s", page.url, param)
            vulns.extend(detect_error_based(client, page.url, param))
            vulns.extend(detect_boolean_blind(client, page.url, param))

    return vulns


def scan_site(
    pages: list[PageResult],
    base_url: str,
    username: str = "admin",
    password: str = "password",
) -> list[Vulnerability]:
    """Scan all crawled pages for SQL injection."""
    from vulnscan.crawler import login

    vulns: list[Vulnerability] = []

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        login(client, base_url, username, password)

        for page in pages:
            page_vulns = scan_page(client, page)
            vulns.extend(page_vulns)

    logger.info("Scan complete: %d vulnerabilities found", len(vulns))
    return vulns
