"""Data models for the vulnerability scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnType(str, Enum):
    SQLI_ERROR = "sqli_error"
    SQLI_BLIND = "sqli_blind"
    XSS_REFLECTED = "xss_reflected"
    SENSITIVE = "sensitive_info"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FormField:
    name: str
    field_type: str  # input type: text, hidden, submit, etc.
    value: str = ""


@dataclass
class Form:
    action: str
    method: str  # GET or POST
    fields: list[FormField] = field(default_factory=list)


@dataclass
class PageResult:
    url: str
    status_code: int
    forms: list[Form] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    vuln_type: VulnType
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: Severity
    request_snippet: str = ""
    response_snippet: str = ""


@dataclass
class ScanResult:
    target: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    pages_crawled: int = 0
    forms_found: int = 0
