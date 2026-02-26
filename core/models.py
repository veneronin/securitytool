"""
core/models.py
Shared dataclasses used across the entire scanner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class Vulnerability:
    """Structured vulnerability record."""
    type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: str          # High | Medium | Low
    severity: str            # Critical | High | Medium | Low
    cvss_score: float
    method: str = "GET"
    detection_method: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = ""
    exploitation_notes: str = ""
    confidence_pct: int = 0
    indicators_matched: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.confidence_pct == 0:
            mapping = {"High": 85, "Medium": 55, "Low": 30}
            self.confidence_pct = mapping.get(self.confidence, 50)


@dataclass
class AuthConfig:
    """Authentication configuration."""
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""
    password: str = ""
    success_indicator: str = ""
    failure_indicator: str = "invalid"
    auth_type: str = "form"  # form | basic | bearer | json | auto


# Severity / CVSS lookup used by all modules
SEVERITY_MATRIX = {
    "Command Injection":                     ("Critical", 9.8),
    "Blind Command Injection":               ("Critical", 9.8),
    "SQL Injection (Error)":                 ("Critical", 9.0),
    "SQL Injection (Time)":                  ("High",     8.5),
    "SQL Injection (Boolean)":               ("High",     8.5),
    "SQL Injection (OOB)":                   ("Critical", 9.0),
    "SQL Injection (Second-Order Error)":    ("Critical", 9.0),
    "SSTI":                                  ("Critical", 9.5),
    "XXE":                                   ("Critical", 9.0),
    "Blind XXE":                             ("High",     8.5),
    "SSRF":                                  ("High",     8.0),
    "Blind SSRF":                            ("High",     7.5),
    "XSS (Reflected)":                       ("Medium",   6.5),
    "XSS (Context-Aware)":                   ("High",     7.5),
    "DOM XSS":                               ("Medium",   6.5),
    "Second-Order XSS":                      ("High",     7.5),
    "Path Traversal":                        ("High",     8.5),
    "Open Redirect":                         ("Medium",   6.1),
    "IDOR":                                  ("High",     8.0),
    "JWT Vulnerability":                     ("Critical", 9.1),
    "JWT alg:none Bypass":                   ("Critical", 9.1),
    "JWT Weak Secret":                       ("Critical", 9.1),
    "JWT Algorithm Confusion (RS256→HS256)": ("Critical", 9.1),
    "Prototype Pollution":                   ("High",     8.0),
    "Prototype Pollution (Query)":           ("High",     8.0),
    "Prototype Pollution (Server-Side)":     ("High",     8.0),
    "Header Injection":                      ("Medium",   6.5),
    "HTTP Header Injection / CRLF":          ("Medium",   6.5),
    "Sensitive Endpoint":                    ("Medium",   5.5),
    "Sensitive Endpoint Exposed":            ("Medium",   5.5),
    "Protected Endpoint Found (403)":        ("Low",      3.1),
    "GraphQL Introspection":                 ("Medium",   5.3),
    "GraphQL Injection":                     ("Critical", 9.0),
    "GraphQL Batching":                      ("Medium",   6.0),
    "WebSocket Injection":                   ("High",     8.0),
    "CORS Misconfiguration":                 ("High",     7.5),
    "Business Logic":                        ("High",     7.5),
    "Host Header Injection":                 ("High",     7.2),
    "OAuth Token Leak":                      ("High",     8.1),
    "HTTP Request Smuggling":                ("Critical", 9.5),
    "IDOR (Broken Object Level Authorization)": ("High",  8.0),
}


def calculate_severity(vuln_type: str):
    """Return (severity, cvss_score) for a given vuln type."""
    return SEVERITY_MATRIX.get(vuln_type, ("Medium", 5.0))
