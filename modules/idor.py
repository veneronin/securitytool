"""
modules/idor.py
IDOR / Broken Object Level Authorization (BOLA) test module.

Probes numeric and UUID id-style parameters with alternate identifiers,
looking for unauthorized access to other users' sensitive data.

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

# Parameters that are likely to control object identity
ID_PARAM_NAMES = {
    "id", "user_id", "userid", "account", "order", "basket",
    "product", "item", "file", "doc", "record", "uid", "pid",
    "customer_id", "customerid", "invoice", "report", "resource",
}

# Test values to probe with
PROBE_IDS = [
    "0", "1", "2", "3", "99", "100", "1000", "-1",
    "00000000-0000-0000-0000-000000000001",
    "admin", "administrator", "root",
]

# Keywords that suggest sensitive data was returned
SENSITIVE_KEYWORDS = [
    "email", "password", "token", "address", "credit", "admin",
    "phone", "role", "balance", "card", "ssn", "secret", "key",
    "apikey", "api_key", "private", "dob", "birth", "passport",
    "license", "salary", "username", "hash", "resettoken",
]


async def run(scanner: "BaseScanner", url: str, param: str, method: str = "GET") -> None:
    """Test a single parameter for IDOR. Called per-param by scan_url()."""
    if scanner.config.get("skip_idor", False):
        return
    if param.lower() not in ID_PARAM_NAMES:
        return
    await _test_idor(scanner, url, param, method)


async def _test_idor(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    # Baseline with an unlikely-to-exist ID
    baseline = await scanner.make_request(method, url, params={param: "999999"})
    if not baseline:
        return False

    for test_id in PROBE_IDS:
        res = await scanner.make_request(method, url, params={param: test_id})
        if not res:
            continue

        if res.status_code == 200 and len(res.text) > 50:
            # Flag if response differs meaningfully from baseline AND contains PII keywords
            different = res.text != baseline.text
            has_sensitive = any(k in res.text.lower() for k in SENSITIVE_KEYWORDS)

            if different and has_sensitive:
                severity, cvss = calculate_severity("IDOR")
                scanner.log_vuln(Vulnerability(
                    type="IDOR (Broken Object Level Authorization)",
                    url=url,
                    parameter=param,
                    payload=test_id,
                    evidence=f"Different user data returned for {param}={test_id}",
                    confidence="Medium",
                    severity=severity,
                    cvss_score=cvss,
                    method=method,
                    detection_method="Response differential analysis + PII keyword match",
                    remediation=(
                        "Enforce object-level authorization on every request. "
                        "Validate that the authenticated user owns the requested resource. "
                        "Use indirect reference maps instead of direct database IDs."
                    ),
                    references=["CWE-284", "OWASP-API1:2023"],
                ))
                return True
    return False
