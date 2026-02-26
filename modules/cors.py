"""
modules/cors.py
CORS Misconfiguration detection module.

Tests:
  - Arbitrary origin reflection with credentials allowed
  - Null origin reflection
  - Subdomain suffix bypass (evil.target.com)
  - OPTIONS preflight CORS wildcard + credentials

Deduplicates per server (scheme + host) to avoid redundant checks.

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test URL for CORS misconfigurations. Called per-URL by scan_url()."""
    await _test_cors(scanner, url)


async def _test_cors(scanner: "BaseScanner", url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    target_netloc = urllib.parse.urlparse(scanner.base_url).netloc

    test_origins = [
        "https://evil.attacker.com",
        "https://evil.example.com",
        f"https://evil.{target_netloc}",
        "null",
        "https://localhost.attacker.com",
        f"https://{target_netloc}.evil.com",  # subdomain suffix bypass
    ]

    found = False
    for origin in test_origins:
        for req_method in ("GET", "OPTIONS"):
            extra_hdrs = {"Origin": origin}
            if req_method == "OPTIONS":
                extra_hdrs["Access-Control-Request-Method"] = "GET"
                extra_hdrs["Access-Control-Request-Headers"] = "Authorization"

            res = await scanner.make_request(req_method, url, headers=extra_hdrs)
            if not res:
                continue

            acao = res.headers.get("access-control-allow-origin", "")
            acac = res.headers.get("access-control-allow-credentials", "").lower()

            # High severity: origin reflected + credentials allowed
            if (acao == origin or acao == "*") and acac == "true":
                sev, cvss = calculate_severity("CORS Misconfiguration")
                scanner.log_vuln(Vulnerability(
                    type="CORS Misconfiguration",
                    url=url,
                    parameter="Origin header",
                    payload=f"{req_method} Origin: {origin}",
                    evidence=(
                        f"ACAO: {acao} | ACAC: {acac} — "
                        "arbitrary origin reflected with credentials allowed"
                    ),
                    confidence="High",
                    severity=sev,
                    cvss_score=cvss,
                    method=req_method,
                    detection_method="CORS origin reflection + credentials header check",
                    remediation=(
                        "Validate Origin against an explicit server-side allowlist. "
                        "Never combine wildcard (*) with Access-Control-Allow-Credentials: true. "
                        "Do not reflect arbitrary origins."
                    ),
                    references=["CWE-942", "OWASP-A05:2021"],
                    confidence_pct=92,
                    indicators_matched=2,
                ))
                found = True
                break

            # Lower severity: origin reflected but no credentials
            elif acao == origin and acac != "true":
                scanner.log_vuln(Vulnerability(
                    type="CORS Misconfiguration",
                    url=url,
                    parameter="Origin header",
                    payload=f"{req_method} Origin: {origin}",
                    evidence=f"ACAO: {acao} (reflected without credentials)",
                    confidence="Low",
                    severity="Medium",
                    cvss_score=5.4,
                    method=req_method,
                    detection_method="CORS origin reflection (no credentials)",
                    remediation=(
                        "Validate Origin against an explicit allowlist. "
                        "Avoid reflecting untrusted origins even without credentials."
                    ),
                    references=["CWE-942", "OWASP-A05:2021"],
                    confidence_pct=45,
                    indicators_matched=1,
                ))
                found = True
                break

        if found:
            break
    return found
