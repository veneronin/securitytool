"""
modules/sqli.py
SQL Injection test module.

Covers:
  - Error-based  (DB error string matching)
  - Time-based blind  (3-sigma statistical analysis)
  - Boolean-based blind  (differential length analysis)
  - UNION-based  (column-count probing + reflection)
  - OOB / DNS  (callback via built-in OOB server)
  - Second-order  (stored payload → re-fetch detection)
  - NoSQL  (MongoDB operator injection)

Entry point: async def run(scanner) -> None
Called by main.py for every (url, param, method) triple in scanner.param_map.

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import asyncio
import statistics
import time
import urllib.parse
from typing import TYPE_CHECKING

from payloads.sqli_payloads import (
    ERROR_PAYLOADS,
    ERROR_SIGNATURES,
    TIME_PAYLOADS,
    BOOLEAN_PAYLOADS,
    UNION_PAYLOADS,
    NOSQL_PAYLOADS,
    WAF_BYPASS_TRANSFORMS,
)
from core.models import Vulnerability

if TYPE_CHECKING:
    from core.scanner import BaseScanner

REMEDIATION = (
    "1. Use parameterized queries / prepared statements (primary defense). "
    "2. Apply stored procedures with safe coding practices. "
    "3. Allow-list input validation for table/column names. "
    "4. Enforce least-privilege DB accounts. "
    "See: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
)
REFERENCES = ["CWE-89", "OWASP-A03:2021"]


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run(scanner: "BaseScanner", url: str, param: str, method: str = "GET") -> None:
    """Entry point called per-param by scan_url()."""
    await _test_error(scanner, url, param, method)
    if not scanner.config.get("skip_time_sqli", False):
        await _test_time(scanner, url, param, method)
    await _test_boolean(scanner, url, param, method)
    await _test_union(scanner, url, param, method)
    await _test_nosql(scanner, url, param, method)
    await _test_second_order(scanner, url, param, method)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_real_url_param(url: str, param: str, method: str) -> bool:
    """V24 guard: skip guessed GET params that aren't in the URL's query string."""
    if method != "GET":
        return True
    parsed = urllib.parse.urlparse(url)
    return param in set(urllib.parse.parse_qs(parsed.query).keys())


def _get_variants(scanner: "BaseScanner", payload: str, count: int = 3):
    """Return WAF-bypass variants if WAF detected, else just the raw payload."""
    if scanner.waf_detected:
        return scanner.waf_evasion.generate_variants(payload, count)
    return [payload]


def _calculate_severity(scanner: "BaseScanner", vuln_type: str):
    from core.models import calculate_severity as _cs
    return _cs(vuln_type)


# ─────────────────────────────────────────────────────────────────────────────
# Error-based
# ─────────────────────────────────────────────────────────────────────────────

async def _test_error(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """Error-based SQLi + second-order check."""
    baseline = await scanner.make_request(method, url, params={param: "1"})
    if not baseline:
        return False

    for payload in ERROR_PAYLOADS:
        for variant in _get_variants(scanner, payload, 3):
            res = await scanner.make_request(method, url, params={param: variant})
            if not res:
                continue

            # FP guard: 4xx + short body is a validation rejection, not SQLi
            if res.status_code >= 400 and len(res.text) < 500:
                continue

            text_lower = res.text.lower()
            matches = [sig for sig in ERROR_SIGNATURES if sig in text_lower]

            if matches and matches[0] not in baseline.text.lower():
                severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
                exploit_notes = ""
                if scanner.ctf_mode and scanner.ctf_payloads:
                    exploit_notes = scanner.ctf_payloads.generate_exploitation_report(
                        "SQL Injection (Error)", url, param, variant
                    )
                scanner.log_vuln(Vulnerability(
                    type="SQL Injection (Error)",
                    url=url,
                    parameter=param,
                    payload=variant,
                    evidence=f"DB error: {', '.join(matches[:2])}",
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method=method,
                    detection_method="Error-based with WAF evasion",
                    remediation=REMEDIATION,
                    references=REFERENCES,
                    exploitation_notes=exploit_notes,
                ))
                return True

    # Second-order check
    second_order_result = scanner.second_order.check_execution(baseline.text, url)
    if second_order_result:
        severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
        exploit_notes = ""
        if scanner.ctf_mode and scanner.ctf_payloads:
            exploit_notes = scanner.ctf_payloads.generate_exploitation_report(
                "SQL Injection (Second-Order)",
                url,
                second_order_result["injection_point"]["param"],
                second_order_result["injection_point"]["payload"],
            )
        scanner.log_vuln(Vulnerability(
            type="SQL Injection (Second-Order Error)",
            url=url,
            parameter=second_order_result["injection_point"]["param"],
            payload=second_order_result["injection_point"]["payload"],
            evidence=(
                f"SQL marker {second_order_result['marker']} appeared "
                f"after {second_order_result['time_delta']:.2f}s"
            ),
            confidence="High",
            severity=severity,
            cvss_score=cvss,
            method=method,
            detection_method="Second-order SQL error marker",
            remediation=REMEDIATION,
            references=REFERENCES,
            exploitation_notes=exploit_notes,
        ))
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Time-based blind
# ─────────────────────────────────────────────────────────────────────────────

async def _test_time(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """Time-based blind SQLi with 3-sigma statistical analysis."""
    if not _is_real_url_param(url, param, method):
        return False

    # Warm baseline cache
    await scanner.get_baseline(url, method, param, "1")
    baseline_times = []
    for _ in range(3):
        t0 = time.time()
        await scanner.make_request(method, url, params={param: "1"})
        baseline_times.append(time.time() - t0)

    baseline_avg = statistics.mean(baseline_times)
    baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5

    # Full payload list only for --profile full or CTF mode
    full_profile = scanner.config.get("max_depth", 2) >= 5 or scanner.ctf_mode
    payloads_to_test = TIME_PAYLOADS if full_profile else TIME_PAYLOADS[:5]

    for payload, expected_delay in payloads_to_test:
        for variant in _get_variants(scanner, payload, 2):
            test_times = []
            for _ in range(3):
                t0 = time.time()
                await scanner.make_request(method, url, params={param: variant})
                test_times.append(time.time() - t0)

            test_avg = statistics.mean(test_times)
            difference = test_avg - baseline_avg
            threshold = baseline_avg + (3 * baseline_std)

            if difference >= expected_delay * 0.8 and test_avg >= threshold:
                severity, cvss = _calculate_severity(scanner, "SQL Injection (Time)")
                scanner.log_vuln(Vulnerability(
                    type="SQL Injection (Time)",
                    url=url,
                    parameter=param,
                    payload=variant,
                    evidence=(
                        f"Time delay: {difference:.2f}s "
                        f"(expected {expected_delay}s, 3-sigma threshold: {threshold:.2f}s)"
                    ),
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method=method,
                    detection_method="Time-based with 3-sigma statistical analysis",
                    remediation=REMEDIATION,
                    references=REFERENCES,
                ))
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Boolean-based blind
# ─────────────────────────────────────────────────────────────────────────────

async def _test_boolean(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """Boolean-based blind SQLi via differential response length analysis."""
    if not _is_real_url_param(url, param, method):
        return False

    baseline = await scanner.get_baseline(url, method, param, "safe_baseline_value")
    if not baseline:
        return False
    baseline_length = len(baseline.text)

    true_results = []
    for true_payload in BOOLEAN_PAYLOADS["true"]:
        res = await scanner.make_request(method, url, params={param: true_payload})
        if res:
            true_results.append((true_payload, len(res.text), res.text))

    false_results = []
    for false_payload in BOOLEAN_PAYLOADS["false"]:
        res = await scanner.make_request(method, url, params={param: false_payload})
        if res:
            false_results.append((false_payload, len(res.text), res.text))

    if true_results and false_results:
        true_avg = statistics.mean([r[1] for r in true_results])
        false_avg = statistics.mean([r[1] for r in false_results])
        max_len = max(true_avg, false_avg, 1)
        diff_ratio = abs(true_avg - false_avg) / max_len

        baseline_diff_true = abs(true_avg - baseline_length) / max(baseline_length, 1)
        baseline_diff_false = abs(false_avg - baseline_length) / max(baseline_length, 1)

        # 15% threshold + one side must be close to baseline
        if diff_ratio > 0.15 and (baseline_diff_true < 0.3 or baseline_diff_false < 0.3):
            severity, cvss = _calculate_severity(scanner, "SQL Injection (Boolean)")
            scanner.log_vuln(Vulnerability(
                type="SQL Injection (Boolean)",
                url=url,
                parameter=param,
                payload=true_results[0][0],
                evidence=(
                    f"Differential: true={true_avg:.0f}B vs false={false_avg:.0f}B "
                    f"({diff_ratio:.1%} diff, baseline={baseline_length}B)"
                ),
                confidence="High" if diff_ratio > 0.30 else "Medium",
                severity=severity,
                cvss_score=cvss,
                method=method,
                detection_method="Boolean differential analysis (baseline-anchored)",
                remediation=REMEDIATION,
                references=REFERENCES,
            ))
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# UNION-based
# ─────────────────────────────────────────────────────────────────────────────

async def _test_union(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """UNION-based SQLi: column-count probing + value reflection."""
    baseline = await scanner.get_baseline(url, method, param, "1")
    baseline_text = baseline.text if baseline else ""

    for payload in UNION_PAYLOADS:
        for variant in _get_variants(scanner, payload, 2):
            res = await scanner.make_request(method, url, params={param: variant})
            if not res:
                continue

            # FP guard
            if res.status_code >= 400 and len(res.text) < 500:
                continue

            text = res.text
            # Injection reflected: look for version/db strings or NULL column indicators
            indicators = ["information_schema", "database()", "version()", "@@version"]
            matched = [ind for ind in indicators if ind in text.lower() and ind not in baseline_text.lower()]
            if matched:
                severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
                scanner.log_vuln(Vulnerability(
                    type="SQL Injection (UNION)",
                    url=url,
                    parameter=param,
                    payload=variant,
                    evidence=f"UNION probe reflected DB metadata in response",
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method=method,
                    detection_method="UNION-based column-count probe + reflection",
                    remediation=REMEDIATION,
                    references=REFERENCES,
                ))
                return True

            # Also accept: status 200 response size significantly larger than baseline
            if baseline and len(text) > len(baseline_text) * 1.4 and len(text) > 200:
                error_sigs = [sig for sig in ERROR_SIGNATURES if sig in text.lower()]
                if error_sigs:
                    severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
                    scanner.log_vuln(Vulnerability(
                        type="SQL Injection (UNION/Error)",
                        url=url,
                        parameter=param,
                        payload=variant,
                        evidence=f"UNION probe triggered DB error: {error_sigs[0]}",
                        confidence="Medium",
                        severity=severity,
                        cvss_score=cvss,
                        method=method,
                        detection_method="UNION probe — error in enlarged response",
                        remediation=REMEDIATION,
                        references=REFERENCES,
                    ))
                    return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# NoSQL injection
# ─────────────────────────────────────────────────────────────────────────────

async def _test_nosql(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """MongoDB / NoSQL operator injection."""
    baseline = await scanner.get_baseline(url, method, param, "safe_value")
    baseline_status = baseline.status_code if baseline else 0
    baseline_len = len(baseline.text) if baseline else 0

    for payload in NOSQL_PAYLOADS:
        res = await scanner.make_request(method, url, params={param: payload})
        if not res:
            continue

        # Flag if: auth bypass (200 where baseline was 401/403) or significant length diff
        auth_bypass = baseline_status in (401, 403) and res.status_code == 200
        len_diff = abs(len(res.text) - baseline_len) / max(baseline_len, 1)
        nosql_in_body = any(sig in res.text.lower() for sig in ["mongod", "mongodb", "$where", "bsontype"])

        if auth_bypass or (len_diff > 0.2 and res.status_code == 200) or nosql_in_body:
            severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
            scanner.log_vuln(Vulnerability(
                type="NoSQL Injection",
                url=url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"Auth bypass detected" if auth_bypass
                    else f"Response length diff {len_diff:.1%} with NoSQL operator"
                ),
                confidence="Medium",
                severity=severity,
                cvss_score=cvss,
                method=method,
                detection_method="NoSQL operator injection — response differential",
                remediation=(
                    "Sanitize inputs before passing to MongoDB queries; "
                    "use typed schemas (Mongoose) to reject operator keys."
                ),
                references=["CWE-89", "OWASP-A03:2021"],
            ))
            return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Second-order
# ─────────────────────────────────────────────────────────────────────────────

async def _test_second_order(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """Second-order SQLi: inject marker, re-fetch a profile page, check for execution."""
    # Delegate to the scanner's existing second_order tracker (shared state)
    if not hasattr(scanner, "second_order"):
        return False

    marker_payloads = [
        f"'||(SELECT 1 FROM (SELECT SLEEP(0))a)||'",
        f"SQLI_MARKER_{param}_TEST",
    ]
    for payload in marker_payloads:
        await scanner.make_request(method, url, params={param: payload})

    # Check execution on a re-fetch (profile page is heuristic)
    profile_url = scanner.base_url.rstrip("/") + "/profile"
    res = await scanner.make_request("GET", profile_url)
    if res:
        result = scanner.second_order.check_execution(res.text, profile_url)
        if result:
            severity, cvss = _calculate_severity(scanner, "SQL Injection (Error)")
            scanner.log_vuln(Vulnerability(
                type="SQL Injection (Second-Order)",
                url=url,
                parameter=param,
                payload=result["injection_point"]["payload"],
                evidence=(
                    f"Stored SQLi marker {result['marker']} executed "
                    f"after {result['time_delta']:.2f}s on {profile_url}"
                ),
                confidence="Medium",
                severity=severity,
                cvss_score=cvss,
                method=method,
                detection_method="Second-order: store → re-fetch → marker detection",
                remediation=REMEDIATION,
                references=REFERENCES,
            ))
            return True

    return False
