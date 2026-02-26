"""
modules/graphql.py
GraphQL security test module.

Covers:
  - Introspection enabled (schema leak)
  - Field injection via GraphQL variables (SQLi / NoSQL)
  - Query batching attack (brute-force / DoS vector)

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
SENSITIVE_KEYWORDS = ["email", "admin", "role", "password", "token"]


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test URL and common GraphQL paths for GraphQL issues. Called per-URL by scan_url()."""
    if scanner.config.get("skip_graphql", False):
        return

    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    endpoints = [url] + [base + path for path in GRAPHQL_PATHS]

    for ep in endpoints:
        if await _test_graphql(scanner, ep):
            return True
    return False


async def _test_graphql(scanner: "BaseScanner", url: str) -> bool:
    headers = {"Content-Type": "application/json"}

    # ── 1. Introspection ─────────────────────────────────────────────────────
    introspection_query = {
        "query": "{ __schema { queryType { name } types { name kind fields { name } } } }"
    }
    res = await scanner.make_request("POST", url, json=introspection_query, headers=headers)
    if not res or res.status_code not in (200, 201):
        return False

    body = res.text.lower()
    if not ("__schema" in body or "querytype" in body or '"types"' in body):
        return False

    sev, cvss = calculate_severity("GraphQL Introspection")
    scanner.log_vuln(Vulnerability(
        type="GraphQL Introspection",
        url=url,
        parameter="GraphQL query",
        payload=json.dumps(introspection_query),
        evidence="Introspection query returned schema information",
        confidence="High",
        severity=sev,
        cvss_score=cvss,
        method="POST",
        detection_method="GraphQL introspection schema leak",
        remediation=(
            "Disable introspection in production environments. "
            "Add query depth and complexity limits. "
            "Implement field-level authorization."
        ),
        references=["CWE-200", "OWASP-A05:2021"],
        confidence_pct=90,
        indicators_matched=1,
    ))

    # ── 2. Field injection via variables ─────────────────────────────────────
    sqli_queries = [
        {"query": "{ user(id: \"1 OR 1=1\") { id email } }"},
        {"query": "{ product(name: \"' OR '1'='1\") { id name } }"},
        {"query": "{ user(email: \"admin@juice-sh.op\") { id role } }"},
        # NoSQL injection via variable
        {"query": "query($id: String) { user(id: $id) { id email } }",
         "variables": {"id": {"$gt": ""}}},
    ]
    for sq in sqli_queries:
        r2 = await scanner.make_request("POST", url, json=sq, headers=headers)
        if r2 and r2.status_code == 200:
            b2 = r2.text.lower()
            if any(kw in b2 for kw in SENSITIVE_KEYWORDS):
                sev2, cvss2 = calculate_severity("GraphQL Injection")
                scanner.log_vuln(Vulnerability(
                    type="GraphQL Injection",
                    url=url,
                    parameter="GraphQL query/variables",
                    payload=json.dumps(sq),
                    evidence=f"Sensitive data returned: {b2[:100]}",
                    confidence="Medium",
                    severity=sev2,
                    cvss_score=cvss2,
                    method="POST",
                    detection_method="GraphQL field injection / sensitive data leak",
                    remediation=(
                        "Validate and sanitize all GraphQL arguments. "
                        "Enforce query complexity limits and depth restrictions. "
                        "Use parameterized resolvers."
                    ),
                    references=["CWE-89", "OWASP-A03:2021"],
                    confidence_pct=65,
                    indicators_matched=1,
                ))
                break

    # ── 3. Batching attack ────────────────────────────────────────────────────
    batch_query = [
        {"query": "{ user(id: 1) { email } }"},
        {"query": "{ user(id: 2) { email } }"},
        {"query": "{ user(id: 3) { email } }"},
    ]
    r3 = await scanner.make_request("POST", url, json=batch_query, headers=headers)
    batch_accepted = False
    if r3 and r3.status_code == 200 and r3.text.strip().startswith("["):
        try:
            parsed_batch = r3.json()
            batch_accepted = isinstance(parsed_batch, list)
        except Exception:
            pass

    if batch_accepted:
        sev3, cvss3 = calculate_severity("GraphQL Batching")
        scanner.log_vuln(Vulnerability(
            type="GraphQL Batching",
            url=url,
            parameter="GraphQL batch request",
            payload=json.dumps(batch_query[:1]),
            evidence="Server supports query batching (potential brute-force / DoS vector)",
            confidence="Medium",
            severity=sev3,
            cvss_score=cvss3,
            method="POST",
            detection_method="GraphQL batch query accepted",
            remediation=(
                "Disable or rate-limit GraphQL query batching. "
                "Enforce per-IP request limits on the GraphQL endpoint."
            ),
            references=["CWE-770", "OWASP-A04:2021"],
            confidence_pct=60,
            indicators_matched=1,
        ))

    return True
