"""
reporting/sarif_report.py
SARIF 2.1 export — compatible with GitHub Advanced Security, Azure DevOps,
VS Code SARIF Viewer, and any SARIF-consuming CI/CD pipeline.
Called by BaseScanner.run() after scan completion.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import BaseScanner

_SEV_MAP = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
}


def export_sarif(scanner: "BaseScanner", filename: str = None) -> str:
    """Export scan results as SARIF 2.1.

    Args:
        scanner:  Completed BaseScanner instance.
        filename: Output path; auto-generated if omitted.

    Returns:
        Path of the written file.
    """
    if not filename:
        filename = f"scan_report_{int(time.time())}.sarif"

    # ── Rules: one per unique vuln type ──────────────────────────────────
    rule_ids: dict[str, int] = {}
    rules: list = []
    for v in scanner.results:
        if v.type not in rule_ids:
            rule_ids[v.type] = len(rule_ids)
            rules.append({
                "id":               f"WEBSCANNER{rule_ids[v.type]:04d}",
                "name":             v.type.replace(" ", "").replace("/", ""),
                "shortDescription": {"text": v.type},
                "fullDescription":  {"text": v.remediation or v.type},
                "helpUri": (
                    v.references[0]
                    if v.references
                    else "https://owasp.org/www-project-top-ten/"
                ),
                "properties": {
                    "tags":              ["security", v.severity.lower()],
                    "precision":         v.confidence.lower(),
                    "problem.severity":  _SEV_MAP.get(v.severity, "warning"),
                    "security-severity": str(v.cvss_score),
                },
                "defaultConfiguration": {
                    "level": _SEV_MAP.get(v.severity, "warning"),
                },
            })

    # ── Results ───────────────────────────────────────────────────────────
    sarif_results: list = []
    for v in scanner.results:
        rule_id = f"WEBSCANNER{rule_ids.get(v.type, 0):04d}"
        parsed  = urllib.parse.urlparse(v.url)
        sarif_results.append({
            "ruleId": rule_id,
            "level":  _SEV_MAP.get(v.severity, "warning"),
            "message": {
                "text": (
                    f"{v.type} detected at {v.url} "
                    f"(parameter: {v.parameter}, payload: {v.payload[:80]}) — "
                    f"{v.evidence[:200]}"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri":       v.url,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{
                    "name": parsed.path or "/",
                    "kind": "resource",
                }],
            }],
            "fingerprints": {
                "primaryLocationLineHash": hashlib.md5(
                    f"{v.type}{v.url}{v.parameter}".encode()
                ).hexdigest()
            },
            "properties": {
                "confidence":     v.confidence,
                "confidence_pct": v.confidence_pct,
                "cvss_score":     v.cvss_score,
                "method":         v.method,
                "payload":        v.payload[:300],
                "timestamp":      v.timestamp,
                "remediation":    v.remediation,
                "references":     v.references,
            },
        })

    # ── SARIF document ────────────────────────────────────────────────────
    sarif_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "V28UltimateScanner",
                    "version":        "28.0.0",
                    "informationUri": "https://github.com/your-org/scanner",
                    "rules":          rules,
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "commandLine":         f"main.py {scanner.base_url}",
                "startTimeUtc": datetime.fromtimestamp(
                    scanner.scan_start, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endTimeUtc": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "properties": {
                    "requestCount":  scanner.request_count,
                    "urlsScanned":   len(scanner.seen_urls),
                    "wafDetected":   scanner.waf_detected,
                    "authFailed":    getattr(scanner, "_auth_failed", False),
                },
            }],
            "results": sarif_results,
            "artifacts": [{
                "location":    {"uri": scanner.base_url},
                "description": {"text": "Target application"},
            }],
        }],
    }

    with open(filename, "w") as f:
        json.dump(sarif_doc, f, indent=2)
    print(f"[+] SARIF report: {filename}")
    return filename
