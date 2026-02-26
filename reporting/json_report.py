"""
reporting/json_report.py
JSON export — flat list of vulnerabilities + scan metadata.
Called by BaseScanner.run() after scan completion.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import BaseScanner


def export_json(scanner: "BaseScanner", filename: str = None) -> str:
    """Export scan results to a JSON file.

    Args:
        scanner:  Completed BaseScanner instance.
        filename: Output path; auto-generated if omitted.

    Returns:
        Path of the written file.
    """
    if not filename:
        filename = f"scan_results_{int(time.time())}.json"

    data = {
        "scan_info": {
            "target":       scanner.base_url,
            "scan_time":    time.time() - scanner.scan_start,
            "timestamp":    datetime.now().isoformat(),
            "requests":     scanner.request_count,
            "urls_scanned": len(scanner.seen_urls),
            "waf_detected": scanner.waf_detected,
            "waf_type":     scanner.waf_type if scanner.waf_detected else None,
            "ctf_mode":     scanner.ctf_mode,
            "auth_failed":  getattr(scanner, "_auth_failed", False),
        },
        "vulnerabilities": [asdict(v) for v in scanner.results],
        "summary": {
            "total": len(scanner.results),
            "by_severity": {
                "critical": sum(1 for v in scanner.results if v.severity == "Critical"),
                "high":     sum(1 for v in scanner.results if v.severity == "High"),
                "medium":   sum(1 for v in scanner.results if v.severity == "Medium"),
                "low":      sum(1 for v in scanner.results if v.severity == "Low"),
            },
            "by_type": {
                v_type: sum(1 for x in scanner.results if x.type == v_type)
                for v_type in {v.type for v in scanner.results}
            },
        },
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON report: {filename}")
    return filename
