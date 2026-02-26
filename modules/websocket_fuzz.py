"""
modules/websocket_fuzz.py
WebSocket injection fuzzing module.

Converts http(s):// to ws(s)://, probes common WS paths,
and sends XSS/SQLi/SSTI/CMDi/prototype-pollution payloads.

Requires: pip install websockets

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import asyncio
import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

INJECT_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR '1'='1",
    "{{7*7}}",
    "; id",
    '{"__proto__":{"admin":true}}',
]

INJECTION_INDICATORS = ["49", "alert", "script", "uid=", "gid=", "admin", "true", "syntax error"]

WS_EXTRA_PATHS = ["/socket.io/", "/ws", "/websocket", "/live", "/stream"]


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test URL for WebSocket injection. Called per-URL by scan_url()."""
    if scanner.config.get("skip_websocket", False):
        return
    if not WEBSOCKETS_AVAILABLE:
        if getattr(scanner, "verbose", False):
            print("[~] WebSocket testing skipped (pip install websockets)")
        return
    await _test_websocket(scanner, url)


async def _test_websocket(scanner: "BaseScanner", url: str) -> bool:
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")
    ws_targets = [ws_url]
    for path in WS_EXTRA_PATHS:
        ws_targets.append(urllib.parse.urljoin(url, path).replace("http", "ws"))

    for ws_target in ws_targets:
        for payload in INJECT_PAYLOADS:
            try:
                async with websockets.connect(
                    ws_target, open_timeout=5, close_timeout=3
                ) as ws:
                    await ws.send(payload)
                    try:
                        reply = await asyncio.wait_for(ws.recv(), timeout=3)
                        reply_lower = str(reply).lower()
                        if any(sig in reply_lower for sig in INJECTION_INDICATORS):
                            sev, cvss = calculate_severity("WebSocket Injection")
                            scanner.log_vuln(Vulnerability(
                                type="WebSocket Injection",
                                url=ws_target,
                                parameter="WebSocket message",
                                payload=payload,
                                evidence=f"Server echoed injection indicator: {str(reply)[:120]}",
                                confidence="Medium",
                                severity=sev,
                                cvss_score=cvss,
                                method="WS",
                                detection_method="WebSocket payload injection + response analysis",
                                remediation=(
                                    "Validate and sanitize all WebSocket message data server-side. "
                                    "Treat WebSocket input with the same scrutiny as HTTP parameters."
                                ),
                                references=["CWE-79", "OWASP-A03:2021"],
                                confidence_pct=60,
                                indicators_matched=1,
                            ))
                            return True
                    except asyncio.TimeoutError:
                        pass
            except Exception:
                pass
    return False
