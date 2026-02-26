"""
modules/sensitive_endpoints.py
Probe 80+ common sensitive / exposed paths once per scan.

V20 feature: SPA catch-all false-positive suppression — compares each
200 response against a canary path to detect Angular/React/Vue routers
serving index.html for every path.

Entry point: async def run(scanner) -> None
"""
from __future__ import annotations

import difflib
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import BaseScanner

try:
    from core.models import Vulnerability, calculate_severity
except ImportError:
    from models import Vulnerability, calculate_severity  # type: ignore

# 80+ paths: admin panels, info disclosure, API docs, cloud/k8s, CI/CD, etc.
_SENSITIVE_PATHS = [
    # Admin / config
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/rest/admin/application-configuration",
    "/rest/admin/application-version",
    # Info disclosure
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/config.json", "/package.json", "/package-lock.json",
    "/composer.json", "/composer.lock", "/yarn.lock",
    "/server-status", "/server-info", "/.htaccess",
    "/web.config", "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Juice Shop specific
    "/ftp/", "/ftp/acquisitions.md", "/ftp/package.json.bak",
    "/ftp/eastere.gg", "/ftp/incident-support.kdbx",
    "/ftp/coupons_2013.md.bak", "/ftp/announcement.md",
    # API / docs
    "/api/", "/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/api-docs", "/api-docs/swagger.json",
    "/graphql", "/graphiql", "/v1/", "/v2/",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/mappings", "/actuator/beans", "/actuator/httptrace",
    "/actuator/logfile", "/actuator/info", "/actuator/dump",
    "/actuator/heapdump", "/actuator/threaddump", "/actuator/shutdown",
    "/metrics", "/health", "/info", "/trace", "/dump",
    # Backup / debug
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/debug", "/debug.php", "/test", "/dev",
    "/console", "/rails/info/properties", "/rails/info/routes",
    # Source code leaks
    "/index.php.bak", "/index.html.bak", "/config.php.bak",
    "/.DS_Store", "/Thumbs.db",
    # Secrets
    "/secret", "/secrets", "/credentials", "/keys", "/private",
    "/id_rsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    # Kubernetes / Docker
    "/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets",
    "/readyz", "/livez", "/healthz",
    "/debug/pprof/", "/debug/vars",
    # Laravel / PHP
    "/storage/logs/laravel.log", "/storage/app/public",
    "/.well-known/security.txt", "/phpinfo.php", "/info.php",
    # Django
    "/admin/login/", "/django-admin/",
    # Node.js / Express
    "/node_modules/", "/__webpack_hmr",
    # CI/CD leaks
    "/.github/workflows/", "/Jenkinsfile", "/.travis.yml",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    # nginx / Apache
    "/nginx_status", "/server-status?auto",
    # OAuth / OIDC
    "/.well-known/openid-configuration", "/oauth/authorize",
    "/oauth2/token", "/.well-known/jwks.json",
]


async def run(scanner: "BaseScanner") -> None:
    """Probe sensitive paths once per scan. Guard (_sensitive_done) is set by scanner."""
    root = scanner.base_url

    # ── Fetch root + canary to fingerprint SPA catch-all routers ─────────
    root_res  = await scanner.make_request("GET", root)
    root_text = root_res.text if root_res else ""
    root_len  = len(root_text)

    canary_url = urllib.parse.urljoin(root, "/____canary_nonexistent_v28____")
    canary_res = await scanner.make_request("GET", canary_url)

    spa_catchall       = False
    spa_body_fingerprint = ""
    spa_body_len       = 0

    if canary_res and canary_res.status_code == 200 and len(canary_res.text) > 100:
        canary_len = len(canary_res.text)
        max_len    = max(canary_len, root_len) or 1
        len_ratio  = min(canary_len, root_len) / max_len
        if len_ratio > 0.95:
            spa_catchall = True
        else:
            similarity = difflib.SequenceMatcher(
                None, root_text[:2000], canary_res.text[:2000]
            ).ratio()
            if similarity > 0.80:
                spa_catchall = True
        if spa_catchall:
            spa_body_fingerprint = canary_res.text[:500]
            spa_body_len         = canary_len
            if scanner.verbose:
                print(f"[~] SPA catch-all detected (len_ratio={len_ratio:.0%}) — sensitive endpoint filtering active")

    root_ct = (root_res.headers.get("content-type", "") if root_res else "").lower()

    # ── Probe each path ───────────────────────────────────────────────────
    for path in _SENSITIVE_PATHS:
        full_url = urllib.parse.urljoin(root, path)
        res = await scanner.make_request("GET", full_url)
        if not res:
            continue

        # SPA false-positive suppression
        if spa_catchall and res.status_code == 200 and len(res.text) > 100:
            res_len   = len(res.text)
            max_l     = max(res_len, spa_body_len) or 1
            len_ratio = min(res_len, spa_body_len) / max_l
            if len_ratio > 0.92:
                continue
            sim = difflib.SequenceMatcher(None, spa_body_fingerprint, res.text[:500]).ratio()
            if sim > 0.80:
                continue

        ct = res.headers.get("content-type", "").lower()
        spa_ct = root_ct
        different_ct = spa_catchall and ct and spa_ct and ct.split(";")[0] != spa_ct.split(";")[0]
        body_meaningful = (
            len(res.text) > 20 and (
                different_ct or
                not (
                    res.status_code == 200 and "text/html" in ct and len(res.text) > 10000
                    and ("<app-root" in res.text or "ng-version" in res.text
                         or "window.__NUXT__" in res.text or "__NEXT_DATA__" in res.text)
                )
            )
        )

        if res.status_code in (200, 206) and body_meaningful:
            sev, cvss = calculate_severity("Sensitive Endpoint")
            scanner.log_vuln(Vulnerability(
                type="Sensitive Endpoint Exposed",
                url=full_url,
                parameter="path",
                payload=path,
                evidence=f"HTTP {res.status_code} — {len(res.text)} bytes — Content-Type: {ct[:40]}",
                confidence="Medium",
                severity=sev,
                cvss_score=cvss,
                method="GET",
                detection_method="Endpoint enumeration with SPA catch-all filtering",
                remediation="Restrict access; remove or protect sensitive endpoints",
                references=["CWE-200", "OWASP-A05:2021"],
            ))
            if scanner.verbose:
                print(f"[!] Sensitive endpoint (200): {full_url}")

        elif res.status_code == 403:
            scanner.log_vuln(Vulnerability(
                type="Protected Endpoint Found (403)",
                url=full_url,
                parameter="path",
                payload=path,
                evidence="HTTP 403 — endpoint exists but access denied",
                confidence="Low",
                severity="Low",
                cvss_score=3.1,
                method="GET",
                detection_method="Endpoint enumeration",
                remediation="Verify this endpoint is intentionally protected and not bypassable",
                references=["CWE-200", "OWASP-A05:2021"],
            ))
            if scanner.verbose:
                print(f"[~] Protected endpoint (403): {full_url}")
