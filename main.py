#!/usr/bin/env python3
"""
main.py — V28 Ultimate Scanner entry point.

Thin CLI layer: parse args → apply profile presets → build config →
instantiate BaseScanner → run scan → write reports.

For authorized security testing and CTF competitions only.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
import traceback
from collections import defaultdict
from typing import List

from core.models import AuthConfig, Vulnerability
from core.scanner import BaseScanner

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║           V28 ULTIMATE COMPLETE - CTF EXAM READY              ║
║  ✅ SQLi  ✅ XSS  ✅ SSTI  ✅ CMDi  ✅ LFI  ✅ SSRF        ║
║  ✅ XXE  ✅ IDOR  ✅ JWT  ✅ CORS  ✅ GraphQL  ✅ WS        ║
║  ✅ Smuggling  ✅ Proto Pollution  ✅ OOB  ✅ SARIF         ║
╚═══════════════════════════════════════════════════════════════╝
   For Authorized Security Testing and CTF Competitions Only
"""


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="V28 ULTIMATE Security Scanner — For Authorized Testing and CTF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 main.py http://target.com

  # Juice Shop one-liner (auto-seeds endpoints + admin creds)
  python3 main.py http://localhost:3000 --juiceshop --verbose

  # With manual JSON REST authentication (e.g. Juice Shop)
  python3 main.py http://target.com \\
      --auth-url http://target.com/rest/user/login \\
      --username admin@site.com --password pass123 \\
      --auth-type json

  # CTF Mode
  python3 main.py http://ctf-target.com \\
      --ctf --attacker-ip 10.10.14.5 --attacker-port 4444 --verbose

  # Quick scan profile (fast, low noise)
  python3 main.py http://target.com --profile quick

  # API-focused profile (no browser DOM tests, no business logic)
  python3 main.py http://target.com --profile api

  # Full scan with custom output, timeout, and checkpoint
  python3 main.py http://target.com \\
      --max-depth 3 --enable-oob --verbose --output my_scan \\
      --timeout 45 --checkpoint my_scan.chk

  # Resume an interrupted scan
  python3 main.py http://target.com --checkpoint my_scan.chk

  # Multi-target batch scan
  python3 main.py --targets targets.txt --output batch_out

  # Plugin-based scan (drop .py into ./tests/)
  python3 main.py http://target.com --plugin-dir ./tests --verbose
        """,
    )

    # Target
    parser.add_argument(
        "url", nargs="?", default=None,
        help="Target URL (or use --targets for batch mode)",
    )

    # V19+: Multi-target + profiles
    v19 = parser.add_argument_group("V19+ Features")
    v19.add_argument(
        "--targets", default=None,
        help="File containing one URL per line for batch scanning",
    )
    v19.add_argument(
        "--profile", choices=["quick", "api", "webapp", "full"], default=None,
        help=(
            "Scan profile preset: "
            "quick=fast (skip time-sqli/websocket/business-logic/ssrf), "
            "api=API focus (no browser/business-logic/websocket), "
            "webapp=full web (default depth+all tests), "
            "full=everything (max depth, all tests, browser on)"
        ),
    )
    v19.add_argument(
        "--mode", choices=["fast", "standard", "deep"], default="standard",
        help=(
            "Scan speed/depth: fast=~5 min (SQLi/XSS/JWT/endpoints only, no CMDi/XXE/SSRF/blind), "
            "standard=~20 min all active tests no blind/OOB (default), "
            "deep=~60 min everything+blind+OOB max depth"
        ),
    )

    # Authentication
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--auth-url",  help="Login page URL")
    auth.add_argument("--username",  help="Username")
    auth.add_argument("--password",  help="Password")
    auth.add_argument(
        "--auth-type",
        choices=["form", "basic", "bearer", "json", "auto"], default="auto",
        help="Authentication type (default: auto). Use json for REST APIs like Juice Shop",
    )
    auth.add_argument("--success-indicator", help="Text indicating successful login")
    auth.add_argument(
        "--failure-indicator", default="invalid",
        help="Text indicating failed login (default: invalid)",
    )

    # CTF
    ctf = parser.add_argument_group("CTF Mode")
    ctf.add_argument("--ctf", action="store_true",
                     help="Enable CTF mode with exploitation payloads")
    ctf.add_argument("--attacker-ip",   help="Attacker IP for reverse shells")
    ctf.add_argument("--attacker-port", type=int, default=4444,
                     help="Attacker port for reverse shells (default: 4444)")

    # Scan options
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("--max-depth",  type=int,   default=2,
                      help="Maximum crawl depth (default: 2)")
    scan.add_argument("--concurrency", type=int,  default=5,
                      help="Concurrent requests (default: 5)")
    scan.add_argument("--rate-limit",  type=float, default=0.2,
                      help="Delay between requests in seconds (default: 0.2)")
    scan.add_argument("--timeout",     type=float, default=30.0,
                      help="HTTP request timeout in seconds (default: 30)")
    scan.add_argument("--skip-time-sqli",      action="store_true",
                      help="Skip time-based SQLi tests (much faster scans)")
    scan.add_argument("--skip-graphql",        action="store_true",
                      help="Skip GraphQL-specific tests")
    scan.add_argument("--skip-websocket",      action="store_true",
                      help="Skip WebSocket fuzzing tests")
    scan.add_argument("--skip-business-logic", action="store_true",
                      help="Skip Juice Shop business logic tests")
    scan.add_argument("--skip-ssrf",           action="store_true",
                      help="Skip SSRF tests (faster scans when not testing SSRF)")
    scan.add_argument("--skip-idor",           action="store_true",
                      help="Skip IDOR / BOLA tests")
    scan.add_argument("--juiceshop",           action="store_true",
                      help="Juice Shop preset: seeds known endpoints, uses JSON auth")

    # Features
    feat = parser.add_argument_group("Feature Toggles")
    feat.add_argument("--enable-browser",  action="store_true", default=True,
                      help="Enable browser-based testing (default: enabled)")
    feat.add_argument("--disable-browser", action="store_false", dest="enable_browser",
                      help="Disable browser-based testing")
    feat.add_argument("--enable-oob",  action="store_true", default=True,
                      help="Enable OOB server (default: enabled)")
    feat.add_argument("--disable-oob", action="store_false", dest="enable_oob",
                      help="Disable OOB server")
    feat.add_argument("--oob-port", type=int, default=8888,
                      help="OOB server port (default: 8888)")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    out.add_argument(
        "--output", "-o", default=None,
        help="Output file prefix (default: auto timestamped). "
             "Generates <prefix>_<ts>.json / .html / .sarif",
    )
    out.add_argument(
        "--checkpoint", default=None,
        help="Checkpoint file for pause/resume. If file exists, scan resumes from it.",
    )
    out.add_argument(
        "--plugin-dir", default="tests",
        help="Directory to load external test plugins from (default: ./tests)",
    )

    return parser.parse_args()


# ── Mode presets ──────────────────────────────────────────────────────────────

def apply_mode(args: argparse.Namespace) -> None:
    """Mutate args based on --mode. Runs before --profile so profile can override."""
    if args.mode == "fast":
        args.skip_time_sqli      = True
        args.skip_ssrf           = True
        args.skip_websocket      = True
        args.enable_oob          = False
        args.max_depth           = 1
        args.concurrency         = 15
        args._skip_cmdi          = True
        args._skip_xxe           = True
        print("[*] Mode: FAST — SQLi, XSS, JWT, endpoints only (~5 min)")
    elif args.mode == "standard":
        args.enable_oob          = False
        args._skip_cmdi          = False
        args._skip_xxe           = False
        print("[*] Mode: STANDARD — all active tests, no blind/OOB (~20 min)")
    elif args.mode == "deep":
        args.skip_ssrf           = False
        args.skip_websocket      = False
        args.enable_oob          = True
        args.enable_browser      = True
        args.max_depth           = max(getattr(args, 'max_depth', 2), 3)
        args.concurrency         = 5
        args._skip_cmdi          = False
        args._skip_xxe           = False
        print("[*] Mode: DEEP — all tests + blind/OOB (~60 min)")


# ── Profile presets ───────────────────────────────────────────────────────────

def apply_profile(args: argparse.Namespace) -> None:
    """Mutate args in-place based on --profile selection."""
    if args.profile == "quick":
        args.skip_time_sqli      = True
        args.skip_websocket      = True
        args.skip_business_logic = True
        args.skip_ssrf           = True
        args.max_depth           = 1
        args.concurrency         = 15
        args.enable_browser      = False
        print("[*] Profile: QUICK — fast, low noise")

    elif args.profile == "api":
        args.skip_business_logic = True
        args.skip_websocket      = True
        args.enable_browser      = False
        args.max_depth           = 3
        args.concurrency         = 10
        print("[*] Profile: API — REST/GraphQL focused")

    elif args.profile == "webapp":
        args.max_depth   = 3
        args.concurrency = 8
        print("[*] Profile: WEBAPP — full web app testing")

    elif args.profile == "full":
        args.max_depth      = 5
        args.concurrency    = 5
        args.enable_browser = True
        print("[*] Profile: FULL — maximum depth + all tests")


# ── Config builder ────────────────────────────────────────────────────────────

def build_config(args: argparse.Namespace) -> dict:
    return {
        "verbose":              args.verbose,
        "max_depth":            args.max_depth,
        "concurrency":          args.concurrency,
        "rate_limit":           args.rate_limit,
        "timeout":              args.timeout,
        "enable_browser":       args.enable_browser,
        "enable_oob":           args.enable_oob,
        "oob_port":             args.oob_port,
        "output":               args.output,
        "skip_time_sqli":       getattr(args, "skip_time_sqli",      False),
        "skip_graphql":         getattr(args, "skip_graphql",        False),
        "skip_websocket":       getattr(args, "skip_websocket",      False),
        "skip_business_logic":  getattr(args, "skip_business_logic", False),
        "skip_ssrf":            getattr(args, "skip_ssrf",           False),
        "skip_idor":            getattr(args, "skip_idor",           False),
        "skip_cmdi":            getattr(args, "_skip_cmdi",          False),
        "skip_xxe":             getattr(args, "_skip_xxe",           False),
        "checkpoint":           args.checkpoint,
        "plugin_dir":           args.plugin_dir,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    print(BANNER)
    args = parse_args()

    if not args.url and not args.targets:
        print("[!] Error: provide a target URL or --targets <file>")
        raise SystemExit(1)

    # Apply mode first (sets defaults), then profile (can override)
    apply_mode(args)
    if args.profile:
        apply_profile(args)

    config = build_config(args)

    # ── Collect targets ───────────────────────────────────────────────────
    targets: List[str] = []
    if args.targets:
        try:
            with open(args.targets) as tf:
                for line in tf:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        targets.append(stripped)
            print(f"[*] Batch mode: {len(targets)} targets loaded from {args.targets}")
        except FileNotFoundError:
            print(f"[!] Targets file not found: {args.targets}")
            raise SystemExit(1)
    if args.url:
        targets.insert(0, args.url)

    # ── Juice Shop preset ─────────────────────────────────────────────────
    juice_alt_passwords: List[str] = []
    if args.juiceshop and targets:
        first = targets[0]
        print("[*] Juice Shop preset enabled — seeding known endpoints and auth")
        if not args.auth_url:
            args.auth_url = first.rstrip("/") + "/rest/user/login"
        if not args.auth_type or args.auth_type == "auto":
            args.auth_type = "json"
        if not args.username:
            args.username = "admin@juice-sh.op"
        if not args.password:
            args.password = "admin123"
        juice_alt_passwords = ["Admin1234!", "password", "juice", "12345", "admin"]

    # ── Scan each target ──────────────────────────────────────────────────
    all_results: List[Vulnerability] = []

    for idx, target_url in enumerate(targets):
        if len(targets) > 1:
            print(f"\n[*] === Scanning target {idx+1}/{len(targets)}: {target_url} ===")

        per_config = dict(config)
        if config.get("output") and len(targets) > 1:
            per_config["output"] = f"{config['output']}_target{idx+1}"

        auth_config = None
        if args.username and args.password:
            auth_config = AuthConfig(
                login_url=args.auth_url or target_url,
                username=args.username,
                password=args.password,
                auth_type=args.auth_type,
                success_indicator=args.success_indicator or "",
                failure_indicator=args.failure_indicator,
            )

        scanner = BaseScanner(
            base_url=target_url,
            config=per_config,
            auth_config=auth_config,
            ctf_mode=args.ctf,
            attacker_ip=args.attacker_ip,
            attacker_port=args.attacker_port,
        )
        if juice_alt_passwords:
            scanner._alt_passwords = juice_alt_passwords

        try:
            await scanner.run()
            all_results.extend(scanner.results)
        except (KeyboardInterrupt, asyncio.CancelledError):
            print("\n[!] Scan interrupted — saving checkpoint and writing partial report...")
            scanner.save_checkpoint()
            await scanner.close()
            scanner._print_report()
            break
        except Exception as exc:
            print(f"\n[!] Error scanning {target_url}: {exc}")
            scanner.save_checkpoint()
            if args.verbose:
                traceback.print_exc()
            await scanner.close()

    # ── Batch summary ─────────────────────────────────────────────────────
    if len(targets) > 1:
        print(f"\n{'='*70}")
        print(f"BATCH SCAN COMPLETE — {len(targets)} targets | {len(all_results)} total findings")
        by_sev: dict = defaultdict(int)
        for v in all_results:
            by_sev[v.severity] += 1
        for sev in ["Critical", "High", "Medium", "Low"]:
            if by_sev[sev]:
                print(f"  {sev}: {by_sev[sev]}")
        print(f"{'='*70}")


if __name__ == "__main__":
    asyncio.run(main())
