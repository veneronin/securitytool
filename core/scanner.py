"""
core/scanner.py
BaseScanner — crawl, request engine, auth, concurrency, plugins, checkpointing.
Modules call scanner.log_vuln() and scanner.make_request() via the shared interface.
"""
from __future__ import annotations

import asyncio
import difflib
import importlib
import importlib.util
import inspect
import json
import os
import random
import re
import statistics
import time
import urllib.parse
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from bs4 import BeautifulSoup

from core.auth_handler import EnhancedAuthHandler
from core.models import AuthConfig, Vulnerability, calculate_severity
from core.oob_server import EnhancedOOBServer
from core.waf_evasion import AdvancedWAFEvasion

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    class tqdm:
        def __init__(self, *a, **kw): self.total = kw.get('total', 0); self._n = 0
        def update(self, n=1): self._n += n
        def set_postfix_str(self, s, **kw): pass
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass

try:
    from playwright.async_api import async_playwright, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class SecondOrderTracker:
    def __init__(self, verbose: bool = False):
        self.injections: Dict[str, List[Dict]] = defaultdict(list)
        self.verbose = verbose

    def record_injection(self, url, param, payload, marker, vuln_type="XSS"):
        self.injections[marker].append({
            "url": url, "param": param, "payload": payload,
            "timestamp": time.time(), "marker": marker, "vuln_type": vuln_type,
        })

    def check_execution(self, response_text: str, url: str) -> Optional[Dict]:
        for marker, injections in self.injections.items():
            if marker in response_text:
                return {
                    "marker": marker,
                    "injection_point": injections[0],
                    "execution_point": url,
                    "time_delta": time.time() - injections[0]['timestamp'],
                }
        return None

    def generate_marker(self, prefix: str = "XXX") -> str:
        import uuid
        return f"{prefix}{uuid.uuid4().hex[:8]}{prefix}"


class BaseScanner:
    """
    Core scanner: HTTP engine, crawl, auth, plugin loader, dedup, reporting hooks.
    Vulnerability modules receive this object and call self.log_vuln() / self.make_request().
    """

    def __init__(
        self,
        base_url: str,
        config: Dict = None,
        auth_config: AuthConfig = None,
        ctf_mode: bool = False,
        attacker_ip: str = None,
        attacker_port: int = 4444,
    ):
        self.base_url = base_url
        self.config = config or {}
        self.verbose = self.config.get('verbose', False)
        self.auth_config = auth_config
        self.ctf_mode = ctf_mode
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port

        _timeout = self.config.get('timeout', 30.0)
        self.client = httpx.AsyncClient(
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "DNT": "1",
                "Connection": "keep-alive",
            },
            follow_redirects=True,
            timeout=_timeout,
        )

        # State
        self.seen_urls: Set[str] = set()
        self.results: List[Vulnerability] = []
        self.request_count = 0
        self.scan_start = time.time()

        # Components
        self.oob_server = EnhancedOOBServer(port=self.config.get('oob_port', 8888))
        self.oob_server.verbose = self.verbose
        self.waf_evasion = AdvancedWAFEvasion(verbose=self.verbose)
        self.auth_handler = EnhancedAuthHandler(self.client, self.verbose)
        self.second_order = SecondOrderTracker(verbose=self.verbose)
        self._second_order_param_count: Dict[str, Set[str]] = defaultdict(set)

        # WAF state
        self.waf_detected = False
        self.waf_type = "Unknown"

        # Rate limiting
        self.semaphore = asyncio.Semaphore(self.config.get('concurrency', 5))
        self.rate_limit = self.config.get('rate_limit', 0.2)
        self.last_request = 0
        self._max_concurrency = self.config.get('concurrency', 5)
        self._current_concurrency = self._max_concurrency
        self._response_times: List[float] = []

        # Caches & dedup
        self._baseline_cache: Dict[str, Tuple[int, int, str]] = {}
        self._vuln_keys: Set[str] = set()
        self._cors_seen: Set[str] = set()

        # Misc flags
        self._auth_failed = False
        self._sensitive_done = False
        self._graphql_done = False
        self._ws_done = False
        self._bizlogic_done = False
        self._rate_limited_urls: Set[str] = set()

        # Checkpoint
        self._checkpoint_file = self.config.get('checkpoint', None)

        # Progress bar
        self._pbar = None

        # CTF payloads (lazy import to avoid circular deps)
        self.ctf_payloads = None
        if ctf_mode:
            from payloads.shells import CTFPayloadGenerator
            if not self.attacker_ip:
                self.attacker_ip = self.oob_server.get_local_ip()
            self.ctf_payloads = CTFPayloadGenerator(self.attacker_ip, self.attacker_port)
            self.ctf_payloads.verbose = self.verbose

        # Browser
        self.browser: Optional[Any] = None
        self.playwright = None
        self.use_browser = self.config.get('enable_browser', True) and PLAYWRIGHT_AVAILABLE

        # Plugin registry
        self._plugins: List[Any] = []
        self._load_plugins()

    # ── Plugin loading ──────────────────────────────────────────────────────

    def _load_plugins(self):
        plugin_dir = self.config.get('plugin_dir', 'tests')
        if not os.path.isdir(plugin_dir):
            return
        for fname in sorted(os.listdir(plugin_dir)):
            if not fname.endswith('.py') or fname.startswith('_'):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    fname[:-3], os.path.join(plugin_dir, fname)
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if hasattr(cls, 'run') and hasattr(cls, 'PLUGIN_NAME'):
                        inst = cls()
                        self._plugins.append(inst)
                        if self.verbose:
                            print(f"[+] Plugin loaded: {cls.PLUGIN_NAME}")
            except Exception as e:
                print(f"[!] Plugin load error ({fname}): {e}")

    # ── Checkpoint ──────────────────────────────────────────────────────────

    def save_checkpoint(self):
        if not self._checkpoint_file:
            return
        state = {
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "seen_urls": list(self.seen_urls),
            "request_count": self.request_count,
            "results": [asdict(v) for v in self.results],
        }
        try:
            with open(self._checkpoint_file, 'w') as f:
                json.dump(state, f, indent=2)
            if self.verbose:
                print(f"[~] Checkpoint saved: {self._checkpoint_file}")
        except Exception as e:
            print(f"[!] Checkpoint save error: {e}")

    def load_checkpoint(self):
        if not self._checkpoint_file or not os.path.exists(self._checkpoint_file):
            return False
        try:
            with open(self._checkpoint_file, 'r') as f:
                state = json.load(f)
            if state.get('target') != self.base_url:
                print("[!] Checkpoint target mismatch — ignoring")
                return False
            self.seen_urls = set(state.get('seen_urls', []))
            self.request_count = state.get('request_count', 0)
            for vdata in state.get('results', []):
                try:
                    self.results.append(Vulnerability(**{
                        k: v for k, v in vdata.items()
                        if k in Vulnerability.__dataclass_fields__
                    }))
                except Exception:
                    pass
            print(f"[~] Resumed: {len(self.seen_urls)} URLs, {len(self.results)} vulns")
            return True
        except Exception as e:
            print(f"[!] Checkpoint load error: {e}")
            return False

    # ── Vulnerability logging ───────────────────────────────────────────────

    def log_vuln(self, vuln: Vulnerability):
        key = f"{vuln.type}|{vuln.url}|{vuln.parameter}|{vuln.payload[:60]}"
        if key in self._vuln_keys:
            return
        self._vuln_keys.add(key)
        self.results.append(vuln)
        colors = {"Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[94m", "Low": "\033[92m"}
        color = colors.get(vuln.severity, "")
        reset = "\033[0m"
        print(f"{color}[{vuln.confidence}] {vuln.severity} - {vuln.type} ({vuln.confidence_pct}%){reset}")
        print(f"    URL: {vuln.url}")
        print(f"    Param: {vuln.parameter}")
        if self.verbose:
            print(f"    Method: {vuln.detection_method}")
        self.save_checkpoint()

    # ── Baseline cache ──────────────────────────────────────────────────────

    async def get_baseline(
        self, url: str, method: str = "GET", param: str = "", safe_val: str = "baseline_safe_value"
    ) -> Optional[Any]:
        key = f"{method}|{url}|{param}"
        if key in self._baseline_cache:
            status, length, text = self._baseline_cache[key]
            class _Cached:
                def __init__(self, s, l, t):
                    self.status_code = s; self._len = l; self.text = t
                def __len__(self): return self._len
            return _Cached(status, length, text)
        res = await self.make_request(method, url, params={param: safe_val} if param else {})
        if res:
            self._baseline_cache[key] = (res.status_code, len(res.text), res.text)
        return res

    # ── HTTP engine ─────────────────────────────────────────────────────────

    async def throttle(self):
        now = time.time()
        delay = self.waf_evasion.timing_randomization() if self.waf_detected else self.rate_limit
        elapsed = now - self.last_request
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        self.last_request = time.time()

    async def make_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        async with self.semaphore:
            await self.throttle()
            self.request_count += 1
            if self._pbar is not None:
                self._pbar.update(1)
                self._pbar.set_postfix_str(
                    f"vulns={len(self.results)} urls={len(self.seen_urls)}", refresh=True
                )
            if not TQDM_AVAILABLE and self.request_count % 25 == 0:
                elapsed = time.time() - self.scan_start
                print(f"[~] {self.request_count} reqs | {len(self.seen_urls)} URLs | "
                      f"{len(self.results)} vulns | {elapsed:.0f}s")

            if self.waf_detected:
                self.client.headers['User-Agent'] = self.waf_evasion.rotate_user_agent()

            if method == "POST" and url in self.auth_handler.csrf_tokens:
                if 'data' not in kwargs:
                    kwargs['data'] = {}
                kwargs['data']['csrf_token'] = self.auth_handler.csrf_tokens[url]

            follow = kwargs.pop('follow_redirects', True)
            kwargs.pop('_no_reauth', None)
            _no_reauth = False

            if url in self._rate_limited_urls:
                return None

            for attempt in range(4):
                try:
                    t0 = time.time()
                    if method == "GET":
                        res = await self.client.get(url, follow_redirects=follow, **kwargs)
                    elif method == "POST":
                        res = await self.client.post(url, follow_redirects=follow, **kwargs)
                    else:
                        res = await self.client.request(method, url, follow_redirects=follow, **kwargs)

                    elapsed_req = time.time() - t0
                    self._response_times.append(elapsed_req)
                    if len(self._response_times) > 20:
                        self._response_times.pop(0)
                        avg = statistics.mean(self._response_times)
                        if avg > 3.0 and self._current_concurrency > 1:
                            self._current_concurrency = max(1, self._current_concurrency - 1)
                            self.semaphore = asyncio.Semaphore(self._current_concurrency)
                        elif avg < 0.5 and self._current_concurrency < self._max_concurrency:
                            self._current_concurrency = min(self._max_concurrency, self._current_concurrency + 1)
                            self.semaphore = asyncio.Semaphore(self._current_concurrency)

                    if res.status_code in (429, 503):
                        wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                        if self.verbose:
                            print(f"[!] Rate limited ({res.status_code}), backoff {wait:.1f}s")
                        await asyncio.sleep(wait)
                        if attempt >= 2:
                            self._rate_limited_urls.add(url)
                            return None
                        continue

                    _is_auth_url = (
                        self.auth_config and self.auth_config.login_url and
                        self.auth_config.login_url in url
                    )
                    if (res.status_code == 401 and self.auth_config and
                            not _no_reauth and not _is_auth_url and not self._auth_failed):
                        if self.verbose:
                            print("[~] 401, refreshing auth...")
                        ok = await self.auth_handler.attempt_login(self.auth_config)
                        if not ok:
                            self._auth_failed = True
                        _no_reauth = True
                        continue

                    if self._auth_failed and res.status_code in (401, 403):
                        return None

                    if not self.waf_detected:
                        waf = self.waf_evasion.detect_waf(res)
                        if waf['detected']:
                            self.waf_detected = True
                            self.waf_type = waf['type']
                            indicators = waf.get('indicators', [])
                            ind_str = f" [{', '.join(indicators[:3])}]" if indicators else ""
                            print(f"\n[!] WAF Detected: {self.waf_type}{ind_str} — enabling evasion\n")

                    return res

                except Exception as e:
                    err = str(e)
                    if any(p in err for p in [
                        "Only Transfer-Encoding: chunked is supported",
                        "Illegal header value", "Invalid header value",
                    ]):
                        return None
                    if self.verbose:
                        print(f"[-] Request error (attempt {attempt+1}): {err[:100]}")
                    if attempt < 3:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        return None
        return None

    # ── Browser ─────────────────────────────────────────────────────────────

    async def init_browser(self):
        if self.use_browser and not self.browser:
            try:
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(headless=True)
                if self.verbose:
                    print("[*] Browser initialized")
            except Exception:
                self.use_browser = False

    async def close(self):
        try:
            await self.client.aclose()
        except Exception:
            pass
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
        if self.playwright:
            try:
                await self.playwright.stop()
            except Exception:
                pass
        self.oob_server.stop()

    # ── Parameter extraction ────────────────────────────────────────────────

    def extract_parameters(self, url: str, soup: BeautifulSoup, page_text: str) -> Dict[str, Set[str]]:
        params: Dict[str, Set[str]] = {'get': set(), 'post': set(), 'json': set()}

        parsed = urllib.parse.urlparse(url)
        params['get'].update(urllib.parse.parse_qs(parsed.query).keys())

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            t = 'post' if method == "POST" else 'get'
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    params[t].add(name)

        _SKIP_ATTRS = {
            "beasties-container", "beasties-inlined", "ng-version", "ng-server-context",
            "nuxt", "next-page", "data-reactroot", "v-cloak", "ssr", "hydrate",
        }
        for elem in soup.find_all(lambda tag: any(k.startswith('data-') for k in tag.attrs)):
            for attr, val in elem.attrs.items():
                if not attr.startswith('data-'):
                    continue
                name = attr[5:]
                if name.lower() in _SKIP_ATTRS:
                    continue
                if any(name.lower().startswith(p) for p in ('ng', 'nguniversal', 'beasties')):
                    continue
                params['get'].add(name)

        for script in soup.find_all("script"):
            txt = script.string or ""
            for match in re.findall(r'\{[^{}]*["\'](\w+)["\']\s*:', txt):
                if match not in ('var', 'let', 'const', 'function', 'return', 'if', 'else'):
                    params['json'].add(match)
            for match in re.findall(r'(?:var|let|const)\s+(\w+)\s*=', txt):
                if len(match) > 2:
                    params['json'].add(match)
            for match in re.findall(r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]', txt):
                if '?' in match:
                    params['json'].update(urllib.parse.parse_qs(match.split('?')[1]).keys())

        return params

    # ── Crawl ────────────────────────────────────────────────────────────────

    async def crawl(self, start_url: str, max_depth: int = 2):
        to_visit = [(start_url, 0)]
        visited: Set[str] = set(self.seen_urls)

        juice_endpoints = [
            "/rest/user/login", "/rest/user/change-password", "/rest/user/whoami",
            "/rest/products/search?q=test", "/api/Users", "/api/Users/1",
            "/api/Products", "/api/Products/1", "/rest/basket/1",
            "/api/BasketItems", "/api/Feedbacks", "/rest/challenges",
            "/rest/admin/application-configuration", "/ftp/",
        ]
        for ep in juice_endpoints:
            full = urllib.parse.urljoin(start_url, ep)
            if full not in visited:
                to_visit.append((full, 1))

        js_pattern = re.compile(r'["\'](/(?:api|rest|ftp)/[^\s"\'<>?#]{1,80})["\']')

        # V29 FIX: reject paths scraped from JSON that contain embedded external URLs.
        # e.g. admin-config returns JSON with "https://twitter.com/..." values; the
        # regex captures /api/"https://... producing garbage scan targets.
        def _valid_scraped_path(match: str) -> bool:
            return not any(c in match for c in ('"', "'", "http:", "https:", "%22", "%27", "\\"))

        while to_visit:
            url, depth = to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            res = await self.make_request("GET", url)
            if not res:
                continue

            soup = BeautifulSoup(res.text, 'html.parser')
            await self.scan_url(url, soup, res.text)

            if depth < max_depth:
                for link in soup.find_all('a', href=True):
                    nxt = urllib.parse.urljoin(url, link['href'])
                    if urllib.parse.urlparse(nxt).netloc == urllib.parse.urlparse(start_url).netloc:
                        if nxt not in visited:
                            to_visit.append((nxt, depth + 1))

                for script in soup.find_all('script', src=True):
                    src = urllib.parse.urljoin(url, script['src'])
                    if urllib.parse.urlparse(src).netloc == urllib.parse.urlparse(start_url).netloc:
                        js_res = await self.make_request("GET", src)
                        if js_res:
                            for match in js_pattern.findall(js_res.text):
                                if not _valid_scraped_path(match):
                                    continue
                                cand = urllib.parse.urljoin(start_url, match)
                                if cand not in visited:
                                    to_visit.append((cand, depth + 1))

                for script in soup.find_all('script', src=False):
                    for match in js_pattern.findall(script.string or ""):
                        if not _valid_scraped_path(match):
                            continue
                        cand = urllib.parse.urljoin(start_url, match)
                        if cand not in visited:
                            to_visit.append((cand, depth + 1))

    # ── scan_url: orchestrates all module calls ─────────────────────────────

    async def scan_url(self, url: str, soup: BeautifulSoup = None, page_text: str = ""):
        if url in self.seen_urls:
            return
        self.seen_urls.add(url)

        _is_auth_endpoint = (
            self.auth_config and self.auth_config.login_url and
            self.auth_config.login_url.rstrip('/') in url.rstrip('/')
        )

        if self.verbose:
            print(f"\n[*] Scanning: {url}")

        if not soup:
            res = await self.make_request("GET", url)
            if not res:
                return
            soup = BeautifulSoup(res.text, 'html.parser')
            page_text = res.text

        params = self.extract_parameters(url, soup, page_text)

        # Supplement REST API params
        rest_param_map = {
            "/rest/products/search": ["q"],
            "/rest/user/login":      ["email", "password"],
            "/rest/user/change-password": ["current", "new", "repeat"],
            "/api/Users":            ["email", "password", "username"],
            "/api/Products":         ["name", "description", "price"],
            "/api/Feedbacks":        ["comment", "rating"],
            "/api/BasketItems":      ["ProductId", "quantity", "BasketId"],
        }
        rest_get_ok = {"/rest/products/search"}
        parsed_path = urllib.parse.urlparse(url).path
        _is_rest = parsed_path.startswith("/rest/") or parsed_path.startswith("/api/")

        for endpoint, extra in rest_param_map.items():
            if endpoint in parsed_path or endpoint in url:
                if endpoint in rest_get_ok:
                    params['get'].update(extra)
                params['post'].update(extra)
                params['json'].update(extra)

        if not params['get'] and not params['post'] and not _is_rest:
            params['get'].update(["q", "id", "search", "email", "name",
                                   "redirect", "url", "next", "file", "path"])

        all_params = params['get'] | params['post'] | params['json']
        if self.verbose and all_params:
            print(f"[*] {len(all_params)} params: {', '.join(list(all_params)[:10])}")

        # Import modules lazily to avoid circular imports at module load time
        from modules import (
            sqli, xss, ssti, cmdi, lfi, ssrf, xxe, idor,
            jwt_tests, cors, graphql, websocket_fuzz, smuggling,
            proto_pollution, business_logic, sensitive_endpoints,
        )

        # Per-URL tests (not per-param)
        await jwt_tests.run(self, url)
        await sensitive_endpoints.run(self)
        await cors.run(self, url)
        await smuggling.run(self, url)
        if not self.config.get('skip_xxe'):
            await xxe.run(self, url)

        if not self.config.get('skip_graphql') and not self._graphql_done:
            if await graphql.run(self, url):
                self._graphql_done = True

        if not self.config.get('skip_websocket') and not self._ws_done:
            if await websocket_fuzz.run(self, url):
                self._ws_done = True

        # Per-param tests
        if not _is_auth_endpoint:
            root_res = await self.make_request("GET", url)
            root_len = len(root_res.text) if root_res else 0
            root_status = root_res.status_code if root_res else 0

            for param in params['get']:
                probe = await self.make_request("GET", url, params={param: "probe_val"})
                if (probe and root_res and
                        probe.status_code == root_status and
                        abs(len(probe.text) - root_len) <= 10):
                    self._record_second_order(url, param)
                    continue

                await sqli.run(self, url, param, "GET")
                await xss.run(self, url, param, "GET")
                await ssti.run(self, url, param, "GET")
                if not self.config.get('skip_cmdi'):
                    await cmdi.run(self, url, param, "GET")
                await lfi.run(self, url, param, "GET")
                if not self.config.get('skip_ssrf'):
                    await ssrf.run(self, url, param, "GET")
                if not self.config.get('skip_idor'):
                    await idor.run(self, url, param, "GET")
                await proto_pollution.run(self, url, param, "GET")
                self._record_second_order(url, param)

            for param in params['post']:
                await sqli.run(self, url, param, "POST")
                await xss.run(self, url, param, "POST")
                await ssti.run(self, url, param, "POST")
                if not self.config.get('skip_cmdi'):
                    await cmdi.run(self, url, param, "POST")
                await lfi.run(self, url, param, "POST")
                if not self.config.get('skip_ssrf'):
                    await ssrf.run(self, url, param, "POST")
                if not self.config.get('skip_idor'):
                    await idor.run(self, url, param, "POST")
                await proto_pollution.run(self, url, param, "POST")

        # Business logic (once per scan)
        if not self.config.get('skip_business_logic') and not self._bizlogic_done:
            self._bizlogic_done = True
            await business_logic.run(self)

        # External plugins
        for plugin in self._plugins:
            for param in list(all_params)[:5]:
                try:
                    await plugin.run(self, url, param, "GET")
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Plugin error: {e}")

        # Second-order execution check
        result = self.second_order.check_execution(page_text, url)
        if result:
            sev, cvss = calculate_severity("Second-Order XSS")
            self.log_vuln(Vulnerability(
                type="Second-Order XSS",
                url=url,
                parameter=result['injection_point']['param'],
                payload=result['injection_point']['payload'],
                evidence=f"Marker {result['marker']} executed after {result['time_delta']:.2f}s",
                confidence="High", severity=sev, cvss_score=cvss, method="GET",
                detection_method="Second-order marker execution",
                remediation="Sanitize stored data on output",
                references=["CWE-79", "OWASP-A03:2021"],
            ))

    def _record_second_order(self, url: str, param: str):
        PRIORITY = {
            "id", "email", "user", "username", "name", "token",
            "search", "q", "query", "message", "comment",
            "redirect", "url", "next", "path", "file", "input",
        }
        if param.lower() in PRIORITY and len(self._second_order_param_count[url]) < 3:
            self._second_order_param_count[url].add(param)
            sqli_marker = self.second_order.generate_marker("SQL")
            self.second_order.record_injection(
                url, param, f"' OR '1'='1' -- {sqli_marker}", sqli_marker, "SQLi"
            )
            xss_marker = self.second_order.generate_marker()
            self.second_order.record_injection(
                url, param, f"<script>alert('{xss_marker}')</script>", xss_marker
            )

    # ── Main run ─────────────────────────────────────────────────────────────

    async def run(self):
        from reporting.json_report import export_json
        from reporting.html_report import export_html, export_md
        from reporting.sarif_report import export_sarif

        print(f"[*] Target: {self.base_url}")
        print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.load_checkpoint()

        if self.config.get('enable_oob', True):
            self.oob_server.start_http()
        if self.use_browser:
            await self.init_browser()

        if self.auth_config and self.auth_config.username:
            print("[*] Authenticating...")
            if not self.auth_config.auth_type or self.auth_config.auth_type == "auto":
                detected = await self.auth_handler.detect_auth_type(
                    self.auth_config.login_url or self.base_url
                )
                self.auth_config.auth_type = detected
                print(f"[*] Detected auth type: {detected}")

            ok = await self.auth_handler.attempt_login(self.auth_config)
            for alt_pw in getattr(self, '_alt_passwords', []):
                if ok:
                    break
                self.auth_config.password = alt_pw
                ok = await self.auth_handler.attempt_login(self.auth_config)

            if ok:
                print(f"[+] Authenticated ({self.auth_handler.auth_type})")
            else:
                print("[-] Auth failed — scanning UNAUTHENTICATED (results may be incomplete)")
                self._auth_failed = True

        max_depth = self.config.get('max_depth', 2)
        if TQDM_AVAILABLE:
            with tqdm(desc="Scanning", unit="req", dynamic_ncols=True,
                      bar_format="{l_bar}{bar}| {n_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:
                self._pbar = pbar
                await self.crawl(self.base_url, max_depth)
                self._pbar = None
        else:
            await self.crawl(self.base_url, max_depth)

        await self.close()
        self._print_report()

        ts = int(time.time())
        out = self.config.get('output')
        export_json(self, f"{out}_{ts}.json" if out else None)
        export_html(self, f"{out}_{ts}.html" if out else None)
        export_md(self, f"{out}_{ts}.md" if out else None)
        export_sarif(self, f"{out}_{ts}.sarif" if out else None)

    def _print_report(self):
        scan_time = time.time() - self.scan_start
        print("\n" + "=" * 70)
        print("SCAN REPORT")
        print("=" * 70)
        print(f"Target:        {self.base_url}")
        print(f"Scan Time:     {scan_time:.2f}s")
        print(f"Requests:      {self.request_count}")
        print(f"URLs Scanned:  {len(self.seen_urls)}")
        if self.waf_detected:
            print(f"WAF:           {self.waf_type}")
        if self._auth_failed:
            print("⚠ WARNING: Auth failed — results may be incomplete")
        print(f"\nVulnerabilities: {len(self.results)}")
        print("=" * 70)
        by_sev = defaultdict(list)
        for v in self.results:
            by_sev[v.severity].append(v)
        for sev in ["Critical", "High", "Medium", "Low"]:
            vs = by_sev[sev]
            if not vs:
                continue
            print(f"\n{sev} ({len(vs)}):")
            print("-" * 70)
            for v in vs:
                print(f"  [{v.confidence}] {v.type} ({v.confidence_pct}%)")
                print(f"      URL:      {v.url}")
                print(f"      Param:    {v.parameter}")
                print(f"      Payload:  {v.payload[:120]}")
                print(f"      Evidence: {v.evidence[:120]}")
                print(f"      CVSS:     {v.cvss_score}")
                print()
