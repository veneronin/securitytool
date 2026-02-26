"""
core/auth_handler.py
Authentication: form, HTTP Basic, Bearer, JSON REST.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Dict, Optional

import httpx
from bs4 import BeautifulSoup

from .models import AuthConfig


class EnhancedAuthHandler:
    """Handles form, Basic, Bearer, and JSON REST authentication."""

    def __init__(self, client: httpx.AsyncClient, verbose: bool = False):
        self.client = client
        self.verbose = verbose
        self.authenticated = False
        self.session_cookies: Dict[str, str] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self.auth_headers: Dict[str, str] = {}
        self.auth_type: str = ""

    async def detect_auth_type(self, url: str) -> str:
        try:
            res = await self.client.get(url)
            if res.status_code == 401 and 'www-authenticate' in res.headers:
                val = res.headers['www-authenticate'].lower()
                if 'basic' in val:
                    return 'basic'
                if 'bearer' in val:
                    return 'bearer'
            soup = BeautifulSoup(res.text, 'html.parser')
            if soup.find_all('input', {'type': 'password'}):
                return 'form'
        except Exception:
            pass
        return 'none'

    async def detect_login_form(self, url: str) -> Optional[Dict]:
        try:
            res = await self.client.get(url)
            soup = BeautifulSoup(res.text, 'html.parser')
            for form in soup.find_all('form'):
                pw = form.find('input', {'type': 'password'})
                if not pw:
                    continue
                action = form.get('action') or url
                method = (form.get('method') or 'POST').upper()
                fields: Dict[str, str] = {}
                username_field = None
                password_field_name = None
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if not name:
                        continue
                    t = inp.get('type', '').lower()
                    if t == 'password':
                        password_field_name = name
                    elif t in ['text', 'email'] or any(
                        kw in name.lower() for kw in ['user', 'email', 'login', 'account']
                    ):
                        username_field = name
                    elif t == 'hidden':
                        val = inp.get('value', '')
                        if any(kw in name.lower() for kw in ['csrf', 'token', '_token']):
                            self.csrf_tokens[name] = val
                        fields[name] = val
                if username_field and password_field_name:
                    return {
                        'action': urllib.parse.urljoin(url, action),
                        'method': method,
                        'username_field': username_field,
                        'password_field': password_field_name,
                        'extra_fields': fields,
                    }
        except Exception:
            pass
        return None

    async def attempt_form_login(self, auth_config: AuthConfig) -> bool:
        if not auth_config.login_url:
            return False
        form = await self.detect_login_form(auth_config.login_url)
        if not form:
            return False
        data = {
            form['username_field']: auth_config.username,
            form['password_field']: auth_config.password,
        }
        data.update(form.get('extra_fields', {}))
        try:
            if form['method'] == 'POST':
                res = await self.client.post(form['action'], data=data, follow_redirects=True)
            else:
                res = await self.client.get(form['action'], params=data, follow_redirects=True)
            if self._check_auth_success(res, auth_config):
                self.session_cookies = dict(self.client.cookies)
                self.authenticated = True
                self.auth_type = "form"
                if self.verbose:
                    print(f"[+] Form auth successful: {auth_config.username}")
                return True
        except Exception:
            pass
        return False

    async def attempt_basic_auth(self, auth_config: AuthConfig) -> bool:
        try:
            creds = f"{auth_config.username}:{auth_config.password}"
            encoded = base64.b64encode(creds.encode()).decode()
            self.auth_headers['Authorization'] = f"Basic {encoded}"
            self.client.headers.update(self.auth_headers)
            res = await self.client.get(auth_config.login_url or str(self.client.base_url))
            if res.status_code != 401:
                self.authenticated = True
                self.auth_type = "basic"
                if self.verbose:
                    print("[+] HTTP Basic auth successful")
                return True
        except Exception:
            pass
        return False

    async def attempt_bearer_auth(self, token: str) -> bool:
        try:
            self.auth_headers['Authorization'] = f"Bearer {token}"
            self.client.headers.update(self.auth_headers)
            self.authenticated = True
            self.auth_type = "bearer"
            if self.verbose:
                print("[+] Bearer token set")
            return True
        except Exception:
            return False

    async def attempt_json_login(self, auth_config: AuthConfig) -> bool:
        login_url = auth_config.login_url
        payloads = [
            {"email": auth_config.username, "password": auth_config.password},
            {"username": auth_config.username, "password": auth_config.password},
            {"user": auth_config.username, "pass": auth_config.password},
            {"login": auth_config.username, "password": auth_config.password},
        ]
        _shown = False
        for payload in payloads:
            try:
                res = await self.client.post(
                    login_url,
                    json=payload,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    follow_redirects=True,
                )
                if res.status_code in (200, 201):
                    try:
                        data = res.json()
                        token = (
                            data.get("authentication", {}).get("token") or
                            data.get("token") or
                            data.get("access_token") or
                            data.get("accessToken")
                        )
                        if token:
                            self.auth_headers["Authorization"] = f"Bearer {token}"
                            self.client.headers.update(self.auth_headers)
                            self.authenticated = True
                            self.auth_type = "bearer_json"
                            if self.verbose:
                                print("[+] JSON REST login successful, Bearer token acquired")
                            return True
                    except Exception:
                        pass
                    if self._check_auth_success(res, auth_config):
                        self.session_cookies = dict(self.client.cookies)
                        self.authenticated = True
                        self.auth_type = "json"
                        if self.verbose:
                            print("[+] JSON login successful")
                        return True
                else:
                    if self.verbose and not _shown:
                        print(f"[-] JSON login HTTP {res.status_code}: {res.text[:120]}")
                        _shown = True
            except Exception as e:
                if self.verbose and not _shown:
                    print(f"[-] JSON login error: {str(e)[:80]}")
                    _shown = True
        return False

    async def attempt_login(self, auth_config: AuthConfig) -> bool:
        if not auth_config.username or not auth_config.password:
            return False
        if auth_config.auth_type == "basic":
            return await self.attempt_basic_auth(auth_config)
        if auth_config.auth_type == "bearer":
            return await self.attempt_bearer_auth(auth_config.password)
        if auth_config.login_url:
            if await self.attempt_json_login(auth_config):
                return True
        return await self.attempt_form_login(auth_config)

    def _check_auth_success(self, response: httpx.Response, auth_config: AuthConfig) -> bool:
        if auth_config.success_indicator:
            return auth_config.success_indicator in response.text
        if auth_config.failure_indicator:
            return auth_config.failure_indicator.lower() not in response.text.lower()
        bad = ['invalid', 'incorrect', 'failed', 'wrong', 'error', 'denied', 'unauthorized', 'forbidden']
        return not any(w in response.text.lower() for w in bad)

    def extract_csrf_token(self, html: str, token_name: str = None) -> Optional[str]:
        soup = BeautifulSoup(html, 'html.parser')
        if token_name:
            inp = soup.find('input', {'name': token_name})
            if inp and inp.get('value'):
                return inp.get('value')
        for pat in [
            {'name': re.compile(r'csrf', re.I)},
            {'name': re.compile(r'_token', re.I)},
        ]:
            inp = soup.find('input', pat)
            if inp and inp.get('value'):
                return inp.get('value')
        for pat in [
            {'name': re.compile(r'csrf', re.I)},
            {'property': re.compile(r'csrf', re.I)},
        ]:
            meta = soup.find('meta', pat)
            if meta and meta.get('content'):
                return meta.get('content')
        return None

    async def refresh_csrf(self, url: str):
        try:
            res = await self.client.get(url)
            token = self.extract_csrf_token(res.text)
            if token:
                self.csrf_tokens[url] = token
        except Exception:
            pass

