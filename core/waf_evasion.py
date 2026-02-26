"""
core/waf_evasion.py
WAF detection, evasion techniques, and IP obfuscation.
"""
from __future__ import annotations

import random
import re
import urllib.parse
import base64
from typing import Any, Dict, List

import httpx


class AdvancedWAFEvasion:
    """WAF detection + bypass: case, comments, spaces, encoding, null-byte."""

    USER_AGENTS = [
        # Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Chrome macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Chrome Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        # Mobile
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        # Bots (bypass attempt)
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/7.88.1",
    ]

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def rotate_user_agent(self) -> str:
        return random.choice(self.USER_AGENTS)

    def timing_randomization(self) -> float:
        return random.uniform(0.1, 3.0)

    def obfuscate_ip(self, ip: str) -> List[str]:
        parts = ip.split('.')
        if len(parts) != 4:
            return [ip]
        variants = []
        decimal = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
        variants.append(str(decimal))
        variants.append('.'.join(f"0{int(p):o}" for p in parts))
        variants.append('0x' + ''.join(f"{int(p):02x}" for p in parts))
        variants.append(f"{parts[0]}.{int(parts[1]):o}.{parts[2]}.{parts[3]}")
        variants.append(f"http://{decimal}/")
        if ip == "127.0.0.1":
            variants.extend(["::1", "0000::1", "[::1]"])
        return variants

    def case_variation(self, payload: str, mode: str = "random") -> str:
        if mode == "random":
            return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        if mode == "alternate":
            return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        if mode == "keyword":
            keywords = ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "SCRIPT", "ALERT", "ONERROR"]
            result = payload
            for kw in keywords:
                if kw in result.upper():
                    varied = ''.join(random.choice([c.upper(), c.lower()]) for c in kw)
                    result = re.sub(kw, varied, result, flags=re.IGNORECASE)
            return result
        return payload

    def comment_injection(self, payload: str) -> str:
        comment = "/**/"
        result = payload
        for kw in ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR"]:
            if kw in result.upper():
                mid = len(kw) // 2
                injected = kw[:mid] + comment + kw[mid:]
                result = re.sub(kw, injected, result, flags=re.IGNORECASE)
        return result

    def space_alternatives(self, payload: str) -> List[str]:
        return [
            payload.replace(" ", "+"),
            payload.replace(" ", "%20"),
            payload.replace(" ", "%09"),
            payload.replace(" ", "%0a"),
            payload.replace(" ", "/**/"),
            payload.replace(" ", "%0b"),
            payload.replace(" ", "${IFS}"),
        ]

    def encode_payload(self, payload: str, technique: str = "url") -> str:
        enc = {
            "url":        lambda p: urllib.parse.quote(p),
            "double_url": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
            "unicode":    lambda p: ''.join(f"\\u{ord(c):04x}" for c in p),
            "hex":        lambda p: ''.join(f"%{ord(c):02x}" for c in p),
            "base64":     lambda p: base64.b64encode(p.encode()).decode(),
            "mixed":      lambda p: ''.join(
                urllib.parse.quote(c) if i % 2 == 0 else f"%{ord(c):02x}"
                for i, c in enumerate(p)
            ),
        }
        return enc.get(technique, enc["url"])(payload)

    def generate_variants(self, payload: str, max_variants: int = 10) -> List[str]:
        variants: set = {payload}
        variants.add(self.case_variation(payload, "random"))
        variants.add(self.case_variation(payload, "alternate"))
        variants.add(self.case_variation(payload, "keyword"))
        if any(kw in payload.upper() for kw in ["SELECT", "UNION", "WHERE"]):
            variants.add(self.comment_injection(payload))
        for enc in ["url", "double_url", "hex", "mixed"]:
            try:
                variants.add(self.encode_payload(payload, enc))
            except Exception:
                pass
        for alt in self.space_alternatives(payload)[:3]:
            variants.add(alt)
        variants.add(payload + "%00")
        variants.add("%00" + payload)
        return list(variants)[:max_variants]

    def detect_waf(self, response: httpx.Response) -> Dict[str, Any]:
        detected = False
        waf_type = "Unknown"
        indicators = []

        if response.status_code in [406, 419, 503, 999]:
            detected = True
            indicators.append(f"Status: {response.status_code}")

        waf_headers = {
            "cloudflare":   ["cf-ray", "cf-cache-status", "server: cloudflare"],
            "imperva":      ["x-iinfo", "x-cdn: incapsula"],
            "akamai":       ["x-akamai", "akamai-grn"],
            "sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
            "mod_security": ["mod_security"],
            "barracuda":    ["barra_counter_session"],
            "fortiweb":     ["fortiwafsid"],
            "aws_waf":      ["x-amzn-requestid", "x-amz-cf-id"],
        }
        for waf_name, sigs in waf_headers.items():
            for header, value in response.headers.items():
                header_line = f"{header}: {value}".lower()
                for sig in sigs:
                    if sig.lower() in header_line:
                        detected = True
                        waf_type = waf_name.title()
                        indicators.append(f"Header: {sig}")
                        if response.status_code == 403:
                            indicators.append("Status: 403")

        body_lower = response.text.lower()
        for waf_name, sigs in [
            ("cloudflare", ["ray id"]),
            ("imperva",    ["incapsula", "imperva"]),
            ("sucuri",     ["sucuri", "access denied"]),
            ("mod_security", ["mod_security"]),
            ("akamai",     ["akamai", "reference #"]),
        ]:
            for sig in sigs:
                if sig in body_lower:
                    if indicators or response.status_code in [403, 406, 419, 503]:
                        detected = True
                        if waf_type == "Unknown":
                            waf_type = waf_name.title()
                        indicators.append(f"Body: {sig}")

        if detected and len(indicators) < 2:
            detected = False
            indicators = []

        confidence = "High" if len(indicators) > 2 else "Medium" if indicators else "Low"
        return {"detected": detected, "type": waf_type, "indicators": indicators, "confidence": confidence}
