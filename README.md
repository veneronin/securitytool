# AScan

Asynchronous modular web application security scanner for authorized penetration testing and CTF competitions.

---

## Requirements

- Python 3.10+
- `pip install aiohttp beautifulsoup4 tqdm websockets`

---

## Installation

```bash
git clone <repo>
cd ascan
pip install aiohttp beautifulsoup4 tqdm websockets
```

---

## Usage

```bash
# Basic scan
python3 main.py http://target.local

# Juice Shop
python3 main.py http://localhost:3000 --juiceshop --verbose

# Fast mode (~5 min)
python3 main.py http://localhost:3000 --mode fast --verbose

# Deep mode (~60 min, blind/OOB enabled)
python3 main.py http://target.local --mode deep --oob --verbose

# API target
python3 main.py http://api.target.local --profile api --mode standard
```

---

## Scan Modes

| Mode | Time | Coverage |
|---|---|---|
| `fast` | ~5 min | SQLi, XSS, JWT, sensitive endpoints |
| `standard` | ~20 min | All modules, OOB off |
| `deep` | ~60 min | All modules + blind/OOB, depth 3 |

---

## Vulnerability Coverage

| Module | What It Tests |
|---|---|
| `sqli` | Error, boolean, time-based, UNION, NoSQL, second-order |
| `xss` | Reflected, stored, DOM, CSP bypass |
| `ssti` | Jinja2, Twig, Freemarker, Velocity, Mako |
| `cmdi` | Linux/Windows command injection, blind via UUID marker |
| `lfi` | Path traversal, null byte, encoding variants |
| `ssrf` | Localhost, cloud metadata endpoints |
| `xxe` | In-band, OOB, error-based |
| `idor` | Sequential ID and UUID enumeration |
| `jwt_tests` | None-alg, alg confusion, secret brute-force, kid injection |
| `cors` | Wildcard, null origin, subdomain reflection |
| `graphql` | Introspection, batch, injection |
| `websocket_fuzz` | Injection via WebSocket messages |
| `smuggling` | CL.TE, TE.CL variants |
| `proto_pollution` | JSON body, query string |
| `business_logic` | Pricing flaws, coupon reuse, auth bypasses |
| `sensitive_endpoints` | 80+ known paths, SPA-aware |

---

## Output

All reports are written to the current directory after the scan completes:

| File | Format |
|---|---|
| `scan_report.json` | Machine-readable JSON |
| `scan_report.html` | Interactive dark-theme HTML with timeline chart |
| `scan_report.md` | Markdown (GitHub / Notion) |
| `scan_report.sarif` | SARIF 2.1 (GitHub Code Scanning, VS Code) |

---

## Flags

| Flag | Description |
|---|---|
| `--mode fast\|standard\|deep` | Scan depth preset |
| `--juiceshop` | Juice Shop preset (seeded endpoints + credentials) |
| `--profile webapp\|api\|spa` | Target profile |
| `--depth N` | Crawler depth (default: 2) |
| `--concurrency N` | Parallel requests |
| `--oob` | Enable OOB callback server for blind detection |
| `--verbose` | Detailed output |
| `--output-dir PATH` | Report output directory |

---

## Project Structure

```
ascan/
├── main.py
├── core/
│   ├── auth_handler.py
│   ├── models.py
│   ├── oob_server.py
│   ├── scanner.py
│   └── waf_evasion.py
├── modules/
│   ├── sqli.py / xss.py / ssti.py / cmdi.py / lfi.py
│   ├── ssrf.py / xxe.py / idor.py / cors.py / jwt_tests.py
│   ├── graphql.py / smuggling.py / websocket_fuzz.py
│   ├── proto_pollution.py / business_logic.py / sensitive_endpoints.py
├── payloads/
│   ├── sqli_payloads.py / xss_payloads.py
│   ├── shells.py / encoders.py
└── reporting/
    ├── html_report.py / json_report.py / sarif_report.py
```

---

## Legal

For authorized security testing and CTF competitions only.
Do not scan systems you do not own or have explicit written permission to test.
