#!/usr/bin/env python3
"""Synthetic localhost-only application; no real credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        owner={'/api/orders/1001':'customer_a','/api/orders/1002':'customer_b'}.get(self.path)
        status=404 if owner is None else (200 if self.headers.get('X-CyberLab-Test-Account')==owner else 403)
        self.send_response(status);self.send_header('Content-Type','text/plain');self.end_headers();self.wfile.write(b'synthetic demo')
    def log_message(self,*args):pass
print('Synthetic local API at http://127.0.0.1:3999',flush=True)
ThreadingHTTPServer(('127.0.0.1',3999),Handler).serve_forever()
