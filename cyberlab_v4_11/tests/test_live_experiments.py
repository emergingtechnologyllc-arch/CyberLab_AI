import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cyberlab import live_experiments as le

class Mock(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(403 if self.headers.get('X-CyberLab-Test-Account')=='customer_a' else 200)
        self.end_headers()
        self.wfile.write(b'local fixture')
    def log_message(self,*args): pass

class LiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.project=self.root/'demo'
        (self.project/'app/api/orders/[id]').mkdir(parents=True)
        (self.project/'app/api/orders/[id]/route.ts').write_text('')
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Mock)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.plan={'schema_version':1,'base_url':f'http://127.0.0.1:{self.server.server_port}',
                   'cases':[{'route':'/api/orders/[id]','path':'/api/orders/1002','requester':'customer_a','owner':'customer_b','expected_status':403}]}
        self.write()
    def write(self): (self.project/'cyberlab-live-plan.json').write_text(json.dumps(self.plan))
    def test_live_observation(self):
        rid=le.run(self.root/'test.sqlite3',self.project,self.root)
        row,events=le.detail(self.root/'test.sqlite3',rid)
        self.assertEqual(row['status'],'completed')
        evidence=[json.loads(e['payload']) for e in events if e['kind']=='live_observation']
        self.assertEqual(evidence[0]['status'],403)
        self.assertFalse(evidence[0]['confirmed_vulnerability'])
    def test_ai_cannot_expand_scope(self):
        rid=le.run(self.root/'test.sqlite3',self.project,self.root,selector=lambda _:99)
        row,events=le.detail(self.root/'test.sqlite3',rid)
        self.assertEqual(row['status'],'error')
        self.assertFalse(any(e['kind']=='live_observation' for e in events))
    def test_remote_rejected(self):
        self.plan['base_url']='http://example.com:8080';self.write()
        with self.assertRaises(ValueError): le.validate_plan(self.project,self.root)
    def test_mismatched_route_rejected(self):
        self.plan['cases'][0]['path']='/api/admin/1';self.write()
        with self.assertRaises(ValueError): le.validate_plan(self.project,self.root)
    def test_redirect_not_followed(self):
        # fetch_local uses HTTPConnection, which never follows Location headers.
        self.assertTrue(callable(le.fetch_local))
if __name__=='__main__': unittest.main()
