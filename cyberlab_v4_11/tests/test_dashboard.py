"""Real HTTP subprocess tests using an isolated database and project root."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from cyberlab import change_investigation as ci, continuous as c


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.projects = cls.root/'projects'; cls.projects.mkdir()
        cls.project = cls.projects/'demo'; cls.project.mkdir()
        cls.data = cls.root/'data'; cls.data.mkdir()
        cls.db = str(cls.data/'investigations.sqlite3')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); cls.port = sock.getsockname()[1]
        cls.url = f'http://127.0.0.1:{cls.port}'
        cls.env = dict(os.environ, CYBERLAB_DATA_DIR=str(cls.data),
                       CYBERLAB_PROJECTS_DIR=str(cls.projects), CYBERLAB_V4_PORT=str(cls.port))
        cls.log = open(cls.root/'server.log','w+')
        cls.start()

    @classmethod
    def start(cls):
        cls.proc = subprocess.Popen(['bash','./start-cyberlab-v4.sh'],env=cls.env,stdout=cls.log,stderr=cls.log)
        for _ in range(100):
            if cls.proc.poll() is not None:
                cls.log.seek(0); raise AssertionError(cls.log.read())
            try:
                with urllib.request.urlopen(cls.url,timeout=1) as r:
                    cls.html = r.read().decode()
                cls.token = re.search(r'name="csrf" value="([^"]+)"',cls.html)[1]
                return
            except OSError: time.sleep(.05)
        raise AssertionError('Dashboard did not become ready')

    @classmethod
    def stop(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=25)

    @classmethod
    def tearDownClass(cls):
        cls.stop(); cls.log.close(); cls.tmp.cleanup()

    def request(self,path='/',values=None,headers=None):
        body = urllib.parse.urlencode(values).encode() if values is not None else None
        req = urllib.request.Request(self.url+path,data=body,headers=headers or {})
        try:
            with urllib.request.urlopen(req,timeout=5) as r: return r.status,r.read().decode()
        except urllib.error.HTTPError as exc: return exc.code,exc.read().decode()

    def form(self,**kwargs):
        return dict(csrf=self.token,authorized='yes',project='demo',**kwargs)

    def test_dashboard_and_csrf_authorization(self):
        status,body = self.request()
        self.assertEqual(status,200)
        self.assertIn('Change investigations (v4.11)',body)
        for values in [{'project':'demo','authorized':'yes'},{'project':'demo','csrf':self.token}]:
            self.assertEqual(self.request('/continuous/assess',values)[0],400)
        self.assertEqual(self.request('/run',self.form(target='http://example.com:80'))[0],400)
        self.assertEqual(self.request(headers={'Host':'attacker.example'})[0],400)

    def test_end_to_end_change_export_and_restart(self):
        self.assertEqual(self.request('/continuous/assess',self.form())[0],200)
        route = self.project/'app/api/<script>/route.ts'
        route.parent.mkdir(parents=True,exist_ok=True); route.write_text('synthetic')
        self.assertEqual(self.request('/continuous/assess',self.form())[0],200)
        rid = ci.recent(self.db)[0]['id']
        def fake(ctx):
            return dict(hypothesis='Review <script> boundary',reason='Route added',confidence='low',
                        supporting_evidence_ids=[ctx['evidence'][0]['id']],
                        recommended_action='manual_review',confirmed_vulnerability=False)
        self.assertEqual(ci.analyze(self.db,rid,fake),'recommended_review')
        status,body = self.request(f'/changes/{rid}')
        self.assertEqual(status,200)
        self.assertNotIn('<script>',body); self.assertIn('&lt;script&gt;',body)
        status,body = self.request(f'/changes-export/{rid}')
        self.assertEqual(status,200)
        self.assertFalse(json.loads(body)['recommendation']['confirmed_vulnerability'])
        self.assertEqual(self.request('/monitor/configure',self.form(interval='30',enabled='yes'))[0],200)
        self.assertEqual(self.request('/monitor/configure',self.form(interval='30'))[0],200)
        for action in ['/memory/build','/risk/analyze']:
            self.assertEqual(self.request(action,self.form())[0],200)
        for path in ['/memory/1','/risk/1','/continuous/1']:
            self.assertEqual(self.request(path)[0],200)
        self.stop(); self.start()
        self.assertEqual(self.request(f'/changes/{rid}')[0],200)
        self.assertEqual(ci.detail(self.db,rid)['status'],'recommended_review')
        self.assertIn('paused',self.request()[1])
        self.assertEqual(self.request('/continuous/assess',self.form())[0],200)

    def test_provenance_links_resolve(self):
        from cyberlab import ai_behavior, live_experiments as live
        route = self.project/'app/api/proof/[id]/route.ts'
        route.parent.mkdir(parents=True,exist_ok=True); route.touch()
        c.assess(self.db,self.project,self.projects)
        def planner(routes,reviewed):
            return dict(action='finish' if reviewed else 'inspect_route',route='/api/proof/[id]',hypothesis='secret prose excluded',reason='review')
        ai_run = ai_behavior.run(self.db,self.project,self.projects,planner=planner)
        plan = dict(schema_version=1,base_url='http://127.0.0.1:3999',cases=[
            dict(route='/api/proof/[id]',path='/api/proof/1002',requester='customer_a',owner='customer_b',expected_status=403)])
        (self.project/'cyberlab-live-plan.json').write_text(json.dumps(plan))
        local_run = live.run(self.db,self.project,self.projects,fetcher=lambda *args: dict(status=200,body='PRIVATE_BODY'))
        route.unlink()
        rid = ci.ensure(self.db,c.assess(self.db,self.project,self.projects))
        status,body = self.request(f'/changes/{rid}')
        self.assertEqual(status,200)
        for target in [f'/ai-behavior/{ai_run}',f'/live/{local_run}']:
            self.assertIn(f'href="{target}"',body)
            self.assertEqual(self.request(target)[0],200)
        self.assertIn('verified local observation',body)
        status,export = self.request(f'/changes-export/{rid}')
        self.assertEqual(status,200)
        self.assertNotIn('PRIVATE_BODY',export)
        self.assertNotIn('secret prose excluded',export)

    def test_unknown_recommendation_and_nested_project_rejected(self):
        self.assertEqual(self.request('/changes/analyze',self.form(investigation='999999'))[0],400)
        nested = self.projects/'nested/demo'; nested.mkdir(parents=True,exist_ok=True)
        values = self.form(); values['project']='nested/demo'
        self.assertEqual(self.request('/continuous/assess',values)[0],400)


if __name__ == '__main__': unittest.main()
