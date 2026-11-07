import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cyberlab.core import safe_local_url, inspect_project, init_db, investigate, get_run

class PolicyTests(unittest.TestCase):
    def test_url_policy(self):
        safe_local_url('http://127.0.0.1:3000/')
        for url in ['https://127.0.0.1:3000','http://example.com:3000','http://localhost:3000','http://127.0.0.1:8780','http://127.0.0.1:11434','http://127.0.0.1:3000@evil.test:3000']:
            with self.subTest(url=url), self.assertRaises(ValueError): safe_local_url(url)

    def test_project_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base/'app'
            project.mkdir()
            (project/'package.json').write_text(json.dumps({'dependencies':{'next':'1','react':'1'}}))
            (project/'.env').write_text('SECRET=should-not-leak')
            result = inspect_project(project,base)
            self.assertIn('next',result['dependencies'])
            self.assertNotIn('should-not-leak',str(result))
            with self.assertRaises(ValueError): inspect_project('/',base)

    def test_ai_loop_and_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base/'app'
            project.mkdir()
            (project/'package.json').write_text('{}')
            db = str(base/'db.sqlite')
            init_db(db)
            proposals = iter([{'action':'arbitrary_shell','reason':'no','hypothesis':'no'},
                              {'action':'inspect_local_project','reason':'inventory','hypothesis':'what deps?'},
                              {'action':'finish','reason':'done','hypothesis':'none'}])
            with patch('cyberlab.core.ask_ollama',side_effect=lambda *a: next(proposals)):
                rid = investigate(db,'',str(project),base)
            run, events = get_run(db,rid)
            self.assertEqual(run['status'],'completed')
            self.assertIn('policy_denied',[e['kind'] for e in events])
            self.assertIn('tool_observation',[e['kind'] for e in events])

if __name__ == '__main__': unittest.main()
