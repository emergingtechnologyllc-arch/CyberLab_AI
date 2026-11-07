import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cyberlab import ui, projects
from cyberlab.core import init_db


class WorkspaceTests(unittest.TestCase):
    def model(self, payload):
        with patch('urllib.request.OpenerDirector.open') as request:
            response=request.return_value.__enter__.return_value
            response.read.return_value=payload
            with patch.dict('os.environ',{'CYBERLAB_MODEL':'test-model:latest'}):
                result=ui.model_connection()
            self.assertEqual(request.call_args.args[0],'http://127.0.0.1:11434/api/tags')
            return result

    def test_model_connection_checks_tags_without_inference(self):
        payload=json.dumps({'models':[{'name':'test-model:latest'}]}).encode()
        self.assertEqual(self.model(payload)[0],'Model available')
        self.assertEqual(self.model(b'{"models":[]}')[0],'Model not installed')

    def test_model_connection_handles_invalid_oversized_and_timeout(self):
        for payload in [b'not json',b'{}',b'x'*65537]:
            self.assertEqual(self.model(payload)[0],'Connection unavailable')
        with patch('urllib.request.OpenerDirector.open',side_effect=TimeoutError):
            self.assertEqual(ui.model_connection()[0],'Connection unavailable')

    def test_history_filter_treats_project_names_literally(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); db=str(base/'test.db'); init_db(db)
            (base/'team_one').mkdir(); (base/'teamXone').mkdir()
            with sqlite3.connect(db) as conn:
                for project in ['team_one','teamXone',str(base/'team_one')]:
                    conn.execute("INSERT INTO runs(created,project,status,project_root) VALUES('2026',?,'completed',?)",(project,str(base/('teamXone' if project=='teamXone' else 'team_one'))))
            result=ui.records(db,'team_one',base=base)
            self.assertEqual(len(result),2)
            self.assertNotIn('teamXone',[r['project'] for r in result])

    def test_discovery_excludes_symlinks_and_hidden_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'valid').mkdir(); (root/'.hidden').mkdir()
            (root/'alias').symlink_to(root/'valid',target_is_directory=True)
            self.assertEqual(projects.discover(root),['valid'])


if __name__ == '__main__': unittest.main()
