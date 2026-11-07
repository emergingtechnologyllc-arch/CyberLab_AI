import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cyberlab import memory
from cyberlab.ai_behavior import initialize as ai_init
from cyberlab.live_experiments import initialize as live_init
from cyberlab.experiments import initialize as fixture_init

class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=str(Path(self.tmp.name)/'test.sqlite3')
        for fn in (ai_init,live_init,fixture_init,memory.initialize):fn(self.db)
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO ai_behavior_runs(id,created,project,status,summary) VALUES(1,'now','demo','completed','ok')")
            db.execute("INSERT INTO live_runs(id,created,project,status,summary) VALUES(1,'now','demo','completed','ok')")
            db.execute("INSERT INTO ai_behavior_events(run_id,kind,payload) VALUES(1,'hypothesis',?)",(json.dumps({'route':'/api/orders/[id]','hypothesis':'Check ownership'}),))
            db.execute("INSERT INTO live_events(run_id,kind,payload) VALUES(1,'live_observation',?)",(json.dumps({'route':'/api/orders/[id]','classification':'observed_status_mismatch','status':200,'expected_status':403}),))
    def test_correlates_exact_route(self):
        rid=memory.snapshot(self.db,'demo')
        row,links=memory.detail(self.db,rid)
        self.assertEqual(len(links),1)
        self.assertIn('zero vulnerabilities confirmed',row['summary'])
    def test_project_isolation(self):
        rid=memory.snapshot(self.db,'other')
        self.assertEqual(memory.detail(self.db,rid)[1],[])
    def test_no_raw_hypothesis_in_context(self):
        ctx=memory.ai_context(self.db,'demo')
        self.assertEqual(len(ctx),2)
        self.assertNotIn('Check ownership',str(ctx))
    def test_reject_path_project(self):
        with self.assertRaises(ValueError):memory.snapshot(self.db,'../demo')
    def test_does_not_link_simulated_fixture_to_live(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO experiment_runs(id,created,project,status,summary) VALUES(1,'now','demo','completed','ok')")
            db.execute("INSERT INTO experiment_events(run_id,kind,payload) VALUES(1,'synthetic_verification',?)",(json.dumps({'route':'/api/other','classification':'simulated_authorization_mismatch'}),))
        rid=memory.snapshot(self.db,'demo')
        self.assertEqual(len(memory.detail(self.db,rid)[1]),1)

if __name__=='__main__':unittest.main()
