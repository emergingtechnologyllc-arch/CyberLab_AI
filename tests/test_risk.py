import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cyberlab import risk
from cyberlab.memory import initialize as init_memory

class RiskTests(unittest.TestCase):
    def test_graph_evidence_and_indicators(self):
        records=[{'source':'ai','route':'/api/orders/[id]','event_id':1},
                 {'source':'live','route':'/api/orders/[id]','event_id':2,'classification':'observed_status_mismatch'},
                 {'source':'live','route':'/api/other','event_id':3,'classification':'observed_status_match'}]
        edges=risk.build_graph(records)
        self.assertEqual(len(edges),1)
        self.assertEqual(edges[0]['indicator'],'needs_manual_review')
        self.assertEqual(edges[0]['relationship'],'same_route_not_causality')
    def test_match_does_not_claim_safe(self):
        records=[{'source':'ai','route':'/a','event_id':1}, {'source':'live','route':'/a','event_id':2,'classification':'observed_status_match'}]
        self.assertEqual(risk.build_graph(records)[0]['indicator'],'no_mismatch_in_observed_test')
    def test_ai_triage_schema(self):
        def transport(payload):
            self.assertIn('relationships',payload['messages'][1]['content'])
            return {'message':{'content':json.dumps({'summary':'Review status mismatch','next_step':'Check expected access policy'})}}
        answer=risk.ai_triage([{'route':'/a','indicator':'needs_manual_review','relationship':'same_route_not_causality'}],transport)
        self.assertIn('Review',answer['summary'])
    def test_ai_invalid_schema(self):
        with self.assertRaises(ValueError):
            risk.ai_triage([],lambda _: {'message':{'content':'{}'}})
    def test_db_roundtrip_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            db=str(Path(folder)/'test.db')
            for runs,events in [('ai_behavior_runs','ai_behavior_events'),('live_runs','live_events'),('experiment_runs','experiment_events')]:
                with sqlite3.connect(db) as conn:
                    conn.execute(f'CREATE TABLE {runs} (id INTEGER PRIMARY KEY, project TEXT, status TEXT)')
                    conn.execute(f'CREATE TABLE {events} (id INTEGER PRIMARY KEY, run_id INTEGER, kind TEXT, payload TEXT)')
            init_memory(db)
            rid=risk.analyze(db,'demo',use_ai=True)
            run,edges=risk.detail(db,rid)
            self.assertEqual(edges,[])
            self.assertEqual(run['ai_status'],'no_relationships')
            self.assertIn('0 confirmed vulnerabilities',run['summary'])
            self.assertEqual(len(risk.recent(db)),1)

if __name__=='__main__':unittest.main()
