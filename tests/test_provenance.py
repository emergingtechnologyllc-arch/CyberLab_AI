import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cyberlab import ai_behavior, live_experiments as live, continuous, change_investigation as ci, monitor
from cyberlab.provenance import summaries


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.project = self.base/'demo'; self.project.mkdir()
        self.db = str(self.base/'db.sqlite3')
        ai_behavior.initialize(self.db); live.initialize(self.db)

    def route(self,name='orders/[id]',project=None):
        p = (project or self.project)/'app/api'/name/'route.ts'
        p.parent.mkdir(parents=True,exist_ok=True); p.touch()

    def evidence(self,root=None,legacy=False,raw='/api/orders/1002'):
        root = root or self.project
        with sqlite3.connect(self.db) as db:
            rid = db.execute("INSERT INTO live_runs(created,project,status,summary,project_root) VALUES('2020',?,'completed','',?)",(root.name,'' if legacy else str(root))).lastrowid
            eid = db.execute("INSERT INTO live_events(run_id,kind,payload) VALUES(?,'live_observation',?)",(rid,json.dumps(dict(route='/api/orders/[id]',path=raw,status=200,expected_status=403,secret='NEVER_INCLUDE',body='PRIVATE_BODY')))).lastrowid
        return eid

    def test_root_isolation_legacy_and_sanitization(self):
        good = self.evidence()
        other = self.base/'other/demo'; other.mkdir(parents=True)
        self.evidence(other); self.evidence(legacy=True)
        items = summaries(self.db,self.project,['/api/orders/[id]'])
        self.assertEqual([r['id'] for r in items],[f'live_event:{good}'])
        self.assertEqual(items[0]['pattern'],'/api/orders/[id]')
        self.assertEqual(items[0]['raw_path'],'/api/orders/1002')
        self.assertEqual(items[0]['rule'],'unique_single_segment_parameter')
        self.assertNotIn('PRIVATE_BODY',json.dumps(items)); self.assertNotIn('NEVER_INCLUDE',json.dumps(items))

    def test_ambiguous_evidence_rejected(self):
        self.evidence()
        self.assertEqual(summaries(self.db,self.project,['/api/orders/[id]','/api/orders/[other]']),[])

    def test_real_writers_capture_root_and_link_observation(self):
        self.route()
        def planner(routes,reviewed):
            return dict(action='finish' if reviewed else 'inspect_route',route='/api/orders/[id]',hypothesis='DO_NOT_COPY',reason='metadata')
        aid = ai_behavior.run(self.db,self.project,self.base,planner=planner)
        self.assertEqual(ai_behavior.detail(self.db,aid)[0]['project_root'],str(self.project))
        continuous.assess(self.db,self.project,self.base)
        self.route('new')
        rid = ci.ensure(self.db,continuous.assess(self.db,self.project,self.base))
        # A later approved local observation is displayed without altering the prompt.
        before = ci.detail(self.db,rid)['context']
        self.assertNotIn('DO_NOT_COPY',json.dumps(before))
        self.assertTrue(any(e['id'].startswith('ai_event:') for e in summaries(self.db,self.project,['/api/orders/[id]'])))
        plan = {'schema_version':1,'base_url':'http://127.0.0.1:3999','cases':[
            {'route':'/api/new','path':'/api/new','requester':'customer_a','owner':'customer_b','expected_status':403}]}
        (self.project/'cyberlab-live-plan.json').write_text(json.dumps(plan))
        run = live.run(self.db,self.project,self.base,fetcher=lambda *args: {'status':200})
        self.assertEqual(live.detail(self.db,run)[0]['project_root'],str(self.project))
        record = ci.detail(self.db,rid)
        self.assertEqual(record['context'],before)
        self.assertEqual(record['observation_status'],'verified_local_observation')
        self.assertFalse(record['local_observations'][0]['confirmed_vulnerability'])

    def test_prior_observation_is_allowed_model_evidence(self):
        self.route('initial'); continuous.assess(self.db,self.project,self.base)
        eid = self.evidence(); self.route()
        rid = ci.ensure(self.db,continuous.assess(self.db,self.project,self.base))
        def model(ctx):
            self.assertIn(f'live_event:{eid}', [e['id'] for e in ctx['evidence']])
            return dict(hypothesis='Review access policy',reason='Prior synthetic status mismatch',
                        supporting_evidence_ids=[f'live_event:{eid}'], confidence='low',
                        recommended_action='manual_review',confirmed_vulnerability=False)
        self.assertEqual(ci.analyze(self.db,rid,model),'recommended_review')

    def test_old_schema_migration_preserves_unknown_roots(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO ai_behavior_runs(created,project,status,summary) VALUES('old','demo','completed','keep')")
        ai_behavior.initialize(self.db)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT summary,project_root FROM ai_behavior_runs').fetchone(),('keep',''))

    def test_pausing_during_assessment_prevents_scheduled_ai(self):
        self.route('initial'); continuous.assess(self.db,self.project,self.base); self.route()
        monitor.configure(self.db,self.project,self.base,enabled=True,use_ai=True,interval=30)
        worker = monitor.Monitor(self.db,self.base)
        original = continuous.assess
        def pause(*args):
            result = original(*args)
            monitor.configure(self.db,self.project,self.base,enabled=False,use_ai=False,interval=60)
            return result
        with patch.object(continuous,'assess',side_effect=pause), patch.object(ci,'ollama') as model:
            worker.tick(); model.assert_not_called()
        settings = monitor.settings(self.db)[0]
        self.assertFalse(settings['enabled']); self.assertEqual(settings['next_run'],0)
        self.assertEqual(ci.recent(self.db)[0]['status'],'pending_analysis')

    def test_revoked_ai_generation_rejected(self):
        self.route('initial'); continuous.assess(self.db,self.project,self.base); self.route()
        rid = ci.ensure(self.db,continuous.assess(self.db,self.project,self.base))
        monitor.configure(self.db,self.project,self.base,enabled=True,use_ai=True)
        generation = monitor.settings(self.db)[0]['generation']
        monitor.configure(self.db,self.project,self.base,enabled=True,use_ai=False)
        with patch.object(ci,'ollama') as model:
            self.assertEqual(ci.analyze(self.db,rid,schedule=(str(self.project),generation)),'pending_analysis')
            model.assert_not_called()


if __name__ == '__main__': unittest.main()
