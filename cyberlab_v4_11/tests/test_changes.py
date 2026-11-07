import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cyberlab import continuous as c, change_investigation as ci, monitor


class ChangeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.project = self.base/'demo'
        self.project.mkdir()
        self.db = str(self.base/'db.sqlite3')

    def route(self, name='orders', project=None):
        p = (project or self.project)/'app/api'/name/'route.ts'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('export async function GET() {}')
        return p

    def change(self):
        self.route()
        c.assess(self.db,self.project,self.base)
        self.route('users')
        assessment = c.assess(self.db,self.project,self.base)
        return ci.ensure(self.db,assessment)

    def valid(self, context):
        return {'hypothesis':'Review the new route authorization boundary', 'reason':'Inventory changed',
                'supporting_evidence_ids':[context['evidence'][0]['id']], 'confidence':'low',
                'recommended_action':'manual_review', 'confirmed_vulnerability':False}

    def test_baseline_is_not_change(self):
        self.route()
        aid = c.assess(self.db,self.project,self.base)
        self.assertIsNone(ci.ensure(self.db,aid))
        self.assertFalse(c.detail(self.db,aid)[1]['changed'])

    def test_deduplicate_unchanged_and_change(self):
        rid = self.change()
        aid = ci.detail(self.db,rid)['assessment_id']
        self.assertEqual(rid,ci.ensure(self.db,aid))
        repeated = [c.assess(self.db,self.project,self.base) for _ in range(5)]
        self.assertEqual(len(set(repeated)),1)
        self.assertEqual(len(ci.recent(self.db)),1)
        self.assertIsNone(ci.ensure(self.db,repeated[0]))

    def test_valid_model_and_restart(self):
        rid = self.change()
        self.assertEqual(ci.analyze(self.db,rid,self.valid),'recommended_review')
        ci.recover(self.db)
        record = ci.detail(self.db,rid)
        self.assertEqual(record['recommendation']['recommended_action'],'manual_review')
        self.assertFalse(record['recommendation']['confirmed_vulnerability'])
        with patch.object(ci,'ollama',side_effect=AssertionError('duplicate analysis')):
            self.assertEqual(ci.analyze(self.db,rid),'recommended_review')

    def test_invalid_outputs(self):
        rid = self.change()
        for field,value in [('supporting_evidence_ids',['assessment:999999']),
                            ('recommended_action','execute_shell'),('confirmed_vulnerability',True),
                            ('confidence','certain'),('hypothesis','')]:
            with self.subTest(field=field):
                def bad(ctx):
                    p = self.valid(ctx); p[field] = value; return p
                self.assertEqual(ci.analyze(self.db,rid,bad),'model_invalid')
                self.assertEqual(ci.detail(self.db,rid)['recommendation'],{})
        self.assertEqual(ci.analyze(self.db,rid,lambda _: []),'model_invalid')

    def test_timeout_absent_and_json_error(self):
        rid = self.change()
        for exc,status in [(TimeoutError(),'model_unavailable'),(ConnectionRefusedError(),'model_unavailable'),
                           (json.JSONDecodeError('invalid','x',0),'model_invalid'),(RuntimeError(),'analysis_failed')]:
            with self.subTest(status=status):
                def fail(_): raise exc
                self.assertEqual(ci.analyze(self.db,rid,fail),status)

    def test_project_root_isolation_same_basename(self):
        self.change()
        other = self.base/'nested/demo'; other.mkdir(parents=True)
        self.route('alien',other)
        aid = c.assess(self.db,other,self.base)
        self.assertEqual(c.detail(self.db,aid)[0]['status'],'baseline')
        self.route('new',other)
        rid = ci.ensure(self.db,c.assess(self.db,other,self.base))
        context = ci.detail(self.db,rid)['context']
        self.assertNotIn('/api/users',json.dumps(context))
        for evidence in context['evidence']:
            linked = c.detail(self.db,int(evidence['id'].split(':')[1]))[0]
            self.assertEqual(linked['project_root'],str(other.resolve()))

    def test_metadata_changes_not_source_changes(self):
        p = self.route(); c.assess(self.db,self.project,self.base)
        p.write_text('source changed but not inspected')
        self.assertEqual(c.detail(self.db,c.assess(self.db,self.project,self.base))[0]['status'],'unchanged')
        p.rename(p.with_suffix('.js'))
        aid = c.assess(self.db,self.project,self.base)
        self.assertEqual(c.detail(self.db,aid)[1]['modified_routes'],['/api/orders'])

    def test_removed_event_and_original_snapshots(self):
        p = self.route(); baseline = c.assess(self.db,self.project,self.base); p.unlink()
        rid = ci.ensure(self.db,c.assess(self.db,self.project,self.base))
        context = ci.detail(self.db,rid)['context']
        self.assertEqual(context['diff']['removed_routes'],['/api/orders'])
        self.assertIn(f'assessment:{baseline}',[x['id'] for x in context['evidence']])

    def test_dynamic_patterns(self):
        match = ci.match_route('/api/orders/1002',['/api/orders/[id]'])
        self.assertEqual(match['pattern'],'/api/orders/[id]')
        self.assertIsNone(ci.match_route('/api/orders/1',['/api/orders/[id]','/api/orders/[other]']))
        self.assertIsNone(ci.match_route('/api/orders/1/2',['/api/orders/[id]']))
        self.assertIsNone(ci.match_route('/api/orders/1',['/api/orders/[...id]']))
        self.assertIsNone(ci.match_route('/api/users/1',['/api/orders/[id]']))

    def test_migration_preserves_legacy(self):
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE continuous_runs(id INTEGER PRIMARY KEY,created TEXT,project TEXT,fingerprint TEXT,status TEXT,summary TEXT,snapshot TEXT)')
            db.execute("INSERT INTO continuous_runs VALUES(1,'old','demo','hash','baseline','legacy',?)",(json.dumps({'routes':['/api/old'],'schema':1}),))
        ci.initialize(self.db); ci.initialize(self.db)
        self.assertEqual(c.detail(self.db,1)[0]['summary'],'legacy')
        self.route()
        aid = c.assess(self.db,self.project,self.base)
        self.assertEqual(c.detail(self.db,aid)[0]['status'],'baseline')

    def test_concurrent_analysis_claim(self):
        import threading
        rid = self.change()
        entered, release = threading.Event(), threading.Event()
        def slow(ctx):
            entered.set(); release.wait(3); return self.valid(ctx)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(ci.analyze,self.db,rid,slow)
            self.assertTrue(entered.wait(2))
            self.assertEqual(ci.analyze(self.db,rid,self.valid),'analyzing')
            release.set()
            self.assertEqual(first.result(),'recommended_review')
        self.assertEqual(ci.detail(self.db,rid)['attempts'],1)

    def test_monitor_default_ai_off_pause_resume(self):
        self.route()
        monitor.configure(self.db,self.project,self.base,enabled=True,interval=30)
        worker = monitor.Monitor(self.db,self.base)
        with patch.object(ci,'ollama',side_effect=AssertionError('AI must be off')):
            worker.tick()
            self.route('new')
            monitor.configure(self.db,self.project,self.base,enabled=False,interval=30)
            worker.tick()
            self.assertEqual(len(ci.recent(self.db)),0)
            monitor.configure(self.db,self.project,self.base,enabled=True,interval=30)
            worker.tick()
            self.assertEqual(len(ci.recent(self.db)),1)
            self.assertEqual(ci.recent(self.db)[0]['status'],'pending_analysis')
            worker.tick()
            self.assertEqual(len(ci.recent(self.db)),1)
        self.assertTrue(monitor.settings(self.db)[0]['enabled'])
        worker.start(); worker.stop()
        self.assertFalse(worker.thread.is_alive())

    def test_monitor_opt_in_ai(self):
        self.route()
        monitor.configure(self.db,self.project,self.base,enabled=True,interval=30,use_ai=True)
        worker = monitor.Monitor(self.db,self.base); worker.tick()
        self.route('new')
        monitor.configure(self.db,self.project,self.base,enabled=True,interval=30,use_ai=True)
        with patch.object(ci,'ollama',self.valid): worker.tick()
        self.assertEqual(ci.recent(self.db)[0]['status'],'recommended_review')

    def test_interrupted_analysis_recovered(self):
        rid = self.change()
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE change_investigations SET status='analyzing' WHERE id=?",(rid,))
        ci.recover(self.db)
        self.assertEqual(ci.detail(self.db,rid)['status'],'analysis_failed')
        self.assertEqual(ci.analyze(self.db,rid,self.valid),'recommended_review')

    def test_concurrent_assessment_no_duplicate_changes(self):
        self.route(); c.assess(self.db,self.project,self.base); self.route('new')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(lambda _: c.assess(self.db,self.project,self.base),range(8)))
        changed = {aid for aid in ids if c.detail(self.db,aid)[0]['status']=='changed'}
        self.assertEqual(len(changed),1)

    def test_pages_index_route(self):
        from cyberlab.behavior import route_for
        self.assertEqual(route_for(Path('pages/api/index.ts')),'/api/')
        self.assertEqual(route_for(Path('pages/api/orders/index.ts')),'/api/orders')

    def test_monitor_rejects_scope_and_interval(self):
        for interval in [0,29,86401]:
            with self.assertRaises(ValueError): monitor.configure(self.db,self.project,self.base,interval=interval)
        with self.assertRaises(ValueError): monitor.configure(self.db,self.base,self.base)


if __name__ == '__main__': unittest.main()
