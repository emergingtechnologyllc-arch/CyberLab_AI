"""Regression coverage for project isolation, resolved dependencies and retry isolation."""
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cyberlab import identity, dependencies as d, intelligence as intel, knowledge as k, memory, risk, briefing
from test_knowledge import DELTA,CVE


class NextBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.project=self.base/'demo'; self.project.mkdir()
        self.db=str(self.base/'db'); intel.initialize(self.db); identity.initialize(self.db); k.initialize(self.db)
        self.manifest={'dependencies':{'foo':'^1.0.0'}}
        self.lock={'lockfileVersion':3,'packages':{'':copy.deepcopy(self.manifest),
            'node_modules/foo':{'version':'1.2.3','resolved':'https://PRIVATE:token@registry.invalid/foo'},
            'node_modules/bar':{'version':'2.0.0'},
            'node_modules/bar/node_modules/foo':{'version':'1.0.1'}}}
        self.write()

    def write(self):
        (self.project/'package.json').write_text(json.dumps(self.manifest))
        (self.project/'package-lock.json').write_text(json.dumps(self.lock))

    def test_lockfile_keeps_transitive_and_multiple_versions_without_registry_secrets(self):
        result=d.inventory(self.project,self.base)
        self.assertTrue(result['consistency_verified'])
        self.assertEqual({(c['name'],c['version']) for c in result['components']},{('foo','1.2.3'),('foo','1.0.1'),('bar','2.0.0')})
        self.assertNotIn('PRIVATE',json.dumps(result)); self.assertEqual(result['occurrences'],3)

    def test_version_two_and_shrinkwrap_precedence(self):
        self.lock['lockfileVersion']=2; self.write()
        self.assertEqual(len(d.inventory(self.project,self.base)['components']),3)
        self.lock['packages']={'':copy.deepcopy(self.manifest),'node_modules/foo':{'version':'1.9.0'}}
        (self.project/'npm-shrinkwrap.json').write_text(json.dumps(self.lock))
        result=d.inventory(self.project,self.base)
        self.assertEqual(result['lockfile'],'npm-shrinkwrap.json'); self.assertEqual(result['components'][0]['version'],'1.9.0')

    def test_v1_preserves_nested_versions_but_does_not_claim_manifest_consistency(self):
        self.lock={'lockfileVersion':1,'dependencies':{'foo':{'version':'1.2.3','dependencies':{'foo':{'version':'1.0.1'}}}}};self.write()
        result=d.inventory(self.project,self.base)
        self.assertFalse(result['consistency_verified']); self.assertEqual(len(result['components']),2)

    def test_manifest_change_invalidates_snapshot_even_when_lock_unchanged(self):
        old=d.inventory(self.project,self.base); self.manifest['dependencies']['foo']='^2.0.0'; self.write()
        new=d.inventory(self.project,self.base)
        self.assertEqual(old['lock_hash'],new['lock_hash']); self.assertNotEqual(d.fingerprint(old),d.fingerprint(new))
        self.assertFalse(new['consistency_verified'])

    def test_symlink_and_oversize_are_rejected(self):
        lock=self.project/'package-lock.json'; lock.unlink(); lock.symlink_to(self.base/'missing')
        with self.assertRaises(ValueError): d.inventory(self.project,self.base)
        lock.unlink();lock.write_text('x'*100)
        with patch.object(d,'MAX_BYTES',50),self.assertRaises(ValueError): d.inventory(self.project,self.base)

    def test_unresolved_workspace_is_explicit(self):
        self.lock['packages']['node_modules/foo']={'link':True,'resolved':'packages/foo'};self.write()
        result=d.inventory(self.project,self.base)
        self.assertFalse(result['consistency_verified']);self.assertIn('workspace/link entry',result['coverage_notes'])

    def test_no_lock_uses_manifest_and_never_claims_installation(self):
        (self.project/'package-lock.json').unlink()
        result=d.inventory(self.project,self.base)
        self.assertFalse(result['resolved_from_lock']);self.assertEqual(result['components'][0]['provenance'],'manifest_range')

    def test_array_transport_preserves_multiple_versions_and_stores_query_coverage(self):
        captured=[]
        def query(items):
            captured.extend(items);return [{'vulns':[{'id':'GHSA-test-0001'}]} for _ in items]
        cid=intel.check_project(self.db,self.project,self.base,component_query=query,details_fetch=lambda ids:{})
        check,matches=intel.check_detail(self.db,cid)
        self.assertEqual(check['status'],'completed');self.assertEqual(len(captured),3);self.assertEqual(len(matches),3)
        self.assertTrue(all(m['assessment']=='potential_lockfile_version_match' for m in matches))
        self.assertEqual(json.loads(check['coverage'])['queried_components'],3)
        with sqlite3.connect(self.db) as db: self.assertEqual(db.execute('SELECT sum(queried) FROM intelligence_components').fetchone()[0],3)

    def test_failed_query_never_reports_complete_coverage(self):
        cid=intel.check_project(self.db,self.project,self.base,component_query=lambda _:[],details_fetch=lambda _: {})
        check,_=intel.check_detail(self.db,cid)
        self.assertEqual(check['status'],'error');self.assertEqual(json.loads(check['coverage'])['queried_components'],0)

    def test_query_cap_keeps_full_inventory_and_exposes_unqueried_pairs(self):
        self.manifest={'dependencies':{}}; self.lock={'lockfileVersion':3,'packages':{'':{},**{'node_modules/p'+str(i):{'version':'1.0.0'} for i in range(1002)}}};self.write()
        seen=[]
        def query(items):seen.extend(items);return [{} for _ in items]
        cid=intel.check_project(self.db,self.project,self.base,component_query=query,details_fetch=lambda _: {})
        check,_=intel.check_detail(self.db,cid);coverage=json.loads(check['coverage'])
        self.assertEqual(coverage['inventory_components'],1002);self.assertEqual(coverage['queried_components'],1000)
        with sqlite3.connect(self.db) as db:self.assertEqual(db.execute('SELECT count(*) FROM intelligence_components WHERE queried=0').fetchone()[0],2)

    def test_manifest_credential_url_is_not_returned(self):
        (self.project/'package-lock.json').unlink();self.manifest={'dependencies':{'foo':'git+https://PRIVATE:token@example.invalid/repo'}};self.write();(self.project/'package-lock.json').unlink()
        self.assertNotIn('PRIVATE',json.dumps(d.inventory(self.project,self.base)))

    def test_cve_due_retry_drains_after_not_modified_index(self):
        def fail(url,*args):
            if url==k.SOURCES['cve']['url']:return copy.deepcopy(DELTA),'etag','rev'
            raise TimeoutError()
        self.assertEqual(k.refresh(self.db,'cve',True,fail),'partial')
        with sqlite3.connect(self.db) as db:db.execute('UPDATE knowledge_cve_queue SET next_retry=0')
        def recover(url,*args):return (None,'etag','not_modified') if url==k.SOURCES['cve']['url'] else (copy.deepcopy(CVE),'etag','rev')
        self.assertEqual(k.refresh(self.db,'cve',True,recover),'updated')
        self.assertIsNotNone(k.detail(self.db,'cve','CVE-2026-12345'))

    def test_component_query_sends_version_for_each_pair_and_batches(self):
        requests=[]
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):return json.dumps({'results':[{} for _ in requests[-1]['queries']]}).encode()
        def opener(req,**kw): requests.append(json.loads(req.data));return Response()
        components=[dict(name='foo',version='1.0.'+str(i)) for i in range(76)]
        self.assertEqual(len(intel.osv_component_query(components,opener=opener)),76)
        self.assertEqual([len(r['queries']) for r in requests],[75,1]);self.assertEqual(requests[1]['queries'][0]['version'],'1.0.75')

    def test_same_named_roots_have_different_stable_ids(self):
        other=self.base/'elsewhere'/'demo';other.mkdir(parents=True)
        first=identity.register(self.db,self.project);second=identity.register(self.db,other)
        self.assertNotEqual(first,second); self.assertEqual(first,identity.register(self.db,self.project))

    def test_legacy_name_only_never_gains_project_identity(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO intelligence_checks(project,status) VALUES('demo','completed')")
            db.execute("INSERT INTO intelligence_checks(project,status,project_root) VALUES('demo','completed',?)",(str(self.project),))
        identity.initialize(self.db)
        with sqlite3.connect(self.db) as db: rows=db.execute('SELECT project_id FROM intelligence_checks ORDER BY id').fetchall()
        self.assertEqual(rows[0][0],'');self.assertEqual(rows[1][0],identity.register(self.db,self.project))

    def test_passport_persists_and_validates_fields(self):
        values=dict(owner='<team>',purpose='Local app',environment='production',data_classification='internal',access_policy='Owner only')
        identity.update_passport(self.db,self.project,**values)
        self.assertEqual(identity.passport(self.db,self.project)['owner'],'<team>')
        values['environment']='invalid'
        with self.assertRaises(ValueError):identity.update_passport(self.db,self.project,**values)

    def test_briefing_unknown_and_stale_are_not_zero_risk(self):
        from cyberlab import continuous,change_investigation
        continuous.initialize(self.db);change_investigation.initialize(self.db)
        self.assertIn('have not been checked',briefing.build(self.db,self.project,self.base)['items'][0]['title'])
        intel.check_project(self.db,self.project,self.base,component_query=lambda items:[{} for _ in items],details_fetch=lambda _: {})
        self.assertIn('Current dependency coverage',[i['title'] for i in briefing.build(self.db,self.project,self.base)['items']])
        self.manifest['description']='changed';self.write()
        self.assertIn('Dependency check needs attention',[i['title'] for i in briefing.build(self.db,self.project,self.base)['items']])

    def test_cve_poison_record_isolated_backoff_quarantine_and_manual_retry(self):
        delta=copy.deepcopy(DELTA);delta['new'].append(dict(cveId='CVE-2026-12346',dateUpdated='2026-11-06T00:00:00Z'))
        calls=[]
        def fetch(url,*args):
            if url==k.SOURCES['cve']['url']:return delta,'etag','rev'
            calls.append(url)
            if '12345.json' in url:raise TimeoutError('PRIVATE details')
            good=copy.deepcopy(CVE);good['cveMetadata']['cveId']='CVE-2026-12346';return good,'etag','rev'
        self.assertEqual(k.refresh(self.db,'cve',True,fetch),'partial')
        self.assertIsNotNone(k.detail(self.db,'cve','CVE-2026-12346'));self.assertEqual(len(calls),2)
        self.assertEqual(k.refresh(self.db,'cve',True,fetch),'partial');self.assertEqual(len(calls),2)
        for _ in range(2):
            with sqlite3.connect(self.db) as db:db.execute('UPDATE knowledge_cve_queue SET next_retry=0')
            self.assertEqual(k.refresh(self.db,'cve',True,fetch),'partial')
        state=next(s for s in k.status(self.db) if s['source']=='cve')
        self.assertEqual(state['blocked_records'],1);self.assertNotIn('PRIVATE',json.dumps(state))
        k.retry_failed(self.db)
        with sqlite3.connect(self.db) as db:self.assertEqual(db.execute("SELECT attempts,state FROM knowledge_cve_queue WHERE external_id='CVE-2026-12345'").fetchone(),(0,'pending'))

    def test_cve_new_revision_revives_quarantined_record(self):
        with sqlite3.connect(self.db) as db:db.execute("INSERT INTO knowledge_cve_queue(external_id,delta_updated,state,attempts) VALUES('CVE-2026-12345','2020-01-01T00:00:00+00:00','quarantined',3)")
        def fetch(url,*args):return (copy.deepcopy(DELTA) if url==k.SOURCES['cve']['url'] else copy.deepcopy(CVE)),'etag','rev'
        self.assertEqual(k.refresh(self.db,'cve',True,fetch),'updated')
        with sqlite3.connect(self.db) as db:self.assertEqual(db.execute('SELECT attempts,state FROM knowledge_cve_queue').fetchone(),(0,'done'))

if __name__=='__main__':unittest.main()
