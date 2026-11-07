import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from cyberlab import knowledge as k
from cyberlab import intelligence, continuous, change_investigation as changes

KEV={'count':1,'dateReleased':'2026-11-07T00:00:00Z','vulnerabilities':[
    dict(cveID='CVE-2026-12345',vulnerabilityName='Product issue',shortDescription='A public bulletin.',
         dateAdded='2026-11-06',vendorProject='Vendor',product='Product',requiredAction='Apply vendor update.') ]}
ATTACK={'type':'bundle','objects':[dict(type='attack-pattern',name='Example technique',modified='2026-11-06T00:00:00Z',
    description='Technique reference, not a detected attack.',external_references=[dict(source_name='mitre-attack',external_id='T1234')])]}
CVE={'cveMetadata':dict(cveId='CVE-2026-12345',state='PUBLISHED',datePublished='2026-11-06T00:00:00Z'),
     'containers':{'cna':{'title':'Example CVE','descriptions':[dict(lang='en',value='Reference description.')],
                           'affected':[dict(vendor='Vendor',product='Product')]}}}
DELTA=dict(fetchTime='2026-11-07T00:00:00Z',new=[dict(cveId='CVE-2026-12345',dateUpdated='2026-11-06T00:00:00Z',githubLink='https://attacker.invalid/ignore-me')],updated=[])


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.db=str(self.base/'db.sqlite3'); k.initialize(self.db)

    def fetch(self,document):
        return lambda *args:(copy.deepcopy(document),'"etag"','revision-1')

    def test_realistic_catalog_persists_and_deduplicates(self):
        for _ in range(2): self.assertEqual(k.refresh(self.db,'kev',True,self.fetch(KEV)),'updated')
        self.assertEqual(len(k.search(self.db)),1)
        row=k.detail(self.db,'kev','CVE-2026-12345')
        self.assertEqual(row['source'],'kev'); self.assertIn('cisa.gov',row['reference'])
        self.assertFalse(k.status(self.db)[2]['stale'])
        with sqlite3.connect(self.db) as db: self.assertEqual(db.execute('SELECT count(*) FROM knowledge_audit').fetchone()[0],2)

    def test_failure_keeps_last_good_cache(self):
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        def fail(*args): raise TimeoutError('do not persist PRIVATE token')
        self.assertEqual(k.refresh(self.db,'kev',True,fail),'error')
        self.assertEqual(len(k.search(self.db)),1)
        states=k.status(self.db); state=next(s for s in states if s['source']=='kev')
        self.assertEqual(state['error_code'],'network_unavailable')
        self.assertNotIn('PRIVATE',json.dumps(states))

    def test_invalid_snapshot_cannot_replace_good_catalog(self):
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        invalid=copy.deepcopy(KEV); invalid['vulnerabilities'].append(invalid['vulnerabilities'][0]); invalid['count']=2
        self.assertEqual(k.refresh(self.db,'kev',True,self.fetch(invalid)),'error')
        self.assertEqual(len(k.search(self.db)),1)

    def test_not_modified_requires_cache_and_keeps_revision(self):
        unchanged=lambda *args:(None,'','not_modified')
        self.assertEqual(k.refresh(self.db,'kev',True,unchanged),'error')
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        self.assertEqual(k.refresh(self.db,'kev',True,unchanged),'unchanged')
        self.assertEqual(len(k.search(self.db)),1)

    def test_generation_change_cancels_stale_write(self):
        def fetch(*args):
            k.configure(self.db,'kev',False,3600)
            return KEV,'etag','rev'
        self.assertEqual(k.refresh(self.db,'kev',True,fetch),'cancelled')
        self.assertEqual(k.search(self.db),[])
        self.assertEqual(k.refresh(self.db,'kev',False,self.fetch(KEV)),'not_due')

    def test_lease_refuses_duplicate_refresh(self):
        def fetch(*args):
            self.assertEqual(k.refresh(self.db,'kev',True,self.fetch(KEV)),'busy')
            return KEV,'etag','rev'
        self.assertEqual(k.refresh(self.db,'kev',True,fetch),'updated')

    def test_attack_revoked_entries_are_removed_on_next_snapshot(self):
        k.refresh(self.db,'attack',True,self.fetch(ATTACK))
        second=copy.deepcopy(ATTACK)
        second['objects'].append(dict(second['objects'][0],name='Second',external_references=[dict(source_name='mitre-attack',external_id='T5678')]))
        second['objects'][0]['revoked']=True
        self.assertEqual(k.refresh(self.db,'attack',True,self.fetch(second)),'updated')
        self.assertIsNone(k.detail(self.db,'attack','T1234'))
        self.assertIsNotNone(k.detail(self.db,'attack','T5678'))

    def test_cve_fetch_derives_url_and_ignores_upstream_link(self):
        urls=[]
        def fetch(url,*args):
            urls.append(url)
            return (copy.deepcopy(DELTA) if url==k.SOURCES['cve']['url'] else copy.deepcopy(CVE)),'etag','rev'
        self.assertEqual(k.refresh(self.db,'cve',True,fetch),'updated')
        self.assertEqual(urls[1],'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/12xxx/CVE-2026-12345.json')
        self.assertIsNotNone(k.detail(self.db,'cve','CVE-2026-12345'))
        self.assertIn('Not a historical',next(s['coverage'] for s in k.status(self.db) if s['source']=='cve'))

    def test_cve_rejection_removes_prior_record(self):
        doc=copy.deepcopy(CVE); delta=copy.deepcopy(DELTA)
        def fetch(url,*args): return (delta if url==k.SOURCES['cve']['url'] else doc),'etag','rev'
        k.refresh(self.db,'cve',True,fetch)
        doc['cveMetadata']['state']='REJECTED'
        delta['new'][0]['dateUpdated']='2026-11-07T00:00:00Z'
        k.refresh(self.db,'cve',True,fetch)
        self.assertIsNone(k.detail(self.db,'cve','CVE-2026-12345'))

    def test_cve_overflow_is_queued_and_drains_after_not_modified(self):
        from unittest.mock import patch
        delta=copy.deepcopy(DELTA)
        delta['new'].append(dict(cveId='CVE-2026-12346',dateUpdated='2026-11-06T00:00:00Z'))
        unchanged=False
        def fetch(url,*args):
            if url==k.SOURCES['cve']['url']:
                return (None,'etag','not_modified') if unchanged else (delta,'etag','rev')
            doc=copy.deepcopy(CVE); doc['cveMetadata']['cveId']=url.rsplit('/',1)[-1].removesuffix('.json')
            return doc,'etag','rev'
        with patch.object(k,'MAX_CVE_FETCH',1):
            self.assertEqual(k.refresh(self.db,'cve',True,fetch),'updated')
            state=next(s for s in k.status(self.db) if s['source']=='cve')
            self.assertEqual(state['pending_records'],1)
            unchanged=True
            self.assertEqual(k.refresh(self.db,'cve',True,fetch),'updated')
        self.assertEqual(len(k.search(self.db)),2)
        self.assertEqual(next(s['pending_records'] for s in k.status(self.db) if s['source']=='cve'),0)

    def test_unapproved_url_is_rejected_before_opening(self):
        for url in ['http://127.0.0.1:3999/','https://attacker.invalid/data','https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/../private.json']:
            with self.subTest(url=url),self.assertRaises(ValueError): k.fetch_json(url,{},100)

    def test_search_escapes_wildcards_and_caps_output(self):
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        self.assertEqual(k.search(self.db,'%'),[])
        self.assertEqual(k.search(self.db,'_'),[])
        self.assertEqual(len(k.search(self.db,'Product')),1)
        with self.assertRaises(ValueError): k.search(self.db,'x'*201)

    def test_project_context_requires_root_scoped_alias(self):
        intelligence.initialize(self.db); k.refresh(self.db,'kev',True,self.fetch(KEV))
        project=self.base/'project'; project.mkdir()
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO advisories VALUES('GHSA-example','','Title',?,'','','')",(json.dumps(['CVE-2026-12345']),))
            rid=db.execute("INSERT INTO intelligence_checks(project,status,project_root) VALUES('project','completed',?)",(str(project),)).lastrowid
            db.execute("INSERT INTO intelligence_matches VALUES(?,'pkg','1.0.0','GHSA-example','','')",(rid,))
        context=k.project_context(self.db,project)
        self.assertTrue(context[0]['id'].startswith('knowledge:kev:CVE-2026-12345:'))
        self.assertEqual(len(context[0]['id'].split(':')[-1]),64)
        self.assertIn('NOT established',context[0]['applicability'])
        self.assertEqual(k.project_context(self.db,self.base/'other'),[])
        continuous.assess(self.db,project,self.base)
        route=project/'app/api/new/route.ts'; route.parent.mkdir(parents=True); route.touch()
        investigation=changes.ensure(self.db,continuous.assess(self.db,project,self.base))
        self.assertIn(context[0]['id'],[e['id'] for e in changes.detail(self.db,investigation)['context']['evidence']])

    def test_historical_reference_survives_catalog_change_and_removal(self):
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        old=k.detail(self.db,'kev','CVE-2026-12345')
        newer=copy.deepcopy(KEV); newer['vulnerabilities'][0]['shortDescription']='Changed summary'
        k.refresh(self.db,'kev',True,self.fetch(newer))
        frozen=k.detail(self.db,'kev','CVE-2026-12345',old['revision'])
        self.assertEqual(frozen['summary'],'A public bulletin.')
        self.assertNotEqual(k.detail(self.db,'kev','CVE-2026-12345')['revision'],old['revision'])
        replacement=copy.deepcopy(KEV); replacement['vulnerabilities'][0]['cveID']='CVE-2026-99999'
        k.refresh(self.db,'kev',True,self.fetch(replacement))
        self.assertIsNone(k.detail(self.db,'kev','CVE-2026-12345'))
        self.assertIsNotNone(k.detail(self.db,'kev','CVE-2026-12345',old['revision']))

    def test_bad_schema_and_invalid_config(self):
        for source in k.SOURCES:
            self.assertEqual(k.refresh(self.db,source,True,self.fetch({'unrelated':True})),'error')
        for source,interval in [('unknown',300),('kev',10),('kev',999999)]:
            with self.assertRaises(ValueError): k.configure(self.db,source,True,interval)

    def test_stale_state_survives_restart(self):
        k.refresh(self.db,'kev',True,self.fetch(KEV))
        with sqlite3.connect(self.db) as db: db.execute("UPDATE knowledge_sources SET succeeded='2020-01-01T00:00:00+00:00' WHERE source='kev'")
        k.initialize(self.db)
        self.assertTrue(next(s['stale'] for s in k.status(self.db) if s['source']=='kev'))
        self.assertEqual(len(k.search(self.db)),1)


if __name__=='__main__': unittest.main()
