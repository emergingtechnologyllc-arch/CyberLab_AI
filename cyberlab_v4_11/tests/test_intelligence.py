import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from cyberlab.intelligence import exact_version, project_manifest, check_project, check_detail

class IntelligenceTests(unittest.TestCase):
    def test_version_policy(self):
        self.assertTrue(exact_version('1.2.3'))
        for x in ('^1.2.3','~1.2.3','latest','file:../x','>=1.2.3'):
            self.assertFalse(exact_version(x))

    def test_scope_and_no_secret_leak(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t); p = base/'demo'; p.mkdir()
            (p/'package.json').write_text(json.dumps({'dependencies':{'next':'^15.0.0','react':'19.0.0'}}))
            (p/'.env').write_text('SECRET=private')
            name, deps = project_manifest(p,base)
            self.assertEqual(name,'demo'); self.assertEqual(deps['next'],'^15.0.0')
            self.assertNotIn('private',str(deps))
            with self.assertRaises(ValueError): project_manifest('/',base)

    def test_ingest_mock_and_uncertainty(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t); p=base/'demo'; p.mkdir()
            (p/'package.json').write_text(json.dumps({'dependencies':{'next':'^15.0.0','react':'19.0.0'}}))
            db=str(base/'db.sqlite')
            def query(pkgs):
                self.assertEqual(list(pkgs),['next','react'])
                return [{'vulns':[{'id':'GHSA-test-0001'}]}, {'vulns':[]}]
            def details(ids):
                return {'GHSA-test-0001':{'id':'GHSA-test-0001','summary':'Test only', 'references':[]}}
            cid=check_project(db,p,base,query=query,details_fetch=details)
            check, matches=check_detail(db,cid)
            self.assertEqual(check['status'],'completed')
            self.assertEqual(len(matches),1)
            self.assertEqual(matches[0]['assessment'],'version_unresolved')
            self.assertEqual(matches[0]['summary'],'Test only')

if __name__ == '__main__': unittest.main()
