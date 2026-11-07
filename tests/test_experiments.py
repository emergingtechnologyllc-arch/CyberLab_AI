import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from cyberlab.experiments import initialize, validate_fixture, verify_case, run, detail

class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.base=Path(self.tmp.name)
        self.project=self.base/'demo'
        route=self.project/'app/api/orders/[id]/route.ts'
        route.parent.mkdir(parents=True)
        route.write_text('export async function GET() {}')
        self.case={'route':'/api/orders/[id]','requester':'customer_a','owner':'customer_b','observed_status':200,'expected_status':403}
        (self.project/'cyberlab-test-fixture.json').write_text(json.dumps({'schema_version':1,'cases':[self.case]}))
        self.db=str(self.base/'test.sqlite')
    def tearDown(self): self.tmp.cleanup()
    def test_fixture_valid(self):
        self.assertEqual(len(validate_fixture(self.project,self.base)),1)
    def test_classification_is_not_real_finding(self):
        result=verify_case(self.case)
        self.assertEqual(result['classification'],'simulated_authorization_mismatch')
        self.assertFalse(result['confirmed_vulnerability'])
    def test_reject_uninventoried_route(self):
        self.case['route']='/api/private'
        (self.project/'cyberlab-test-fixture.json').write_text(json.dumps({'schema_version':1,'cases':[self.case]}))
        with self.assertRaises(ValueError):validate_fixture(self.project,self.base)
    def test_reject_symlink_fixture(self):
        fixture=self.project/'cyberlab-test-fixture.json'
        fixture.unlink()
        fixture.symlink_to(self.base/'outside')
        with self.assertRaises(ValueError):validate_fixture(self.project,self.base)
    def test_run_records_evidence(self):
        initialize(self.db)
        rid=run(self.db,self.project,self.base)
        check,events=detail(self.db,rid)
        self.assertEqual(check['status'],'completed')
        self.assertEqual(events[1]['kind'],'synthetic_verification')
        self.assertIn('0 real vulnerabilities',check['summary'])

if __name__=='__main__':unittest.main()
