import tempfile
import unittest
from pathlib import Path
from cyberlab.continuous import initialize, assess, recent, detail, compare

class ContinuousTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.project=self.base/'demo'; self.project.mkdir()
        self.db=str(self.base/'test.sqlite3')
    def route(self,name):
        p=self.project/'app'/'api'/name/'route.ts'; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('export async function GET() {}')
    def test_baseline_and_unchanged(self):
        self.route('orders'); a=assess(self.db,self.project,self.base); b=assess(self.db,self.project,self.base)
        self.assertEqual(detail(self.db,a)[0]['status'],'baseline'); self.assertEqual(detail(self.db,b)[0]['status'],'unchanged')
    def test_detect_added(self):
        self.route('orders'); assess(self.db,self.project,self.base); self.route('users'); rid=assess(self.db,self.project,self.base)
        self.assertEqual(detail(self.db,rid)[0]['status'],'changed'); self.assertIn('/api/users',detail(self.db,rid)[1]['added_routes'])
    def test_detect_removed(self):
        self.route('orders'); assess(self.db,self.project,self.base); (self.project/'app/api/orders/route.ts').unlink(); rid=assess(self.db,self.project,self.base)
        self.assertIn('/api/orders',detail(self.db,rid)[1]['removed_routes'])
    def test_reject_outside_project(self):
        with self.assertRaises(ValueError): assess(self.db,self.base,self.base)
    def test_isolated_projects(self):
        self.route('orders'); assess(self.db,self.project,self.base); other=self.base/'other'; other.mkdir(); rid=assess(self.db,other,self.base)
        self.assertEqual(detail(self.db,rid)[0]['status'],'baseline')
    def test_compare_no_fabrication(self):
        self.assertEqual(compare({'routes':['/a']},{'routes':['/a']})['added_routes'],[])
