import sqlite3
import tempfile
import unittest
from pathlib import Path
from cyberlab.behavior import inventory, init_behavior, check_project, detail

class BehaviorTests(unittest.TestCase):
    def test_route_discovery_and_hypothesis(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'demo'; (root/'app/api/orders/[id]').mkdir(parents=True)
            (root/'app/api/orders/[id]/route.ts').write_text('export const GET = 1')
            (root/'pages/api').mkdir(parents=True)
            (root/'pages/api/status.js').write_text('')
            result=inventory(root,d)
            self.assertEqual([r['route'] for r in result],['/api/orders/[id]','/api/status'])
            self.assertTrue(result[0]['dynamic'])
            self.assertIn('authorization',result[0]['hypothesis'])
            db=Path(d)/'db.sqlite'; init_behavior(db)
            rid=check_project(db,root,d)
            check,routes=detail(db,rid)
            self.assertEqual(check['status'],'completed')
            self.assertEqual(len(routes),2)
    def test_reject_outside_scope(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'project'; root.mkdir()
            approved=Path(d)/'allowed'; approved.mkdir()
            with self.assertRaises(ValueError):inventory(root,approved)
    def test_ignore_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'demo'; root.mkdir()
            (root/'app').symlink_to(Path(d),target_is_directory=True)
            self.assertEqual(inventory(root,d),[])

if __name__=='__main__': unittest.main()
