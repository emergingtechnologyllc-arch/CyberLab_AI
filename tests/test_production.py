from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from cyberlab import jobs,runtime
from cyberlab import __version__


class ProductionTests(unittest.TestCase):
    def test_queue_is_bounded_and_deduplicated(self):
        queue=jobs.Queue(workers=1,capacity=1); entered=threading.Event(); release=threading.Event()
        def work(): entered.set(); release.wait(3); return 'ok'
        try:
            future=queue.submit('one',work); self.assertTrue(entered.wait(1))
            for key in ['one','two']:
                with self.assertRaises(jobs.BusyError): queue.submit(key,lambda:None)
            release.set(); self.assertEqual(future.result(),'ok')
        finally: release.set(); queue.close()
        with self.assertRaises(jobs.BusyError): queue.submit('after-close',lambda:None)

    def test_shutdown_cancels_jobs_that_have_not_started(self):
        queue=jobs.Queue(workers=1,capacity=2)
        entered=threading.Event(); release=threading.Event(); cancelled=threading.Event(); unexpected=threading.Event()
        first=queue.submit('active',lambda:(entered.set(),release.wait(3)))
        self.assertTrue(entered.wait(1))
        pending=queue.submit('pending',unexpected.set)
        pending.add_done_callback(lambda _:cancelled.set())
        closer=threading.Thread(target=queue.close); closer.start()
        try:
            self.assertTrue(cancelled.wait(1)); self.assertTrue(pending.cancelled())
            self.assertFalse(unexpected.is_set())
        finally: release.set(); closer.join(timeout=5)
        self.assertFalse(closer.is_alive()); self.assertEqual(queue.keys,set())

    def test_one_instance_per_data_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with runtime.instance_lock(tmp):
                with self.assertRaises(RuntimeError):
                    with runtime.instance_lock(tmp): pass
            with runtime.instance_lock(tmp): pass

    def test_backup_is_consistent_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'live.db'; target=Path(tmp)/'backup.db'
            with sqlite3.connect(source) as db:
                db.execute('PRAGMA journal_mode=WAL'); db.execute('CREATE TABLE evidence(value TEXT)'); db.execute("INSERT INTO evidence VALUES('keep')")
            runtime.backup(source,target)
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            with sqlite3.connect(target) as db: self.assertEqual(db.execute('SELECT value FROM evidence').fetchone()[0],'keep')
            with self.assertRaises(ValueError): runtime.backup(source,target)

    def test_inventory_bounds_empty_directory_walks(self):
        from unittest.mock import patch
        from cyberlab.behavior import inventory
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); project=root/'project'; (project/'empty/child').mkdir(parents=True)
            with patch('cyberlab.behavior.MAX_DIRECTORIES',1):
                with self.assertRaisesRegex(ValueError,'directory budget'): inventory(project,root)

    def test_restart_marks_interrupted_jobs_without_deleting_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE runs(id INTEGER PRIMARY KEY,status TEXT,summary TEXT)')
                db.execute("INSERT INTO runs VALUES(1,'running','partial')")
                db.execute('CREATE TABLE events(run_id INTEGER,payload TEXT)')
                db.execute("INSERT INTO events VALUES(1,'keep evidence')")
            runtime.recover_interrupted_jobs(path)
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT status FROM runs').fetchone()[0],'error')
                self.assertEqual(db.execute('SELECT payload FROM events').fetchone()[0],'keep evidence')
                self.assertEqual(db.execute('SELECT affected FROM runtime_recovery_audit').fetchone()[0],1)

    def test_migration_backup_runs_before_new_release_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'test.sqlite3'
            self.assertIsNone(runtime.migration_backup(db,__version__))
            runtime.prepare_database(db,'previous')
            target=runtime.migration_backup(db,__version__)
            self.assertTrue(target.is_file())
            runtime.prepare_database(db,__version__)
            self.assertIsNone(runtime.migration_backup(db,__version__))


if __name__=='__main__': unittest.main()
