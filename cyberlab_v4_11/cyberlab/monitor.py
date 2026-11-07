"""Opt-in single-worker monitoring; no live target requests or command execution."""
import datetime as dt
from pathlib import Path
import sqlite3
import threading
import time
from . import continuous, change_investigation as changes

MAX_PROJECTS = 20


def initialize(path):
    changes.initialize(path)
    with sqlite3.connect(path, timeout=10) as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('''CREATE TABLE IF NOT EXISTS monitor_settings
            (project_root TEXT PRIMARY KEY, enabled INTEGER NOT NULL, interval INTEGER NOT NULL,
             use_ai INTEGER NOT NULL, next_run REAL NOT NULL DEFAULT 0,
             last_assessment INTEGER, status TEXT NOT NULL DEFAULT 'pending', updated TEXT NOT NULL)''')

        if 'generation' not in {r[1] for r in db.execute('PRAGMA table_info(monitor_settings)')}:
            db.execute('ALTER TABLE monitor_settings ADD COLUMN generation INTEGER NOT NULL DEFAULT 0')


def configure(path, project, base, enabled=False, interval=300, use_ai=False):
    root = Path(project).resolve(strict=True)
    approved = Path(base).resolve(strict=True)
    if root.parent != approved or not root.is_dir():
        raise ValueError('Monitor requires a direct project folder under the approved root')
    if type(interval) is not int or not 30 <= interval <= 86400:
        raise ValueError('Interval must be 30–86400 seconds')
    initialize(path)
    with sqlite3.connect(path, timeout=10) as db:
        db.execute('BEGIN IMMEDIATE')
        exists = db.execute('SELECT 1 FROM monitor_settings WHERE project_root=?', (str(root),)).fetchone()
        if not exists and db.execute('SELECT count(*) FROM monitor_settings').fetchone()[0] >= MAX_PROJECTS:
            raise ValueError('Monitor project budget exceeded')
        db.execute('''INSERT INTO monitor_settings(project_root,enabled,interval,use_ai,updated)
            VALUES(?,?,?,?,?) ON CONFLICT(project_root) DO UPDATE SET enabled=excluded.enabled,
            interval=excluded.interval,use_ai=excluded.use_ai,next_run=0,updated=excluded.updated,
            generation=monitor_settings.generation+1''',
            (str(root), int(enabled), interval, int(use_ai), dt.datetime.now(dt.timezone.utc).isoformat()))


def settings(path):
    initialize(path)
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        return [dict(r) for r in db.execute('SELECT * FROM monitor_settings ORDER BY project_root')]


class Monitor:
    def __init__(self, path, base):
        initialize(path)
        self.path, self.base = path, base
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.thread = None

    def tick(self):
        if not self.lock.acquire(blocking=False):
            return
        try:
            for row in settings(self.path):
                if self.stop_event.is_set():
                    break
                # Recheck settings immediately before starting each assessment.
                with sqlite3.connect(self.path, timeout=10) as db:
                    current = db.execute('SELECT enabled,next_run,generation FROM monitor_settings WHERE project_root=?', (row['project_root'],)).fetchone()
                if not current[0] or current[1] > time.time() or current[2] != row['generation']:
                    continue
                assessment = None
                status = 'assessment_failed'
                try:
                    assessment = continuous.assess(self.path, row['project_root'], self.base)
                    investigation = changes.ensure(self.path, assessment)
                    status = continuous.detail(self.path, assessment)[0]['status']
                    if investigation and row['use_ai'] and not self.stop_event.is_set():
                        # Only a new pending analysis is scheduled, failures require manual retry.
                        if changes.detail(self.path, investigation)['status'] == 'pending_analysis':
                            status = changes.analyze(self.path, investigation, schedule=(row['project_root'], row['generation']))
                except Exception:
                    # Never persist exception strings: paths or upstream errors may contain secrets.
                    status = 'assessment_failed'
                with sqlite3.connect(self.path, timeout=10) as db:
                    db.execute('UPDATE monitor_settings SET next_run=?,last_assessment=?,status=? WHERE project_root=? AND generation=?',
                               (time.time() + row['interval'], assessment, status, row['project_root'], row['generation']))
        finally:
            self.lock.release()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        def loop():
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except sqlite3.Error:
                    pass
                self.stop_event.wait(1)
        self.thread = threading.Thread(target=loop, name='cyberlab-monitor', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=20)
