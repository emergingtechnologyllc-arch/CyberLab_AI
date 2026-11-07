"""Production local runtime utilities: process lock, private storage, safe backups."""
from contextlib import contextmanager
import datetime as dt
import fcntl
import os
from pathlib import Path
import sqlite3


@contextmanager
def instance_lock(root):
    path=Path(root)/'.instance.lock'
    with path.open('a') as lock:
        os.chmod(path,0o600)
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Another CyberLab process is using this data directory. Stop it first.') from None
        try: yield
        finally: fcntl.flock(lock,fcntl.LOCK_UN)


def backup(database,destination):
    database=Path(database).resolve(strict=True)
    destination=Path(destination)
    if destination.exists(): raise ValueError('Backup destination already exists')
    destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Exclusive file creation prevents accidentally overwriting a prior backup.
    fd=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.close(fd)
    try:
        with sqlite3.connect(database.as_uri()+'?mode=ro',uri=True) as source, sqlite3.connect(destination) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('Backup integrity check failed')
    except Exception:
        destination.unlink(missing_ok=True); raise
    return destination


def prepare_database(path,release):
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('CREATE TABLE IF NOT EXISTS application_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        db.execute("INSERT OR REPLACE INTO application_meta VALUES('release',?)",(release,))
    os.chmod(path,0o600)


def migration_backup(path,release):
    path=Path(path).resolve()
    if not path.exists(): return None
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='application_meta'").fetchone():
            row=db.execute("SELECT value FROM application_meta WHERE key='release'").fetchone()
            if row and row[0]==release: return None
    directory=path.parent/'backups'
    marker=directory/f'before-{release}.sqlite3'
    if marker.exists(): return None
    return backup(path,marker)


def recover_interrupted_jobs(path):
    """Called under the application instance lock before starting request workers.

    Preserve partial observations; never silently replay a previously approved job.
    """
    tables=('runs','behavior_checks','ai_behavior_runs','intelligence_checks','live_runs','experiment_runs')
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS runtime_recovery_audit
            (id INTEGER PRIMARY KEY,created TEXT NOT NULL,source_table TEXT NOT NULL,affected INTEGER NOT NULL)''')
        existing={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in tables:
            if table not in existing: continue
            columns={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
            field='summary' if 'summary' in columns else 'error'
            changed=db.execute(f"UPDATE {table} SET status='error',{field}=? WHERE status='running'",
                ('Interrupted by previous process exit. Partial evidence is preserved; review and authorize a new action.',)).rowcount
            if changed:
                db.execute('INSERT INTO runtime_recovery_audit(created,source_table,affected) VALUES(?,?,?)',
                    (dt.datetime.now(dt.timezone.utc).isoformat(),table,changed))
