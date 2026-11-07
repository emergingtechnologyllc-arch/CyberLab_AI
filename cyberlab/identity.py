"""Persistent project identities. Unknown legacy names never establish ownership."""
import datetime as dt
from pathlib import Path
import sqlite3
import uuid

TABLES=('runs','behavior_checks','ai_behavior_runs','live_runs','experiment_runs',
        'continuous_runs','intelligence_checks','memory_snapshots','risk_runs')


def registry(db):
    db.execute('''CREATE TABLE IF NOT EXISTS project_registry (
        id TEXT PRIMARY KEY, root TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
        created TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '',
        environment TEXT NOT NULL DEFAULT 'unspecified', data_classification TEXT NOT NULL DEFAULT 'unspecified',
        access_policy TEXT NOT NULL DEFAULT '', updated TEXT NOT NULL)''')


def migrate(db,table):
    if table not in TABLES: raise ValueError('Unknown project table')
    columns={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
    if not columns: return
    for column in ('project_root','project_id'):
        if column not in columns: db.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
    db.execute(f'CREATE INDEX IF NOT EXISTS {table}_identity ON {table}(project_id,id)')


def _register(db,root):
    row=db.execute('SELECT id FROM project_registry WHERE root=?',(root,)).fetchone()
    if row: return row[0]
    identifier=str(uuid.uuid4()); stamp=dt.datetime.now(dt.timezone.utc).isoformat()
    db.execute('INSERT INTO project_registry(id,root,name,created,updated) VALUES(?,?,?,?,?)',
               (identifier,root,Path(root).name,stamp,stamp))
    return identifier


def initialize(path,root=None):
    """Add identity to proven historical roots only. Never inspect unknown folders."""
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('BEGIN IMMEDIATE'); registry(db)
        for table in TABLES:
            migrate(db,table)
            columns={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
            if not columns: continue
            params=(root,) if root else ()
            condition="project_id='' AND project_root!=''"+(' AND project_root=?' if root else '')
            roots=db.execute(f'SELECT DISTINCT project_root FROM {table} WHERE {condition}',params).fetchall()
            for (known,) in roots:
                # Preserve the originally captured absolute root; no name or current-symlink inference.
                if not Path(known).is_absolute() or '..' in Path(known).parts: continue
                identifier=_register(db,known)
                db.execute(f"UPDATE {table} SET project_id=? WHERE project_root=? AND project_id=''",(identifier,known))


def register(path,project):
    root=str(Path(project).resolve(strict=True))
    if not Path(root).is_dir(): raise ValueError('Choose a project directory')
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('BEGIN IMMEDIATE'); registry(db)
        return _register(db,root)


def passport(path,project):
    identifier=register(path,project)
    with sqlite3.connect(path) as db:
        db.row_factory=sqlite3.Row
        return dict(db.execute('SELECT * FROM project_registry WHERE id=?',(identifier,)).fetchone())


def update_passport(path,project,**fields):
    allowed={'owner':120,'purpose':800,'environment':30,'data_classification':30,'access_policy':1200}
    if set(fields)!=set(allowed): raise ValueError('Provide all passport fields')
    for key,maximum in allowed.items():
        if not isinstance(fields[key],str) or len(fields[key])>maximum or any(ord(c)<32 and c not in '\n\t' for c in fields[key]):
            raise ValueError('Invalid passport field')
    if fields['environment'] not in ('unspecified','development','staging','production'): raise ValueError('Invalid environment')
    if fields['data_classification'] not in ('unspecified','public','internal','sensitive'): raise ValueError('Invalid data classification')
    identifier=register(path,project)
    with sqlite3.connect(path) as db:
        db.execute('''UPDATE project_registry SET owner=?,purpose=?,environment=?,data_classification=?,
                    access_policy=?,updated=? WHERE id=?''',
            (*[fields[k] for k in allowed],dt.datetime.now(dt.timezone.utc).isoformat(),identifier))
    return identifier
