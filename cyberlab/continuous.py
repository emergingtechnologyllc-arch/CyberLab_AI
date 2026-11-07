"""repeatable, bounded project change assessments. No network scans."""
import datetime as dt
import hashlib
import json
import sqlite3
from pathlib import Path
from .behavior import inventory


def initialize(db_path):
    with sqlite3.connect(db_path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS continuous_runs
        (id INTEGER PRIMARY KEY, created TEXT NOT NULL, project TEXT NOT NULL,
         fingerprint TEXT NOT NULL, status TEXT NOT NULL, summary TEXT NOT NULL,
         snapshot TEXT NOT NULL)""")

        columns = {r[1] for r in db.execute('PRAGMA table_info(continuous_runs)')}
        if 'project_root' not in columns:
            db.execute("ALTER TABLE continuous_runs ADD COLUMN project_root TEXT NOT NULL DEFAULT ''")
        db.execute('CREATE INDEX IF NOT EXISTS continuous_project_root ON continuous_runs(project,project_root,id)')

def canonical_routes(rows):
    return sorted(set(x['route'] for x in rows if isinstance(x.get('route'),str)))

def compare(old, new):
    a=set(old.get('routes',[])); b=set(new.get('routes',[]))
    # Metadata consists of filenames only; source contents are never inspected.
    old_meta = old.get('metadata', {})
    new_meta = new.get('metadata', {})
    modified = sorted(r for r in a & b if r in old_meta and r in new_meta and old_meta[r] != new_meta[r])
    return {'added_routes':sorted(b-a),'removed_routes':sorted(a-b),
            'modified_routes':modified, 'unchanged_routes':len(a&b)-len(modified),
            'changed':a!=b or bool(modified)}

def assess(db_path,project_path,base):
    initialize(db_path)
    project_path=Path(project_path).resolve()
    if project_path == Path(base).resolve():
        raise ValueError("Select a project directory inside the project root")
    rows=inventory(str(project_path),base)
    routes=canonical_routes(rows)
    metadata = {}
    for row in rows:
        metadata.setdefault(row['route'], []).append(row['evidence'])
    snapshot={'routes':routes,'schema':2,'metadata':{r:sorted(v) for r,v in metadata.items()}}
    encoded=json.dumps(snapshot,sort_keys=True,separators=(',',':'))
    fingerprint=hashlib.sha256(encoded.encode()).hexdigest()
    name=project_path.name
    with sqlite3.connect(db_path) as db:
        db.execute('BEGIN IMMEDIATE')
        previous=db.execute('SELECT snapshot,id,status FROM continuous_runs WHERE project=? AND project_root=? ORDER BY id DESC LIMIT 1',(name,str(project_path))).fetchone()
        if previous and previous[0] == encoded and previous[2] == 'unchanged':
            return previous[1]
        diff=compare(json.loads(previous[0]),snapshot) if previous else {'added_routes':[],'removed_routes':[],'modified_routes':[],'unchanged_routes':len(routes),'changed':False}
        status='baseline' if previous is None else ('changed' if diff['changed'] else 'unchanged')
        summary=f"{status}: {len(routes)} routes; {len(diff['added_routes'])} added; {len(diff['removed_routes'])} removed; {len(diff['modified_routes'])} filename metadata changes. No vulnerability confirmation."
        rid=db.execute('INSERT INTO continuous_runs(created,project,fingerprint,status,summary,snapshot,project_root) VALUES(?,?,?,?,?,?,?)',
            (dt.datetime.now(dt.timezone.utc).isoformat(),name,fingerprint,status,summary,encoded,str(project_path))).lastrowid
    return rid

def recent(db_path):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        return [dict(x) for x in db.execute('SELECT id,created,project,status,summary FROM continuous_runs ORDER BY id DESC LIMIT 20')]

def detail(db_path,rid):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM continuous_runs WHERE id=?',(rid,)).fetchone()
        if row is None:return None
        prev=db.execute('SELECT snapshot FROM continuous_runs WHERE project=? AND project_root=? AND id<? ORDER BY id DESC LIMIT 1',(row['project'],row['project_root'],rid)).fetchone()
        current=json.loads(row['snapshot'])
        diff=compare(json.loads(prev[0]),current) if prev else {'added_routes':[],'removed_routes':[],'modified_routes':[],'unchanged_routes':len(current['routes']),'changed':False}
        return dict(row),diff
