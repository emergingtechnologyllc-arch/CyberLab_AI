"""Read-only Next.js route/authorization boundary inventory; hypotheses, never findings."""
import datetime as dt
import json
from pathlib import Path
import re
import sqlite3

MAX_FILES = 3000
MAX_ROUTES = 250
MAX_FILE_BYTES = 100_000
ROUTE_FILES = {'route.js','route.ts','route.jsx','route.tsx'}
API_ROOTS = ('app/api','src/app/api','pages/api','src/pages/api')
SENSITIVE = re.compile(r'(admin|account|billing|customer|invoice|order|payment|profile|user|session|auth)',re.I)
DYNAMIC = re.compile(r'\[(?:\.\.\.)?[^\]]+\]')

def init_behavior(db_path):
    with sqlite3.connect(db_path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS behavior_checks
            (id INTEGER PRIMARY KEY, created TEXT, project TEXT, status TEXT, route_count INTEGER, summary TEXT, error TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS behavior_routes
            (check_id INTEGER, route TEXT, methods TEXT, dynamic INTEGER, sensitive INTEGER,
             hypothesis TEXT, evidence TEXT)''')

def route_for(rel):
    p = rel.as_posix()
    for root in API_ROOTS:
        if p.startswith(root + '/'):
            tail = p[len(root)+1:]
            if root.endswith('app/api'):
                if Path(tail).name not in ROUTE_FILES:
                    return None
                tail = str(Path(tail).parent)
                if tail == '.': tail = ''
            else:
                if Path(tail).suffix not in ('.js','.ts','.jsx','.tsx') or Path(tail).name.startswith('_'):
                    return None
                tail = str(Path(tail).with_suffix(''))
                if tail == 'index': tail = ''
                elif tail.endswith('/index'): tail = tail[:-6]
            return '/api/' + tail.strip('/')
    return None

def inventory(project, base):
    root = Path(project).resolve(strict=True)
    approved = Path(base).resolve(strict=True)
    if not root.is_dir() or not root.is_relative_to(approved):
        raise ValueError('Project must be under the approved projects directory')
    skip = {'node_modules','.git','.next','dist','build','coverage','.venv'}
    routes = []
    seen = 0
    def on_error(exc):
        raise ValueError('Unable to read project directory') from exc
    # Do not follow directory symlinks; do not open source files, credentials, or env files.
    import os
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=on_error):
        dirs[:] = [d for d in dirs if d not in skip and not (Path(directory)/d).is_symlink()]
        for filename in files:
            seen += 1
            if seen > MAX_FILES:
                raise ValueError('Project exceeds inventory file budget')
            file = Path(directory)/filename
            if file.is_symlink(): continue
            rel = file.relative_to(root)
            route = route_for(rel)
            if route is None: continue
            if len(route) > 200:
                raise ValueError('Route exceeds metadata length budget')
            if len(routes) >= MAX_ROUTES:
                raise ValueError('Project exceeds route budget')
            dynamic = bool(DYNAMIC.search(route))
            sensitive = bool(SENSITIVE.search(route))
            hypothesis = ('Review object-level authorization and ownership rules for dynamic resource identifiers' if dynamic else
                          'Review authentication, authorization, and sensitive-data access rules' if sensitive else
                          'Confirm intended access policy and authentication requirements')
            routes.append({'route':route,'methods':'unknown (not inspected)','dynamic':dynamic,'sensitive':sensitive,
                           'hypothesis':hypothesis,'evidence':f'route filename: {rel.as_posix()}'})
    routes.sort(key=lambda x:x['route'])
    return routes

def check_project(db_path, project, base):
    init_behavior(db_path)
    with sqlite3.connect(db_path) as db:
        rid = db.execute('INSERT INTO behavior_checks(created,project,status,route_count,summary,error) VALUES(?,?,?,?,?,?)',
            (dt.datetime.now(dt.timezone.utc).isoformat(),Path(project).name,'running',0,'','')).lastrowid
    try:
        routes = inventory(project, base)
        with sqlite3.connect(db_path) as db:
            db.executemany('INSERT INTO behavior_routes VALUES(?,?,?,?,?,?,?)',[(rid,r['route'],r['methods'],int(r['dynamic']),int(r['sensitive']),r['hypothesis'],r['evidence']) for r in routes])
            db.execute('UPDATE behavior_checks SET status=?,route_count=?,summary=? WHERE id=?',
                       ('completed',len(routes),'Filename-only route inventory; hypotheses are not confirmed vulnerabilities',rid))
    except Exception as exc:
        with sqlite3.connect(db_path) as db:
            db.execute('UPDATE behavior_checks SET status=?,error=? WHERE id=?',('error',f'{type(exc).__name__}: {str(exc)[:250]}',rid))
    return rid

def recent_checks(db_path):
    init_behavior(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute('SELECT * FROM behavior_checks ORDER BY id DESC LIMIT 20')]

def detail(db_path, rid):
    init_behavior(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM behavior_checks WHERE id=?',(rid,)).fetchone()
        if row is None:return None
        routes=[dict(r) for r in db.execute('SELECT * FROM behavior_routes WHERE check_id=? ORDER BY route',(rid,))]
    return dict(row),routes
