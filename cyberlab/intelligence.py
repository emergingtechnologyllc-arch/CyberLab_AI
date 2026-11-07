"""Conservative advisory ingestion and package inventory. No vulnerability confirmation."""
import datetime as dt
import json
from . import __version__
import os
from pathlib import Path
import re
import sqlite3
import urllib.request
import time

OSV_URL = 'https://api.osv.dev/v1/querybatch'
MAX_RESPONSE = 2_000_000
MAX_MANIFEST = 128_000
MAX_PACKAGES = 75


def initialize(db_path):
    with sqlite3.connect(db_path, timeout=15) as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('''CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY, modified TEXT, summary TEXT, aliases TEXT,
            reference TEXT, raw TEXT, fetched TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS intelligence_checks (
            id INTEGER PRIMARY KEY, created TEXT, project TEXT, status TEXT,
            package_count INTEGER, match_count INTEGER, error TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS intelligence_matches (
            check_id INTEGER, package TEXT, declared TEXT, advisory_id TEXT,
            assessment TEXT, reason TEXT)''')

        if 'project_root' not in {r[1] for r in db.execute('PRAGMA table_info(intelligence_checks)')}:
            db.execute("ALTER TABLE intelligence_checks ADD COLUMN project_root TEXT NOT NULL DEFAULT ''")
        db.execute('CREATE INDEX IF NOT EXISTS intelligence_root ON intelligence_checks(project_root,id)')


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def project_manifest(project, projects_base):
    base = Path(projects_base).resolve(strict=True)
    p = Path(project).resolve(strict=True)
    if not p.is_dir() or not p.is_relative_to(base):
        raise ValueError('Project must be within the authorized projects directory')
    manifest = p / 'package.json'
    if not manifest.is_file() or not manifest.resolve().is_relative_to(p):
        raise ValueError('Regular package.json is required')
    if manifest.stat().st_size > MAX_MANIFEST:
        raise ValueError('Manifest exceeds maximum size')
    data = json.loads(manifest.read_text('utf-8'))
    if not isinstance(data,dict): raise ValueError('Manifest must be a JSON object')
    packages = {}
    for group in ('dependencies', 'devDependencies'):
        dependencies=data.get(group,{})
        if not isinstance(dependencies,dict): raise ValueError('Dependency groups must be JSON objects')
        for name, spec in dependencies.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            if re.fullmatch(r'(?:@[-a-zA-Z0-9_.]+/)?[-a-zA-Z0-9_.]+', name):
                packages[name] = spec[:100]
    if len(packages) > MAX_PACKAGES:
        raise ValueError(f'Limit is {MAX_PACKAGES} dependencies per check')
    return p.name, packages


def exact_version(spec):
    # A manifest range is not the resolved installed version. Only bare x.y.z[pre-release] counts.
    return bool(re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?', spec))


def osv_batch_query(packages, opener=None):
    """Send package name and exact version only; ranges are queried by name alone."""
    queries = []
    for name, spec in packages.items():
        item = {'package': {'name': name, 'ecosystem': 'npm'}}
        if exact_version(spec):
            item['version'] = spec
        queries.append(item)
    if not queries:
        return []
    payload = json.dumps({'queries': queries}).encode()
    request = urllib.request.Request(OSV_URL, data=payload,
        headers={'Content-Type':'application/json','User-Agent':f'CyberLab/{__version__}'}, method='POST')
    if opener is None:
        opener = urllib.request.urlopen
    with opener(request, timeout=20) as response:
        data = response.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError('Advisory response too large')
    results = json.loads(data)['results']
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValueError('Unexpected advisory response')
    return results


def osv_details(ids, opener=None):
    """Fetch canonical details from fixed OSV API endpoint, never advisory-provided URLs."""
    if opener is None:
        opener = urllib.request.urlopen
    details = {}
    deadline=time.monotonic()+45
    for advisory_id in sorted(set(ids))[:25]:
        if time.monotonic()>deadline: raise TimeoutError('Advisory detail budget exhausted')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,100}', advisory_id):
            continue
        req = urllib.request.Request('https://api.osv.dev/v1/vulns/' + advisory_id,
            headers={'User-Agent':f'CyberLab/{__version__}'})
        with opener(req, timeout=min(8,max(.1,deadline-time.monotonic()))) as response:
            raw = response.read(100_001)
        if len(raw) > 100_000:
            continue
        data = json.loads(raw)
        if data.get('id') == advisory_id:
            details[advisory_id] = data
    return details


def check_project(db_path, project, projects_base, query=osv_batch_query, details_fetch=osv_details):
    name, packages = project_manifest(project, projects_base)
    initialize(db_path)
    with sqlite3.connect(db_path, timeout=15) as db:
        cur = db.execute('INSERT INTO intelligence_checks(created,project,status,package_count,match_count,error,project_root) VALUES(?,?,?,?,?,?,?)',
                         (utcnow(), name, 'running', len(packages), 0, '', str(Path(project).resolve())))
        check_id = cur.lastrowid
    try:
        results = query(packages)
        ids = [v.get('id') for r in results for v in r.get('vulns', []) if isinstance(v, dict) and isinstance(v.get('id'), str)]
        details = details_fetch(ids)
        matches = []
        for (pkg, spec), result in zip(packages.items(), results):
            for vuln in result.get('vulns', [])[:100]:
                vid = vuln.get('id')
                if not isinstance(vid, str):
                    continue
                if exact_version(spec):
                    assessment = 'potential_version_match'
                    reason = 'OSV returned this advisory for the declared exact version; verify installed lockfile and affected configuration'
                else:
                    assessment = 'version_unresolved'
                    reason = 'Manifest specifies a range or non-exact version; installed version and applicability not established'
                matches.append((check_id, pkg, spec, vid, assessment, reason))
        with sqlite3.connect(db_path, timeout=15) as db:
            for vid, item in details.items():
                references = item.get('references') or []
                reference = next((r.get('url') for r in references if isinstance(r, dict) and isinstance(r.get('url'), str) and r['url'].startswith('https://')), 'https://osv.dev/vulnerability/' + vid)
                db.execute('INSERT OR REPLACE INTO advisories VALUES(?,?,?,?,?,?,?)',
                    (vid, str(item.get('modified',''))[:80], str(item.get('summary',''))[:2000],
                     json.dumps(item.get('aliases',[])[:20]), reference[:500], json.dumps(item)[:50000], utcnow()))
            db.executemany('INSERT INTO intelligence_matches VALUES(?,?,?,?,?,?)', matches)
            db.execute('UPDATE intelligence_checks SET status=?,match_count=? WHERE id=?', ('completed', len(matches), check_id))
    except Exception as exc:
        with sqlite3.connect(db_path, timeout=15) as db:
            db.execute('UPDATE intelligence_checks SET status=?,error=? WHERE id=?', ('error', f'{type(exc).__name__}: {exc}'[:300], check_id))
    return check_id


def recent_checks(db_path):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute('SELECT * FROM intelligence_checks ORDER BY id DESC LIMIT 20')]


def check_detail(db_path, check_id):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        check = db.execute('SELECT * FROM intelligence_checks WHERE id=?', (check_id,)).fetchone()
        if not check:
            return None
        rows = db.execute('''SELECT m.*, a.summary, a.reference, a.modified, a.aliases FROM intelligence_matches m
            LEFT JOIN advisories a ON a.id=m.advisory_id WHERE m.check_id=? ORDER BY m.package,m.advisory_id''', (check_id,)).fetchall()
        result=[dict(row) for row in rows]
        from . import knowledge
        knowledge.initialize(db_path)
        with sqlite3.connect(db_path) as library:
            exploited={r[0] for r in library.execute("SELECT external_id FROM knowledge_records WHERE source='kev'")}
        if not check['project_root']: exploited=set()
        for row in result:
            try: aliases=json.loads(row.get('aliases') or '[]')
            except (ValueError,TypeError): aliases=[]
            row['known_exploited_reference']=bool(exploited.intersection([row['advisory_id']]+(aliases if isinstance(aliases,list) else [])))
        return dict(check), result
