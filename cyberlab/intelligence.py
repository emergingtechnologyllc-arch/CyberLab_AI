"""Conservative advisory ingestion and package inventory. No vulnerability confirmation."""
import datetime as dt
import json
from . import __version__
import os
from pathlib import Path
import re
import sqlite3
from . import identity, dependencies
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
        identity.migrate(db, 'intelligence_checks')
        columns={r[1] for r in db.execute('PRAGMA table_info(intelligence_checks)')}
        for name in ('coverage','snapshot_hash'):
            if name not in columns: db.execute(f"ALTER TABLE intelligence_checks ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
        db.execute('''CREATE TABLE IF NOT EXISTS intelligence_components (
            check_id INTEGER NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,provenance TEXT NOT NULL,
            direct INTEGER NOT NULL,locations_count INTEGER NOT NULL,queried INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(check_id,name,version))''')


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


def osv_component_query(components,deadline=None,opener=None):
    deadline=deadline or time.monotonic()+40
    opener=opener or urllib.request.urlopen
    results=[]
    for offset in range(0,len(components),75):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('Dependency query budget exhausted')
        batch=components[offset:offset+75]; queries=[]
        for component in batch:
            item={'package':{'name':component['name'],'ecosystem':'npm'}}
            if dependencies.VERSION.fullmatch(component['version']): item['version']=component['version']
            queries.append(item)
        request=urllib.request.Request(OSV_URL,data=json.dumps({'queries':queries}).encode(),
            headers={'Content-Type':'application/json','User-Agent':f'CyberLab/{__version__}'},method='POST')
        with opener(request,timeout=min(10,remaining)) as response: raw=response.read(MAX_RESPONSE+1)
        if len(raw)>MAX_RESPONSE: raise ValueError('OSV response exceeds budget')
        data=json.loads(raw)
        items=data.get('results')
        if not isinstance(items,list) or len(items)!=len(batch) or any(not isinstance(r,dict) for r in items):
            raise ValueError('Unexpected OSV component response')
        results.extend(items)
    return results


def check_project(db_path, project, projects_base, query=None, details_fetch=osv_details, component_query=None):
    snapshot=dependencies.inventory(project,projects_base)
    name=snapshot['project']; initialize(db_path)
    project_id=identity.register(db_path,project)
    # Preserve all inventory components; query a bounded direct-first subset explicitly.
    components=sorted(snapshot['components'],key=lambda c:(not c['direct'],c['name'],c['version']))
    selected=components[:1000]
    coverage=json.dumps(dict(lockfile=snapshot['lockfile'],consistency_verified=snapshot['consistency_verified'],
        inventory_components=len(components),query_limit=1000,queried_components=0,
        notes=snapshot['coverage_notes'],limitation=snapshot['limitation']))
    with sqlite3.connect(db_path,timeout=15) as db:
        check_id=db.execute('''INSERT INTO intelligence_checks
            (created,project,status,package_count,match_count,error,project_root,project_id,coverage,snapshot_hash)
            VALUES(?,?,'running',?,0,'',?,?,?,?)''',
            (utcnow(),name,len(components),str(Path(project).resolve()),project_id,coverage,dependencies.fingerprint(snapshot))).lastrowid
        db.executemany('INSERT INTO intelligence_components(check_id,name,version,provenance,direct,locations_count) VALUES(?,?,?,?,?,?)',
            [(check_id,c['name'],c['version'],c['provenance'],int(c['direct']),c['locations_count']) for c in components])
    try:
        if component_query is not None: results=component_query(selected)
        elif query is not None:
            # Compatibility hook for older custom transports; exact multi-version adapters use component_query.
            if len({c['name'] for c in selected})!=len(selected): raise ValueError('Use component_query for multiple versions of the same package')
            results=query({c['name']:c['version'] for c in selected})
        else: results=osv_component_query(selected)
        if not isinstance(results,list) or len(results)!=len(selected) or any(not isinstance(r,dict) for r in results):
            raise ValueError('Unexpected advisory response count')
        ids=[v.get('id') for r in results for v in r.get('vulns',[])[:100] if isinstance(v,dict) and isinstance(v.get('id'),str)]
        details=details_fetch(ids)
        matches=[]
        for component,result in zip(selected,results):
            for vuln in result.get('vulns',[])[:100]:
                if not isinstance(vuln,dict): continue
                vid=vuln.get('id')
                if not isinstance(vid,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,100}',vid): continue
                if component['provenance']=='lockfile_resolved':
                    assessment='potential_lockfile_version_match'
                    reason='OSV candidate for a lockfile-resolved version; deployed installation and reachability are not verified'
                    if not snapshot['consistency_verified']: reason+='; manifest/lock consistency is incomplete'
                elif dependencies.VERSION.fullmatch(component['version']):
                    assessment='potential_version_match'; reason='Declared exact version only; no deployed installation evidence'
                else:
                    assessment='version_unresolved'; reason='Manifest range or unsupported version; installed applicability is unresolved'
                matches.append((check_id,component['name'],component['version'],vid,assessment,reason))
        info=json.loads(coverage); info['queried_components']=len(selected)
        with sqlite3.connect(db_path,timeout=15) as db:
            for vid,item in details.items():
                if item.get('id')!=vid: continue
                # Canonical OSV reference, never a fetch URL taken from feed content.
                reference='https://osv.dev/vulnerability/'+vid
                db.execute('INSERT OR REPLACE INTO advisories VALUES(?,?,?,?,?,?,?)',
                    (vid,str(item.get('modified',''))[:80],str(item.get('summary',''))[:2000],
                     json.dumps(item.get('aliases',[])[:20]),reference,json.dumps(item)[:50000],utcnow()))
            db.executemany('INSERT INTO intelligence_matches VALUES(?,?,?,?,?,?)',matches)
            db.executemany('UPDATE intelligence_components SET queried=1 WHERE check_id=? AND name=? AND version=?',
                           [(check_id,c['name'],c['version']) for c in selected])
            db.execute("UPDATE intelligence_checks SET status='completed',match_count=?,coverage=? WHERE id=?",(len(matches),json.dumps(info),check_id))
    except Exception as exc:
        with sqlite3.connect(db_path,timeout=15) as db:
            db.execute("UPDATE intelligence_checks SET status='error',error=? WHERE id=?",(type(exc).__name__+': advisory operation failed; no complete query coverage is claimed',check_id))
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
