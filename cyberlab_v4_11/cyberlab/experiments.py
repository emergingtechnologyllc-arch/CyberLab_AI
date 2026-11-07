"""v4.5 bounded, offline, synthetic authorization experiments.

A fixture contains two synthetic accounts and their expected resource ownership.
This is a demonstration of evidence verification, NOT a test of a real endpoint.
"""
import datetime as dt
import json
from pathlib import Path
import sqlite3
from .behavior import inventory

MAX_FIXTURE = 32768
MAX_CASES = 25


def initialize(db_path):
    with sqlite3.connect(db_path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS experiment_runs
            (id INTEGER PRIMARY KEY, created TEXT, project TEXT, status TEXT, summary TEXT)''')
        db.execute('''CREATE TABLE IF NOT EXISTS experiment_events
            (id INTEGER PRIMARY KEY, run_id INTEGER, kind TEXT, payload TEXT)''')


def record(db_path, rid, kind, data):
    with sqlite3.connect(db_path) as db:
        db.execute('INSERT INTO experiment_events(run_id,kind,payload) VALUES(?,?,?)',
                   (rid,kind,json.dumps(data,ensure_ascii=False)[:12000]))


def validate_fixture(project, base):
    root = Path(project).resolve(strict=True)
    allowed = Path(base).resolve(strict=True)
    if not root.is_dir() or not root.is_relative_to(allowed):
        raise ValueError('Project outside approved root')
    fixture = root / 'cyberlab-test-fixture.json'
    if fixture.is_symlink() or not fixture.is_file() or fixture.stat().st_size > MAX_FIXTURE:
        raise ValueError('Missing, symlinked, or oversized cyberlab-test-fixture.json')
    data = json.loads(fixture.read_text(encoding='utf-8'))
    if not isinstance(data,dict) or data.get('schema_version') != 1:
        raise ValueError('Fixture must be a version 1 object')
    cases = data.get('cases')
    if not isinstance(cases,list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError('Fixture must contain 1–25 cases')
    routes = {r['route'] for r in inventory(project,base)}
    for case in cases:
        if not isinstance(case,dict) or set(case) != {'route','requester','owner','observed_status','expected_status'}:
            raise ValueError('Invalid case fields')
        if case['route'] not in routes:
            raise ValueError('Case route not in discovered inventory')
        if any(not isinstance(case[k],str) or not 1 <= len(case[k]) <= 64 for k in ('requester','owner')):
            raise ValueError('Invalid synthetic account labels')
        if type(case['observed_status']) is not int or type(case['expected_status']) is not int:
            raise ValueError('Statuses must be integers')
        if case['observed_status'] not in (200,401,403,404) or case['expected_status'] not in (200,401,403,404):
            raise ValueError('Only bounded HTTP status categories supported')
    return cases


def verify_case(case):
    """Classify simulated evidence; never confirm a real vulnerability."""
    requester, owner = case['requester'],case['owner']
    observed, expected = case['observed_status'],case['expected_status']
    if requester != owner and observed == 200 and expected in (401,403,404):
        label = 'simulated_authorization_mismatch'
    elif observed != expected:
        label = 'simulated_behavior_mismatch'
    else:
        label = 'simulated_expected_behavior'
    return {'route':case['route'],'requester':requester,'owner':owner,
            'observed_status':observed,'expected_status':expected,'classification':label,
            'verification':'fixture_only_not_live','confirmed_vulnerability':False}


def run(db_path, project, base):
    initialize(db_path)
    cases = validate_fixture(project,base)
    with sqlite3.connect(db_path) as db:
        rid = db.execute('INSERT INTO experiment_runs(created,project,status,summary) VALUES(?,?,?,?)',
                         (dt.datetime.now(dt.timezone.utc).isoformat(),Path(project).name,'running','')).lastrowid
    record(db_path,rid,'experiment_scope',{'mode':'offline_synthetic_fixture','network_requests':0,'case_count':len(cases)})
    mismatches = 0
    for case in cases:
        outcome = verify_case(case)
        mismatches += outcome['classification'] != 'simulated_expected_behavior'
        record(db_path,rid,'synthetic_verification',outcome)
    summary = f'{len(cases)} synthetic cases evaluated; {mismatches} simulated mismatches; 0 real vulnerabilities confirmed.'
    with sqlite3.connect(db_path) as db:
        db.execute('UPDATE experiment_runs SET status=?,summary=? WHERE id=?',('completed',summary,rid))
    return rid


def recent(db_path):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        return [dict(r) for r in db.execute('SELECT * FROM experiment_runs ORDER BY id DESC LIMIT 20')]


def detail(db_path,rid):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM experiment_runs WHERE id=?',(rid,)).fetchone()
        if row is None:return None
        events=[dict(e) for e in db.execute('SELECT * FROM experiment_events WHERE run_id=? ORDER BY id',(rid,))]
    return dict(row),events
