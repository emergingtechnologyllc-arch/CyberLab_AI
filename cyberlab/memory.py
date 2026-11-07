"""read-only evidence memory and conservative cross-run correlation.

Records are references to existing events; no vulnerability is confirmed by correlation.
"""
import datetime as dt
import json
import sqlite3

MAX_EVENTS = 300
MAX_CONTEXT = 12


def initialize(db_path):
    with sqlite3.connect(db_path) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS memory_snapshots
            (id INTEGER PRIMARY KEY, created TEXT, project TEXT, status TEXT, summary TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS memory_links
            (snapshot_id INTEGER, route TEXT, relation TEXT, left_source TEXT,
             left_event INTEGER, right_source TEXT, right_event INTEGER,
             interpretation TEXT, PRIMARY KEY(snapshot_id,route,left_source,left_event,right_source,right_event))""")


def _records(db, table, event_table, project, kind, limit=MAX_EVENTS):
    # Explicit table identifiers are constants, never supplied by a user.
    return db.execute(f"""SELECT e.id, e.kind, e.payload FROM {event_table} e
        JOIN {table} r ON r.id=e.run_id WHERE r.project=? AND r.status='completed'
        ORDER BY e.id DESC LIMIT ?""", (project, limit)).fetchall()


def collect(db_path, project):
    """Return minimal evidence references and classifications; never store raw responses."""
    if not isinstance(project,str) or not project or len(project)>128 or '/' in project or '\\' in project:
        raise ValueError('Provide a single project folder name')
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        sources=(('ai_behavior_runs','ai_behavior_events','ai'),
                 ('live_runs','live_events','live'),
                 ('experiment_runs','experiment_events','fixture'))
        records=[]
        for runs, events, source in sources:
            for row in _records(db,runs,events,project,source):
                if (source=='ai' and row['kind']!='hypothesis') or (source=='live' and row['kind']!='live_observation') or (source=='fixture' and row['kind']!='synthetic_verification'):
                    continue
                try:
                    payload=json.loads(row['payload'])
                except (ValueError,TypeError):
                    continue
                route=payload.get('route')
                if not isinstance(route,str) or not route.startswith('/') or len(route)>200:
                    continue
                records.append({'source':source,'event_id':row['id'],'route':route,
                                'kind':row['kind'],
                                'classification':('unverified_hypothesis' if source=='ai' else str(payload.get('classification','unknown'))[:80]),
                                'expected_status':payload.get('expected_status') if source!='ai' else None,
                                'observed_status':payload.get('status',payload.get('observed_status')) if source!='ai' else None})
    return records


def correlate(records):
    """Only exact route matches; relationships are investigatory, not causal."""
    hypotheses={}
    observations={}
    for record in records:
        if record['source']=='ai': hypotheses.setdefault(record['route'],[]).append(record)
        elif record['source']=='live': observations.setdefault(record['route'],[]).append(record)
    links=[]
    for route in sorted(hypotheses.keys() & observations.keys()):
        for h in hypotheses[route][:3]:
            for o in observations[route][:3]:
                links.append({'route':route,'relation':'hypothesis_and_local_observation',
                    'left_source':'ai','left_event':h['event_id'],
                    'right_source':'live','right_event':o['event_id'],
                    'interpretation':'Same route was hypothesized and tested locally; verify access policy and test conditions independently.'})
    return links[:100]


def snapshot(db_path, project):
    initialize(db_path)
    records=collect(db_path,project)
    links=correlate(records)
    created=dt.datetime.now(dt.timezone.utc).isoformat()
    summary=f'{len(records)} evidence references; {len(links)} route-level correlations; zero vulnerabilities confirmed by memory.'
    with sqlite3.connect(db_path) as db:
        with db:
            rid=db.execute('INSERT INTO memory_snapshots(created,project,status,summary) VALUES(?,?,?,?)',
                           (created,project,'completed',summary)).lastrowid
            db.executemany('INSERT INTO memory_links VALUES(?,?,?,?,?,?,?,?)',
                [(rid,x['route'],x['relation'],x['left_source'],x['left_event'],x['right_source'],x['right_event'],x['interpretation']) for x in links])
    return rid


def recent(db_path):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute('SELECT * FROM memory_snapshots ORDER BY id DESC LIMIT 20')]


def detail(db_path, rid):
    initialize(db_path)
    with sqlite3.connect(db_path) as db:
        db.row_factory=sqlite3.Row
        row=db.execute('SELECT * FROM memory_snapshots WHERE id=?',(rid,)).fetchone()
        if row is None:return None
        links=[dict(r) for r in db.execute('SELECT * FROM memory_links WHERE snapshot_id=? ORDER BY route LIMIT 100',(rid,))]
    return dict(row),links


def ai_context(db_path, project):
    """Bounded prior evidence for the model, no raw payloads or secrets."""
    records=collect(db_path,project)
    return [{'route':r['route'],'source':r['source'],'event_id':r['event_id'],
             'classification':r['classification']} for r in records[:MAX_CONTEXT]]
