"""Timestamped public reference library. Feed text is data, never instructions.

This is retrieval and refresh, not LLM training or proof of project vulnerability.
All destinations are fixed official publisher endpoints; links in feeds are ignored.
"""
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from . import __version__
from .core import NoRedirect

SOURCES = {
    'kev': dict(name='CISA · Known exploited vulnerabilities',
        url='https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
        interval=3600, cap=8_000_000, kind='exploited_vulnerability'),
    'cve': dict(name='CVE Program · Recent disclosures',
        url='https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json',
        interval=300, cap=2_000_000, kind='vulnerability'),
    'attack': dict(name='MITRE ATT&CK · Enterprise techniques',
        url='https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
        interval=86400, cap=64_000_000, kind='attack_technique'),
}
CVE_ID = re.compile(r'CVE-\d{4}-\d{4,9}')
MAX_CVE_FETCH = 20


def now(): return dt.datetime.now(dt.timezone.utc).isoformat()


def plain(value, limit=4000):
    if not isinstance(value,str): raise ValueError('Expected feed text')
    text=html.unescape(re.sub(r'<[^>]*>', '', value))
    text=re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',text)
    return ''.join(c for c in text if c in '\n\t' or ord(c)>=32)[:limit]


def timestamp(value):
    if not isinstance(value,str) or len(value)>60: raise ValueError('Invalid source date')
    stamp=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None: stamp=stamp.replace(tzinfo=dt.timezone.utc)
    return stamp.astimezone(dt.timezone.utc).isoformat()


def record_revision(item):
    fields={key:item[key] for key in ('source','external_id','kind','title','summary','modified','reference','metadata')}
    if isinstance(fields['metadata'],str): fields['metadata']=json.loads(fields['metadata'])
    return hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def archive_record(db,item,fetched):
    item=dict(item); item['fetched']=fetched
    if not isinstance(item['metadata'],str): item['metadata']=json.dumps(item['metadata'])
    revision=record_revision(item); item['revision']=revision
    db.execute('INSERT OR IGNORE INTO knowledge_versions VALUES(?,?,?,?)',
               (item['source'],item['external_id'],revision,json.dumps(item)))
    return revision


def initialize(path):
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS knowledge_sources (
            source TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
            interval_seconds INTEGER NOT NULL, generation INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'never_refreshed', checked TEXT, succeeded TEXT,
            source_updated TEXT, next_run REAL NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
            etag TEXT NOT NULL DEFAULT '', revision TEXT NOT NULL DEFAULT '',
            coverage TEXT NOT NULL DEFAULT '', error_code TEXT NOT NULL DEFAULT '')''')
        db.execute('''CREATE TABLE IF NOT EXISTS knowledge_records (
            source TEXT NOT NULL, external_id TEXT NOT NULL, kind TEXT NOT NULL,
            title TEXT NOT NULL, summary TEXT NOT NULL, modified TEXT NOT NULL,
            reference TEXT NOT NULL, metadata TEXT NOT NULL, fetched TEXT NOT NULL,
            PRIMARY KEY(source,external_id))''')
        db.execute('CREATE INDEX IF NOT EXISTS knowledge_kind_date ON knowledge_records(kind,modified)')
        versions_existed=db.execute("SELECT 1 FROM sqlite_master WHERE name='knowledge_versions'").fetchone()
        db.execute('''CREATE TABLE IF NOT EXISTS knowledge_versions (
            source TEXT NOT NULL, external_id TEXT NOT NULL, revision TEXT NOT NULL, record TEXT NOT NULL,
            PRIMARY KEY(source,external_id,revision))''')
        if not versions_existed:
            columns=('source','external_id','kind','title','summary','modified','reference','metadata','fetched')
            for row in db.execute('SELECT * FROM knowledge_records').fetchall():
                item=dict(zip(columns,row)); archive_record(db,item,item['fetched'])
        db.execute('''CREATE TABLE IF NOT EXISTS knowledge_cve_queue (
            external_id TEXT PRIMARY KEY, delta_updated TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending')''')
        columns={r[1] for r in db.execute('PRAGMA table_info(knowledge_cve_queue)')}
        for name,definition in (('attempts','INTEGER NOT NULL DEFAULT 0'),('next_retry','REAL NOT NULL DEFAULT 0'),('last_error',"TEXT NOT NULL DEFAULT ''")):
            if name not in columns: db.execute(f'ALTER TABLE knowledge_cve_queue ADD COLUMN {name} {definition}')
        db.execute('CREATE INDEX IF NOT EXISTS cve_queue_state ON knowledge_cve_queue(state,delta_updated)')
        db.execute('''CREATE TABLE IF NOT EXISTS knowledge_audit (
            id INTEGER PRIMARY KEY, created TEXT NOT NULL, source TEXT NOT NULL,
            outcome TEXT NOT NULL, record_count INTEGER NOT NULL, revision TEXT NOT NULL,
            error_code TEXT NOT NULL DEFAULT '')''')
        for source,spec in SOURCES.items():
            db.execute('INSERT OR IGNORE INTO knowledge_sources(source,interval_seconds) VALUES(?,?)',(source,spec['interval']))


def cve_url(identifier):
    if not CVE_ID.fullmatch(identifier): raise ValueError('Invalid CVE ID')
    _,year,serial=identifier.split('-')
    return f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{int(serial)//1000}xxx/{identifier}.json'


def fetch_json(url,headers,cap,deadline=None,stop=None):
    allowed={s['url'] for s in SOURCES.values()}
    if url not in allowed:
        prefix='https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'
        if not url.startswith(prefix) or url != cve_url(url.rsplit('/',1)[-1].removesuffix('.json')):
            raise ValueError('Unapproved feed destination')
    req=urllib.request.Request(url,headers={'User-Agent':f'CyberLab/{__version__}', 'Accept':'application/json',**headers})
    opener=urllib.request.build_opener(NoRedirect)
    deadline=deadline or time.monotonic()+45
    try:
        with opener.open(req,timeout=8) as response:
            chunks=[]; size=0
            while True:
                if time.monotonic()>deadline or (stop and stop.is_set()): raise TimeoutError('Feed budget exhausted')
                chunk=response.read(min(65536,cap-size+1))
                if not chunk: break
                size+=len(chunk)
                if size>cap: raise ValueError('Feed response exceeds budget')
                chunks.append(chunk)
            raw=b''.join(chunks)
            return json.loads(raw),str(response.headers.get('ETag',''))[:200],hashlib.sha256(raw).hexdigest()
    except urllib.error.HTTPError as exc:
        if exc.code==304: return None,headers.get('If-None-Match',''),'not_modified'
        raise


def record(source,identifier,title,summary,modified,metadata):
    if not title: raise ValueError('Missing record title')
    reference = (f'https://attack.mitre.org/techniques/{identifier.replace(".","/")}/'
                 if source=='attack' else 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
                 if source=='kev' else f'https://www.cve.org/CVERecord?id={identifier}')
    return dict(source=source,external_id=identifier,kind=SOURCES[source]['kind'],title=plain(title,300),
                summary=plain(summary),modified=timestamp(modified),reference=reference,metadata=metadata)


def normalize_kev(data):
    if not isinstance(data,dict) or not isinstance(data.get('vulnerabilities'),list): raise ValueError('Invalid KEV catalog')
    items=data['vulnerabilities']
    if not 1<=len(items)<=10000 or data.get('count')!=len(items): raise ValueError('Invalid KEV count')
    updated=timestamp(data['dateReleased']); results=[]
    for item in items:
        identifier=item.get('cveID','')
        if not CVE_ID.fullmatch(identifier): raise ValueError('Invalid KEV identifier')
        results.append(record('kev',identifier,item['vulnerabilityName'],item['shortDescription'],item['dateAdded'],
            dict(known_exploited=True,vendor=plain(item.get('vendorProject',''),120),product=plain(item.get('product',''),120),
                 required_action=plain(item.get('requiredAction',''),1000),due_date=plain(item.get('dueDate',''),40),
                 applicability='Not established for your projects')))
    return results,updated,'Full publisher KEV catalog; known exploitation elsewhere does not prove your project is affected.'


def normalize_attack(data):
    if not isinstance(data,dict) or data.get('type')!='bundle' or not isinstance(data.get('objects'),list):
        raise ValueError('Invalid ATT&CK bundle')
    if len(data['objects'])>60000: raise ValueError('ATT&CK object budget exceeded')
    results=[]
    for item in data['objects']:
        if item.get('type')!='attack-pattern' or item.get('revoked') or item.get('x_mitre_deprecated'): continue
        refs=item.get('external_references',[])
        identifier=next((r.get('external_id','') for r in refs if r.get('source_name')=='mitre-attack'),'')
        if not re.fullmatch(r'T\d{4}(?:\.\d{3})?',identifier): raise ValueError('Invalid technique identifier')
        tactics=[plain(p.get('phase_name',''),80) for p in item.get('kill_chain_phases',[]) if p.get('kill_chain_name')=='mitre-attack'][:10]
        results.append(record('attack',identifier,item['name'],item.get('description',''),item['modified'],
            dict(tactics=tactics,applicability='Reference technique; not evidence of an attack on your machine')))
    if not results: raise ValueError('Empty technique catalog')
    return results,max(r['modified'] for r in results),'Full non-revoked, non-deprecated enterprise attack-pattern catalog. A technique catalog is not a live incident feed.'


def normalize_cve(data,identifier,delta_updated):
    meta=data.get('cveMetadata',{})
    if meta.get('cveId')!=identifier: raise ValueError('Mismatched CVE response')
    if meta.get('state')=='REJECTED': return None
    if meta.get('state')!='PUBLISHED': raise ValueError('Unsupported CVE state')
    cna=data.get('containers',{}).get('cna',{})
    descriptions=cna.get('descriptions',[])
    summary=next((d.get('value','') for d in descriptions if d.get('lang','').startswith('en')),'')
    if not summary: raise ValueError('Missing CVE description')
    affected=[]
    for item in cna.get('affected',[])[:10]:
        affected.append(dict(vendor=plain(item.get('vendor',''),120),product=plain(item.get('product',''),120)))
    return record('cve',identifier,cna.get('title') or identifier,summary,meta.get('dateUpdated') or meta['datePublished'],
                  dict(affected=affected,delta_updated=delta_updated,applicability='Not established for your projects'))


def load_source(path,source,headers,fetcher,deadline,stop):
    spec=SOURCES[source]
    data,etag,revision=fetcher(spec['url'],headers,spec['cap'],deadline,stop)
    if data is None and source!='cve': return None,etag,revision,'',''
    if source=='kev': records,updated,coverage=normalize_kev(data)
    elif source=='attack': records,updated,coverage=normalize_attack(data)
    else:
        candidates={}
        if data is not None:
            if not isinstance(data,dict) or not isinstance(data.get('new'),list) or not isinstance(data.get('updated'),list):
                raise ValueError('Invalid CVE delta')
            updated=timestamp(data['fetchTime'])
            items=data['new']+data['updated']
            if len(items)>10000: raise ValueError('CVE delta budget exceeded')
            for item in items:
                identifier=item.get('cveId','')
                if not CVE_ID.fullmatch(identifier): raise ValueError('Invalid delta identifier')
                stamp=timestamp(item['dateUpdated'])
                candidates[identifier]=max(candidates.get(identifier,''),stamp)
        else:
            with sqlite3.connect(path) as db:
                current=db.execute("SELECT source_updated,revision FROM knowledge_sources WHERE source='cve'").fetchone()
            if not current[1]: raise ValueError('Not-modified response without cache')
            updated=current[0]
        with sqlite3.connect(path,timeout=15) as db:
            for identifier,stamp in candidates.items():
                db.execute('''INSERT INTO knowledge_cve_queue(external_id,delta_updated) VALUES(?,?)
                    ON CONFLICT(external_id) DO UPDATE SET delta_updated=excluded.delta_updated,state='pending',attempts=0,next_retry=0,last_error=''
                    WHERE excluded.delta_updated>knowledge_cve_queue.delta_updated''',(identifier,stamp))
            count=db.execute("SELECT count(*) FROM knowledge_cve_queue WHERE state IN ('pending','retry')").fetchone()[0]
            if count>10000: raise ValueError('CVE backlog budget exceeded')
            pending=db.execute("SELECT external_id,delta_updated FROM knowledge_cve_queue WHERE state='pending' OR (state='retry' AND next_retry<=?) ORDER BY CASE state WHEN 'pending' THEN 0 ELSE 1 END,delta_updated DESC,external_id LIMIT ?",(time.time(),MAX_CVE_FETCH)).fetchall()
        records=[]
        for identifier,stamp in pending:
            if stop and stop.is_set(): raise TimeoutError('Refresh stopped')
            try:
                doc,_,_=fetcher(cve_url(identifier),{},256000,deadline,stop)
                row=normalize_cve(doc,identifier,stamp)
                records.append(row or dict(source='cve',external_id=identifier,rejected=True,delta_updated=stamp))
            except Exception as exc:
                if stop and stop.is_set(): raise TimeoutError('Refresh stopped')
                code='network_unavailable' if isinstance(exc,(OSError,TimeoutError,urllib.error.URLError)) else 'record_invalid'
                records.append(dict(source='cve',external_id=identifier,delta_updated=stamp,failed=code))
        if revision=='not_modified': revision=hashlib.sha256(json.dumps(records,sort_keys=True).encode()).hexdigest()
        coverage=(f'Recent publisher windows only: {len(records)} queued records processed in this refresh; '
                  f'{max(0,count-len(records))} observed records still queued. '
                  'Not a historical CVE mirror; unobserved deltas can be missed while offline or between polling windows.')
    keys=[r['external_id'] for r in records]
    if len(keys)!=len(set(keys)): raise ValueError('Duplicate source identifiers')
    return records,etag,revision,updated,coverage


def retry_failed(path):
    initialize(path)
    with sqlite3.connect(path,timeout=15) as db:
        db.execute("UPDATE knowledge_cve_queue SET state='pending',attempts=0,next_retry=0,last_error='' WHERE state IN ('retry','quarantined')")
        db.execute("UPDATE knowledge_sources SET generation=generation+1,next_run=0 WHERE source='cve'")


def configure(path,source,enabled,interval):
    if source not in SOURCES or type(interval) is not int or not 300<=interval<=604800:
        raise ValueError('Choose a source and an interval between 5 minutes and 7 days')
    initialize(path)
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('UPDATE knowledge_sources SET enabled=?,interval_seconds=?,generation=generation+1,next_run=0 WHERE source=?',
                   (int(enabled),interval,source))


def refresh(path,source,manual=False,fetcher=fetch_json,stop=None):
    if source not in SOURCES: raise ValueError('Unknown intelligence source')
    initialize(path)
    with sqlite3.connect(path,timeout=15) as db:
        db.row_factory=sqlite3.Row; db.execute('BEGIN IMMEDIATE')
        row=dict(db.execute('SELECT * FROM knowledge_sources WHERE source=?',(source,)).fetchone())
        if row['lease_until']>time.time(): return 'busy'
        if not manual and (not row['enabled'] or row['next_run']>time.time()): return 'not_due'
        db.execute("UPDATE knowledge_sources SET state='refreshing',lease_until=? WHERE source=?",(time.time()+90,source))
    headers={'If-None-Match':row['etag']} if row['etag'] else {}
    checked=now(); records=None; state='error'; error_code=''; revision=row['revision']
    try:
        records,etag,digest,updated,coverage=load_source(path,source,headers,fetcher,time.monotonic()+45,stop)
        if records is None:
            if not row['revision']: raise ValueError('Not-modified response without a cached revision')
            state='unchanged'
            etag=row['etag']; updated=row['source_updated']; coverage=row['coverage']
        else:
            state='updated'; revision=digest
    except (OSError,TimeoutError,urllib.error.URLError): error_code='network_unavailable'
    except (ValueError,KeyError,TypeError,AttributeError): error_code='source_invalid'
    except Exception: error_code='refresh_failed'
    with sqlite3.connect(path,timeout=15) as db:
        db.execute('BEGIN IMMEDIATE')
        generation=db.execute('SELECT generation FROM knowledge_sources WHERE source=?',(source,)).fetchone()[0]
        if generation!=row['generation']:
            db.execute("UPDATE knowledge_sources SET state='cancelled',lease_until=0 WHERE source=?",(source,))
            return 'cancelled'
        count=0
        if state in ('updated','unchanged'):
            if source=='cve' and records is not None:
                for item in records:
                    stamp=item.get('delta_updated') or item.get('metadata',{}).get('delta_updated')
                    if item.get('failed'):
                        db.execute("""UPDATE knowledge_cve_queue SET attempts=attempts+1,
                            state=CASE WHEN attempts>=2 THEN 'quarantined' ELSE 'retry' END,
                            next_retry=?,last_error=? WHERE external_id=? AND delta_updated=?""",
                            (time.time()+min(3600,300*2**min(3,db.execute('SELECT attempts FROM knowledge_cve_queue WHERE external_id=?',(item['external_id'],)).fetchone()[0])),item['failed'],item['external_id'],stamp))
                        continue
                    db.execute("UPDATE knowledge_cve_queue SET attempts=0,next_retry=0,last_error='',state='done' WHERE external_id=? AND delta_updated=?",(item['external_id'],stamp))
                db.execute("DELETE FROM knowledge_cve_queue WHERE state='done' AND external_id NOT IN (SELECT external_id FROM knowledge_cve_queue ORDER BY delta_updated DESC LIMIT 10000)")
            if records is not None:
                if source in ('kev','attack'): db.execute('DELETE FROM knowledge_records WHERE source=?',(source,))
                for item in records:
                    if item.get('failed'): continue
                    if item.get('rejected'):
                        db.execute('DELETE FROM knowledge_records WHERE source=? AND external_id=?',(source,item['external_id'])); continue
                    archive_record(db,item,checked)
                    db.execute('''INSERT INTO knowledge_records VALUES(?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(source,external_id) DO UPDATE SET kind=excluded.kind,title=excluded.title,
                        summary=excluded.summary,modified=excluded.modified,reference=excluded.reference,
                        metadata=excluded.metadata,fetched=excluded.fetched''',
                        (source,item['external_id'],item['kind'],item['title'],item['summary'],item['modified'],item['reference'],json.dumps(item['metadata']),checked))
            if source=='cve':
                outstanding=db.execute("SELECT count(*) FROM knowledge_cve_queue WHERE state IN ('retry','quarantined')").fetchone()[0]
                if outstanding:
                    state='partial'; error_code='cve_records_incomplete'
                pending_count=db.execute("SELECT count(*) FROM knowledge_cve_queue WHERE state IN ('pending','retry')").fetchone()[0]
                blocked=db.execute("SELECT count(*) FROM knowledge_cve_queue WHERE state='quarantined'").fetchone()[0]
                coverage=f'Recent publisher windows only: {pending_count} queued; {blocked} quarantined. Individual failures retain prior good records. Not a historical CVE mirror; offline or polling gaps can miss deltas.'
            count=db.execute('SELECT count(*) FROM knowledge_records WHERE source=?',(source,)).fetchone()[0]
            db.execute('''UPDATE knowledge_sources SET succeeded=?,source_updated=?,etag=?,revision=?,coverage=? WHERE source=?''',
                       (checked,updated,etag,revision,coverage,source))
        db.execute('''UPDATE knowledge_sources SET state=?,checked=?,next_run=?,lease_until=0,error_code=? WHERE source=?''',
                   (state,checked,time.time()+(row['interval_seconds'] if state!='error' else 300),error_code,source))
        db.execute('INSERT INTO knowledge_audit(created,source,outcome,record_count,revision,error_code) VALUES(?,?,?,?,?,?)',
                   (checked,source,state,count,revision,error_code))
        db.execute('DELETE FROM knowledge_audit WHERE id NOT IN (SELECT id FROM knowledge_audit ORDER BY id DESC LIMIT 1000)')
    return state


def status(path):
    initialize(path)
    with sqlite3.connect(path) as db:
        db.row_factory=sqlite3.Row
        rows=[dict(r) for r in db.execute('''SELECT s.*,(SELECT count(*) FROM knowledge_records r WHERE r.source=s.source) AS record_count,
                CASE WHEN s.source='cve' THEN (SELECT count(*) FROM knowledge_cve_queue WHERE state IN ('pending','retry')) ELSE 0 END AS pending_records,
                CASE WHEN s.source='cve' THEN (SELECT count(*) FROM knowledge_cve_queue WHERE state='quarantined') ELSE 0 END AS blocked_records
                                          FROM knowledge_sources s ORDER BY s.source''')]
    for row in rows:
        row['name']=SOURCES[row['source']]['name']
        row['stale']=not row['succeeded'] or dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(row['succeeded'])>dt.timedelta(seconds=max(2*row['interval_seconds'],3600))
    return rows


def search(path,query='',kind='',limit=50,offset=0):
    if type(offset) is not int or not 0<=offset<=100000: raise ValueError('Invalid knowledge page')
    if len(query)>200 or kind not in ('','exploited_vulnerability','vulnerability','attack_technique'): raise ValueError('Invalid knowledge search')
    initialize(path)
    pattern='%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%'
    with sqlite3.connect(path) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute('''SELECT * FROM knowledge_records
            WHERE (?='' OR kind=?) AND (external_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')
            ORDER BY modified DESC,external_id LIMIT ? OFFSET ?''',(kind,kind,pattern,pattern,pattern,min(limit,100),offset))]


def detail(path,source,identifier,revision=''):
    if source not in SOURCES: return None
    initialize(path)
    with sqlite3.connect(path) as db:
        db.row_factory=sqlite3.Row
        if revision:
            if not re.fullmatch(r'[a-f0-9]{64}',revision): return None
            row=db.execute('SELECT record FROM knowledge_versions WHERE source=? AND external_id=? AND revision=?',(source,identifier,revision)).fetchone()
            if not row: return None
            result=json.loads(row['record']); result['archived_snapshot']=True
            return result
        row=db.execute('SELECT * FROM knowledge_records WHERE source=? AND external_id=?',(source,identifier)).fetchone()
        if not row: return None
        result=dict(row); result['revision']=record_revision(result)
        return result


def project_context(path,project_root):
    """Retrieve only CVEs linked through a root-proven package advisory check."""
    initialize(path)
    with sqlite3.connect(path) as db:
        if 'project_root' not in {r[1] for r in db.execute('PRAGMA table_info(intelligence_checks)')}: return []
        rows=db.execute('''SELECT m.advisory_id,a.aliases FROM intelligence_matches m
            JOIN intelligence_checks c ON c.id=m.check_id LEFT JOIN advisories a ON a.id=m.advisory_id
            WHERE c.project_root=? AND c.status='completed' ORDER BY c.id DESC LIMIT 100''',(str(Path(project_root).resolve()),)).fetchall()
    identifiers=set()
    for identifier,aliases in rows:
        if CVE_ID.fullmatch(identifier): identifiers.add(identifier)
        try:
            values=json.loads(aliases or '[]')
            if isinstance(values,list): identifiers.update(x for x in values[:20] if isinstance(x,str) and CVE_ID.fullmatch(x))
        except (ValueError,TypeError): pass
    states={r['source']:r for r in status(path)}
    results=[]
    for identifier in sorted(identifiers)[:30]:
        for source in ('kev','cve'):
            row=detail(path,source,identifier)
            if row:
                results.append(dict(id=f'knowledge:{source}:{identifier}:{row["revision"]}',kind='public_advisory',title=row['title'],
                    summary=row['summary'][:700],reference=row['reference'],modified=row['modified'],fetched=row['fetched'],
                    source_cache_stale=states[source]['stale'],last_source_check=states[source]['succeeded'],
                    applicability='Linked by a package advisory alias; project exploitability NOT established'))
            if len(results)>=5: return results
    return results


class Refresher:
    def __init__(self,path):
        initialize(path); self.path=path; self.stop_event=threading.Event(); self.thread=None

    def start(self):
        if self.thread and self.thread.is_alive(): return
        def loop():
            while not self.stop_event.is_set():
                for source in SOURCES:
                    if self.stop_event.is_set(): break
                    try: refresh(self.path,source,stop=self.stop_event)
                    except sqlite3.Error: pass
                self.stop_event.wait(10)
        self.thread=threading.Thread(target=loop,name='cyberlab-intelligence',daemon=True); self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=20)
