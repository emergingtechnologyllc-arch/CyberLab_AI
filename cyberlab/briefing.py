"""Evidence-linked project briefing. Unknown coverage never means zero risk."""
import json
from pathlib import Path
import sqlite3
from . import dependencies, identity, knowledge


def build(path,project,base):
    identifier=identity.register(path,project)
    facts=identity.passport(path,project)
    items=[]
    try:
        inventory=dependencies.inventory(project,base)
        fingerprint=dependencies.fingerprint(inventory)
    except (ValueError,OSError):
        inventory=None; fingerprint=None
    with sqlite3.connect(path) as db:
        db.row_factory=sqlite3.Row
        check=db.execute('SELECT * FROM intelligence_checks WHERE project_id=? ORDER BY id DESC LIMIT 1',(identifier,)).fetchone()
        changes=db.execute('''SELECT c.id,c.status FROM change_investigations c JOIN continuous_runs r ON r.id=c.assessment_id
            WHERE r.project_id=? AND c.status!='completed' ORDER BY c.id DESC LIMIT 5''',(identifier,)).fetchall()
        for change in changes:
            items.append(dict(title='Route change review',detail='Review #'+str(change['id'])+': '+change['status']+'. Filename changes do not establish a vulnerability.',href='/changes/'+str(change['id'])))
        if not check:
            items.append(dict(title='Dependencies have not been checked',detail='No advisory check belongs to this project identity. Coverage is unknown.',href='/intelligence'))
        else:
            current=bool(fingerprint and check['snapshot_hash']==fingerprint and check['status']=='completed')
            try: coverage=json.loads(check['coverage'] or '{}')
            except ValueError: coverage={}
            queried=coverage.get('queried_components',0)
            total=coverage.get('inventory_components',check['package_count'] or 0)
            detail=f'Check #{check["id"]}: {check["status"]}; {queried}/{total} components queried; {check["match_count"] or 0} candidate matches. '
            detail+=('Matches require review; deployed applicability is unverified.' if current else 'Snapshot is stale, incomplete, or from a legacy check. Run a new check.')
            items.append(dict(title='Current dependency coverage' if current else 'Dependency check needs attention',detail=detail,href='/intelligence/'+str(check['id'])))
            if current:
                aliases=set()
                for row in db.execute('''SELECT a.aliases,m.advisory_id FROM intelligence_matches m LEFT JOIN advisories a ON a.id=m.advisory_id WHERE m.check_id=?''',(check['id'],)):
                    aliases.add(row['advisory_id'])
                    try: values=json.loads(row['aliases'] or '[]')
                    except ValueError: values=[]
                    aliases.update(v for v in values if isinstance(v,str))
                for row in db.execute("SELECT external_id FROM knowledge_records WHERE source='kev'"):
                    if row[0] in aliases:
                        items.append(dict(title='Known exploitation reference: '+row[0],detail='CISA lists exploitation in the wild. Your project has a linked advisory candidate; exploitability here is unverified.',href='/knowledge/kev/'+row[0]))
                        if len(items)>=12: break
    sources=knowledge.status(path)
    attention=sum(s['stale'] or s['state'] in ('error','partial') for s in sources)
    if attention: items.append(dict(title='Intelligence coverage needs attention',detail=f'{attention} sources are stale, incomplete, or unavailable. Cached references remain available.',href='/intelligence'))
    return dict(passport=facts,inventory=inventory,items=items,limitation='This briefing summarizes saved evidence when opened. It is not continuous detection or a security clearance.')
