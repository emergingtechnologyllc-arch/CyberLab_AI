"""Root-scoped, minimal evidence summaries. Never infer roots for legacy records."""
import json
from pathlib import Path
import sqlite3
from . import identity

SOURCES = (('ai_behavior_runs', 'ai_behavior_events', 'ai_event', 'hypothesis'),
           ('live_runs', 'live_events', 'live_event', 'live_observation'))


def migrate(db, table):
    identity.migrate(db,table)


def summaries(path, project_root, patterns, before=None):
    """Read at most 300 candidates/source and return at most 12 safe references.

    Classification is recomputed from bounded integer status codes, never model
    text. Raw responses, hypotheses, account labels and filenames are excluded.
    """
    from .change_investigation import match_route
    root = str(Path(project_root).resolve())
    result = []
    with sqlite3.connect(path) as db:
        for runs, events, source, kind in SOURCES:
            columns = {r[1] for r in db.execute(f'PRAGMA table_info({runs})')}
            if 'project_root' not in columns:
                continue
            rows = db.execute(f'''SELECT e.id,r.id,e.payload FROM {events} e
                JOIN {runs} r ON r.id=e.run_id WHERE r.project_root=?
                AND r.status='completed' AND e.kind=? AND (? IS NULL OR r.created<=?)
                ORDER BY e.id DESC LIMIT 300''', (root,kind,before,before)).fetchall()
            for eid, rid, encoded in rows:
                try:
                    if len(encoded) > 16384:
                        continue
                    payload = json.loads(encoded)
                    if not isinstance(payload, dict):
                        continue
                    raw = payload.get('path', payload.get('route')) if source == 'live_event' else payload.get('route')
                    match = match_route(raw, patterns)
                    if match is None:
                        continue
                    item = {'id': f'{source}:{eid}', 'run_id': rid,
                            'kind': kind, **match, 'confirmed_vulnerability': False}
                    if source == 'ai_event':
                        item['classification'] = 'unverified_hypothesis'
                    else:
                        observed, expected = payload.get('status'), payload.get('expected_status')
                        if type(observed) is not int or not 100 <= observed <= 599:
                            continue
                        if type(expected) is not int or expected not in (200,401,403,404):
                            continue
                        item.update(observed_status=observed, expected_status=expected,
                                    classification='observed_status_match' if observed == expected else 'observed_status_mismatch')
                    result.append(item)
                except (ValueError, TypeError):
                    continue
    # Reserve room for actual local observations as well as hypotheses.
    ai = [r for r in result if r['kind'] == 'hypothesis'][:6]
    live = [r for r in result if r['kind'] == 'live_observation'][:6]
    return ai + live
