"""Loopback-only dashboard. No third-party dependencies."""
import html
import json
import os
from pathlib import Path
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit
from . import change_investigation as changes, monitor
from .continuous import initialize as init_continuous, assess as continuous_assess, recent as continuous_recent, detail as continuous_detail
from .memory import initialize as init_memory, snapshot as memory_snapshot, recent as memory_recent, detail as memory_detail
from .risk import initialize as init_risk, analyze as risk_analyze, recent as risk_recent, detail as risk_detail
from .live_experiments import initialize as init_live, run as live_run, recent as live_recent, detail as live_detail, validate_plan
from .experiments import initialize as init_experiments, run as experiment_run, recent as experiment_recent, detail as experiment_detail, validate_fixture
from .core import init_db, investigate, get_run
from .ai_behavior import initialize as init_ai_behavior, run as ai_behavior_run, recent as ai_behavior_recent, detail as ai_behavior_detail
from .intelligence import initialize as init_intel, check_project, recent_checks, check_detail
from .behavior import init_behavior, check_project as behavior_check, recent_checks as behavior_recent, detail as behavior_detail, inventory as behavior_inventory

ROOT = Path(os.getenv('CYBERLAB_DATA_DIR', str(Path.home() / '.cyberlab-v4')))
ROOT.mkdir(mode=0o700, exist_ok=True)
DB = str(ROOT / 'investigations.sqlite3')
PROJECTS = Path(os.getenv('CYBERLAB_PROJECTS_DIR', str(Path.home() / 'CyberLab-Projects'))).resolve()
PROJECTS.mkdir(mode=0o700, parents=True, exist_ok=True)
TOKEN = secrets.token_urlsafe(32)
init_db(DB)
init_intel(DB)
init_behavior(DB)
init_ai_behavior(DB)
init_experiments(DB)
init_live(DB)
init_memory(DB)
init_risk(DB)
init_continuous(DB)
monitor.initialize(DB)


def esc(x):
    return html.escape(str(x), quote=True)


def page(content):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>CyberLab AI v4.11</title><style>body{font:16px system-ui;max-width:950px;margin:3rem auto;padding:0 1rem;background:#101827;color:#e7eefc}'
            'a{color:#82cfff}input,button{padding:.7rem;margin:.35rem 0;border-radius:6px}input{width:min(90%,600px)}button{cursor:pointer}'
            'section{background:#1e2b3e;border-radius:12px;padding:1.2rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}'
            '.muted{color:#aebdd2}.event{border-top:1px solid #45576a;padding:.6rem 0}</style></head><body><h1>CyberLab AI v4.11</h1>'
            '<p class="muted">Local AI investigation · Evidence first · No automatic vulnerability confirmation</p>' + content + '</body></html>').encode()


class Handler(BaseHTTPRequestHandler):
    def send_html(self, body, status=200):
        self.send_response(status)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.send_html(page('<p>Invalid local Host</p>'),400)
            return False
        return True

    def do_GET(self):
        if not self.valid_host(): return
        p = urlsplit(self.path).path
        if p == '/':
            with sqlite3.connect(DB) as db:
                rows = db.execute('SELECT id,created,status FROM runs ORDER BY id DESC LIMIT 30').fetchall()
            checks = recent_checks(DB)
            behavior_checks = behavior_recent(DB)
            ai_checks = ai_behavior_recent(DB)
            experiment_checks = experiment_recent(DB)
            live_checks = live_recent(DB)
            memory_checks = memory_recent(DB)
            risk_checks = risk_recent(DB)
            continuous_checks = continuous_recent(DB)
            continuous_items = ''.join(f'<li><a href="/continuous/{r["id"]}">Assessment #{r["id"]}</a> — {esc(r["project"])} — {esc(r["summary"])}</li>' for r in continuous_checks)
            risk_items = ''.join(f'<li><a href="/risk/{r["id"]}">Risk analysis #{r["id"]}</a> — {esc(r["project"])} — {esc(r["summary"])}</li>' for r in risk_checks)
            memory_items = ''.join(f'<li><a href="/memory/{c["id"]}">Memory #{c["id"]}</a> — {esc(c["project"])} — {esc(c["summary"])}</li>' for c in memory_checks)
            live_items = ''.join(f'<li><a href="/live/{c["id"]}">Local test #{c["id"]}</a> — {esc(c["project"])} — {esc(c["status"])}</li>' for c in live_checks)
            experiment_items = ''.join(f'<li><a href="/experiments/{c["id"]}">Experiment #{c["id"]}</a> — {esc(c["project"])} — {esc(c["status"])}</li>' for c in experiment_checks)
            intel_items = ''.join(f'<li><a href="/intelligence/{c["id"]}">Check #{c["id"]}</a> — {esc(c["project"])} — {esc(c["status"])} — {c["match_count"]} candidate advisory matches</li>' for c in checks)
            ai_items = ''.join(f'<li><a href="/ai-behavior/{c["id"]}">AI investigation #{c["id"]}</a> — {esc(c["project"])} — {esc(c["status"])}</li>' for c in ai_checks)
            behavior_items = ''.join(f'<li><a href="/behavior/{c["id"]}">Inventory #{c["id"]}</a> — {esc(c["project"])} — {esc(c["status"])} — {c["route_count"]} routes</li>' for c in behavior_checks)
            items = ''.join(f'<li><a href="/runs/{rid}">Run #{rid}</a> — {esc(status)} — {esc(created)}</li>' for rid,created,status in rows)
            change_items = ''.join(f'<li><a href="/changes/{r["id"]}">Recommendation #{r["id"]}</a> — {esc(r["status"])}</li>' for r in changes.recent(DB))
            monitor_items = ''.join(f'<li>{esc(Path(r["project_root"]).name)} — {"running" if r["enabled"] else "paused"} — {esc(r["status"])} — last assessment {esc(r["last_assessment"])}</li>' for r in monitor.settings(DB))
            new_section = (f'<section><h2>Change investigations (v4.11)</h2><p>Filename changes produce read-only recommendations. AI text never executes actions or confirms a vulnerability.</p><ul>{change_items or "<li>No changes awaiting review</li>"}</ul></section>'
                f'<section><h2>Scheduled project monitoring</h2><p>Runs only while CyberLab is running. Pausing stops future assessments; an in-flight assessment may finish.</p><ul>{monitor_items or "<li>Monitoring is off</li>"}</ul>'
                f'<form method="post" action="/monitor/configure"><input type="hidden" name="csrf" value="{TOKEN}">'
                '<p><input name="project" placeholder="demo" required></p><p>Interval (seconds): <input name="interval" type="number" min="30" max="86400" value="300" required></p>'
                '<p><label><input style="width:auto" type="checkbox" name="enabled" value="yes"> Enable/resume monitoring (uncheck to pause)</label></p>'
                '<p><label><input style="width:auto" type="checkbox" name="use_ai" value="yes"> Opt in to scheduled Ollama analysis of new changes</label></p>'
                '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I authorize monitoring of this project</label></p><button>Save monitoring settings</button></form></section>')
            body = (new_section + f'<section><h2>Continuous project change assessment (v4.11)</h2><p>Run a repeatable, local-only API route inventory. Compare with the previous snapshot for this project. No automatic scanning or vulnerability confirmation.</p>'
                    f'<form method="post" action="/continuous/assess"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I authorize assessment of this local project</label></p>'
                    '<button type="submit">Assess project changes</button></form>'
                    f'<ul>{continuous_items or "<li>No change assessments yet</li>"}</ul></section>'
                    f'<section><h2>Relationship and risk analysis (v4.8)</h2><p>Correlates evidence by exact route. Mismatches are review indicators, not confirmed vulnerabilities. Optional Ollama commentary cannot modify evidence.</p>'
                    f'<form method="post" action="/risk/analyze"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="use_ai" value="yes"> Ask Ollama to summarize investigation priorities</label></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I am authorized to analyze this project evidence</label></p>'
                    '<button type="submit">Analyze evidence relationships</button></form>'
                    f'<ul>{risk_items or "<li>No risk analyses yet</li>"}</ul></section>'
                    f'<section><h2>Investigation memory and evidence correlation (v4.7)</h2><p>Link AI hypotheses and local observations by exact route. Correlation does not confirm vulnerabilities.</p>'
                    f'<form method="post" action="/memory/build"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I am authorized to analyze this project history</label></p>'
                    '<button type="submit">Build evidence memory</button></form>'
                    f'<ul>{memory_items or "<li>No memory snapshots yet</li>"}</ul></section>'
                    f'<section><h2>Controlled localhost verification (v4.6)</h2><p>Only approved local GET routes, synthetic test-account labels, no credentials, no redirects. Observed mismatches are not automatically confirmed vulnerabilities.</p>'
                    f'<form method="post" action="/live/check"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I own this localhost test application and authorize the GET checks</label></p>'
                    '<button type="submit">Run localhost verification</button></form>'
                    f'<ul>{live_items or "<li>No localhost tests yet</li>"}</ul></section>'
                    f'<section><h2>Safe experiment runner (v4.6)</h2><p>Offline, synthetic authorization fixture only. No live requests or confirmed vulnerabilities.</p>'
                    f'<form method="post" action="/experiments/check"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<label>Project folder</label><p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I am authorized to inspect this synthetic project</label></p>'
                    '<button type="submit">Run synthetic verification</button></form>'
                    f'<ul>{experiment_items or "<li>No experiments yet</li>"}</ul></section>'
                    f'<section><h2>Start a bounded investigation</h2><p>Only loopback HTTP targets are allowed, e.g. http://127.0.0.1:3000/ . '
                    f'Project paths must be inside <code>{esc(PROJECTS)}</code>.</p>'
                    f'<form method="post" action="/run"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<label>Local target URL</label><p><input name="target" placeholder="http://127.0.0.1:3000/"></p>'
                    '<label>Local project folder (optional)</label><p><input name="project" placeholder="Project directory under CyberLab-Projects"></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I own this local test target or have authorization</label></p>'
                    '<button type="submit">Start AI investigation</button></form></section>'
                    f'<section><h2>Threat intelligence: npm advisories</h2><p>Queries the OSV API for declared project dependencies. A candidate match is not a confirmed vulnerability. Project folder must be inside {esc(PROJECTS)}.</p>'
                    f'<form method="post" action="/intelligence/check"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<label>Project folder</label><p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I am authorized to inspect this local project and query package names externally</label></p>'
                    '<button type="submit">Check OSV advisories</button></form>'
                    f'<ul>{intel_items or "<li>No intelligence checks yet</li>"}</ul></section>'
                    f'<section><h2>Application behavior discovery (v4.3)</h2><p>Read-only Next.js API route discovery from filenames. No source contents are read. Results are hypotheses, not vulnerabilities.</p>'
                    f'<form method="post" action="/behavior/check"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<label>Authorized project folder</label><p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I own this local project or am authorized to inspect it</label></p>'
                    '<button type="submit">Discover application routes</button></form>'
                    f'<ul>{behavior_items or "<li>No route inventories yet</li>"}</ul></section>'
                    f'<section><h2>AI-guided application investigation (v4.6)</h2><p>Ollama selects route metadata to investigate and creates unverified hypotheses. No source code or external targets are accessed.</p>'
                    f'<form method="post" action="/ai-behavior/check"><input type="hidden" name="csrf" value="{TOKEN}">'
                    '<label>Authorized project folder</label><p><input name="project" placeholder="demo" required></p>'
                    '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I own this project or am authorized to inspect it</label></p>'
                    '<button type="submit">Start AI-guided investigation</button></form>'
                    f'<ul>{ai_items or "<li>No AI-guided investigations yet</li>"}</ul></section>'
                    f'<section><h2>Investigation history</h2><ul>{items or "<li>No investigations yet</li>"}</ul></section>')
            self.send_html(page(body))
        elif p.startswith('/changes/') and p[len('/changes/'):].isdigit():
            record = changes.detail(DB, int(p[len('/changes/'):]))
            if record is None:
                self.send_html(page('<p>Not found</p>'),404); return
            evidence_links = ''.join(f'<li><a href="/continuous/{esc(e["id"].split(":")[1])}">{esc(e["id"])}</a></li>' for e in record['context']['evidence'])
            content = (f'<p><a href="/">Dashboard</a></p><section><h2>Change investigation #{record["id"]}</h2><p>{esc(record["status"])}</p>'
                f'<pre>{esc(json.dumps(record["context"],indent=2))}</pre><ul>{evidence_links}</ul><pre>{esc(json.dumps(record["recommendation"],indent=2))}</pre>'
                f'<p><a href="/changes-export/{record["id"]}">Export sanitized JSON</a></p><form method="post" action="/changes/analyze"><input type="hidden" name="csrf" value="{TOKEN}"><input type="hidden" name="investigation" value="{record["id"]}">'
                '<p><label><input style="width:auto" type="checkbox" name="authorized" value="yes" required> I authorize read-only Ollama analysis</label></p><button>Request analysis / retry</button></form>'
                '<p>Manual review required. This button does not authorize or run live verification. Use the existing controlled localhost verification form after reviewing its synthetic plan.</p></section>')
            self.send_html(page(content))
        elif p.startswith('/changes-export/') and p[len('/changes-export/'):].isdigit():
            record = changes.detail(DB, int(p[len('/changes-export/'):]))
            if record is None:
                self.send_html(page('<p>Not found</p>'),404); return
            payload = json.dumps(record).encode()
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(payload)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers(); self.wfile.write(payload)
        elif p.startswith('/continuous/') and p[len('/continuous/'):].isdigit():
            result=continuous_detail(DB,int(p[len('/continuous/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404); return
            check,diff=result
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Change assessment #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Added routes:</p><pre>{esc(json.dumps(diff["added_routes"],indent=2))}</pre><p>Removed routes:</p><pre>{esc(json.dumps(diff["removed_routes"],indent=2))}</pre><p>Modified filename metadata:</p><pre>{esc(json.dumps(diff.get("modified_routes",[]),indent=2))}</pre><p>Unchanged routes: {diff["unchanged_routes"]}</p><p>Changes are not vulnerabilities. Re-run authorized investigations to evaluate them.</p></section>'))
        elif p.startswith('/risk/') and p[len('/risk/'):].isdigit():
            result=risk_detail(DB,int(p[len('/risk/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check,edges=result
            rows=''.join('<div class="event"><strong>'+esc(e['route'])+'</strong><p>AI hypothesis event #'+esc(e['hypothesis_event'])+'; localhost observation #'+esc(e['observation_event'])+'</p><p>Indicator: '+esc(e['indicator'])+'</p><p>'+esc(e['recommendation'])+'</p></div>' for e in edges)
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Risk analysis #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Ollama: {esc(check["ai_status"])}</p><pre>{esc(check["ai_commentary"])}</pre><p>No relationships or vulnerabilities are automatically confirmed.</p></section><section>{rows or "No exact-route relationships found. Run AI-guided discovery and localhost verification first."}</section>'))
        elif p.startswith('/memory/') and p[len('/memory/'):].isdigit():
            result=memory_detail(DB,int(p[len('/memory/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check,links=result
            rows=''.join('<div class="event"><strong>'+esc(x['route'])+'</strong><p>'+esc(x['relation'])+'</p><p>AI event #'+esc(x['left_event'])+' and local observation #'+esc(x['right_event'])+'</p><p>'+esc(x['interpretation'])+'</p></div>' for x in links)
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Evidence memory #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Only exact-route correlations. No finding automatically confirmed.</p></section><section>{rows or "No cross-module route matches yet."}</section>'))
        elif p.startswith('/live/') and p[len('/live/'):].isdigit():
            result=live_detail(DB,int(p[len('/live/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check,events=result
            rows=''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Local verification #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["summary"])}</p><p>Local test observations are not independently confirmed vulnerabilities.</p></section><section>{rows}</section>'))
        elif p.startswith('/experiments/') and p[len('/experiments/'):].isdigit():
            result = experiment_detail(DB,int(p[len('/experiments/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check,events = result
            rows = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Synthetic experiment #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["summary"])}</p><p>No live system was tested. These are simulated results, not real vulnerabilities.</p></section><section>{rows}</section>'))
        elif p.startswith('/ai-behavior/') and p[len('/ai-behavior/'):].isdigit():
            result = ai_behavior_detail(DB,int(p[len('/ai-behavior/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check,events = result
            rows = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>AI investigation #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["project"])} · {esc(check["summary"])}</p><p class="muted">All hypotheses are unverified. Filename metadata cannot prove vulnerabilities.</p></section><section>{rows or "No events yet. Refresh shortly."}</section>'))
        elif p.startswith('/behavior/') and p[len('/behavior/'):].isdigit():
            result = behavior_detail(DB, int(p[len('/behavior/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check, routes = result
            rows = ''.join('<div class="event"><strong>'+esc(r['route'])+'</strong><p>Potential investigation: '+esc(r['hypothesis'])+'</p><p>Evidence: '+esc(r['evidence'])+'</p><p class="muted">Methods and access controls unknown; no vulnerability confirmed.</p></div>' for r in routes)
            self.send_html(page(f'<p><a href="/">← Dashboard</a></p><section><h2>Application discovery #{check["id"]}: {esc(check["status"])}</h2><p>Project: {esc(check["project"])} · Routes: {check["route_count"]}</p><p>{esc(check["summary"])} {esc(check["error"])}</p></section><section>{rows or "No API route files found."}</section>'))
        elif p.startswith('/intelligence/') and p[len('/intelligence/'):].isdigit():
            result = check_detail(DB, int(p[len('/intelligence/'):]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            check, matches = result
            rows = ''.join('<div class="event"><strong>'+esc(m['package'])+' '+esc(m['declared'])+'</strong> · '+esc(m['advisory_id'])+'<p>'+esc(m['assessment'])+' — '+esc(m['reason'])+'</p><p>'+esc(m['summary'] or 'Advisory details unavailable')+'</p><p>'+esc(m['reference'] or 'https://osv.dev')+'</p></div>' for m in matches)
            self.send_html(page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>Advisory check #{check["id"]}: {esc(check["status"])}</h2><p>Project: {esc(check["project"])} · Dependencies: {check["package_count"]} · Candidate matches: {check["match_count"]}</p><p>{esc(check["error"])}</p><p class="muted">Advisories are untrusted external information; a candidate match is not proof of exploitability.</p></section><section><h2>Candidate advisories</h2>{rows or "No matches yet; refresh if the check is running."}</section>'))
        elif p.startswith('/runs/') and p[6:].isdigit():
            result = get_run(DB, int(p[6:]))
            if result is None:
                self.send_html(page('<p>Not found</p>'),404)
                return
            run, events = result
            events_html = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong> · '+esc(e['created'])+'<pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>Run #{run["id"]}: {esc(run["status"])}</h2><p>{esc(run["summary"])}</p></section><section><h2>Evidence and decisions</h2>{events_html or "No events yet. Refresh in a moment."}</section>'))
        else:
            self.send_html(page('<p>Not found</p>'),404)

    def do_POST(self):
        if not self.valid_host(): return
        if self.path not in ('/run', '/intelligence/check', '/behavior/check', '/ai-behavior/check', '/experiments/check', '/live/check', '/memory/build', '/risk/analyze', '/continuous/assess', '/monitor/configure', '/changes/analyze'):
            self.send_html(page('<p>Not found</p>'),404)
            return
        try:
            length = int(self.headers.get('Content-Length','0'))
            if length > 4096 or length < 1:
                raise ValueError('Invalid request length')
            values = parse_qs(self.rfile.read(length).decode('utf-8'), max_num_fields=20)
            if any(len(v) != 1 for v in values.values()):
                raise ValueError('Duplicate form field')
            def field(name): return values.get(name,[''])[0].strip()
            if not secrets.compare_digest(field('csrf'), TOKEN) or field('authorized') != 'yes':
                raise ValueError('Authorization confirmation or CSRF token missing')
            target, project = field('target'), field('project')
            if project and not Path(project).is_absolute():
                project = str(PROJECTS / project)
            if project:
                resolved = Path(project).resolve(strict=True)
                if resolved.parent != PROJECTS or len(resolved.name) > 128:
                    raise ValueError('Select a direct project folder under the approved projects root')
            if self.path == '/monitor/configure':
                if not project: raise ValueError('Project is required')
                monitor.configure(DB, project, PROJECTS, enabled=field('enabled')=='yes',
                    interval=int(field('interval')), use_ai=field('use_ai')=='yes')
                self.send_response(303); self.send_header('Location','/'); self.end_headers(); return
            if self.path == '/changes/analyze':
                rid = int(field('investigation'))
                if changes.detail(DB,rid) is None: raise ValueError('Unknown change investigation')
                changes.analyze(DB,rid)
                self.send_response(303); self.send_header('Location',f'/changes/{rid}'); self.end_headers(); return
            if self.path == '/continuous/assess':
                if not project: raise ValueError('Project is required')
                rid = continuous_assess(DB,project,PROJECTS)
                changes.ensure(DB,rid)
                self.send_response(303); self.send_header('Location','/'); self.end_headers(); return
            if self.path == '/risk/analyze':
                if not project: raise ValueError('Project is required')
                behavior_inventory(project,PROJECTS)
                risk_analyze(DB,Path(project).resolve().name,use_ai=(field('use_ai')=='yes'))
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/memory/build':
                if not project: raise ValueError('Project is required')
                from .behavior import inventory
                inventory(project,PROJECTS)
                memory_snapshot(DB,Path(project).resolve().name)
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/live/check':
                validate_plan(project,PROJECTS)
                Thread(target=live_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/experiments/check':
                validate_fixture(project, PROJECTS)
                Thread(target=experiment_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/ai-behavior/check':
                behavior_inventory(project, PROJECTS)
                Thread(target=ai_behavior_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/behavior/check':
                behavior_inventory(project, PROJECTS)
                Thread(target=behavior_check, args=(DB,project,PROJECTS),daemon=True).start()
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            if self.path == '/intelligence/check':
                from .intelligence import project_manifest
                project_manifest(project, PROJECTS)
                Thread(target=check_project, args=(DB,project,PROJECTS),daemon=True).start()
                self.send_response(303)
                self.send_header('Location','/')
                self.end_headers()
                return
            # Validate before background thread starts, then redirect to index.
            from .core import safe_local_url, inspect_project
            if target: safe_local_url(target)
            if project: inspect_project(project, PROJECTS)
            if not target and not project: raise ValueError('Provide a target or project')
            Thread(target=investigate,args=(DB,target,project,PROJECTS),daemon=True).start()
            self.send_response(303)
            self.send_header('Location','/')
            self.end_headers()
        except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.send_html(page('<p><a href="/">← Back</a></p><p>Request rejected: '+esc(exc)+'</p>'),400)


def main():
    host, port = '127.0.0.1', int(os.getenv('CYBERLAB_V4_PORT','8780'))
    print(f'CyberLab AI v4.11: http://{host}:{port} | model={os.getenv("CYBERLAB_MODEL","llama3.2:latest")}')
    print('Local-only. Press Ctrl+C to stop.')
    changes.recover(DB)
    worker = monitor.Monitor(DB, PROJECTS)
    server = ThreadingHTTPServer((host,port),Handler)
    import signal
    def terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    worker.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        worker.stop()
        server.server_close()

if __name__ == '__main__':
    main()
