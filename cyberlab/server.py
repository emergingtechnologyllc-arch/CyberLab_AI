"""Loopback-only dashboard. No third-party dependencies."""
import html
import json
import os
from pathlib import Path
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit, urlencode
from . import change_investigation as changes, monitor, ui, projects as project_store, __version__
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


def evidence_url(evidence):
    source, number = evidence['id'].split(':')
    if source == 'assessment':
        return '/continuous/' + number
    prefix = {'ai_event': '/ai-behavior/', 'live_event': '/live/'}[source]
    return prefix + str(evidence['run_id'])


def status_label(status):
    return {'unchanged':'no changes', 'baseline':'baseline established',
            'pending_analysis':'pending analysis', 'recommended_review':'recommended review',
            'model_unavailable':'model unavailable', 'model_invalid':'analysis failed: invalid model response',
            'analysis_failed':'analysis failed', 'verified_local_observation':'verified local observation (not a confirmed vulnerability)'}.get(status,status)




class Handler(BaseHTTPRequestHandler):
    def render_page(self, content, selected=None):
        p = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        project = selected if selected is not None else query.get('project',[''])[0]
        prefix = p.split('/')[1]
        active = {'continuous':'/monitoring','changes':'/monitoring','risk':'/evidence',
                  'memory':'/evidence','live':'/verification','experiments':'/verification',
                  'ai-behavior':'/investigations','behavior':'/investigations','runs':'/investigations',
                  'intelligence':'/intelligence'}.get(prefix,'/')
        title = dict((path,label) for path,label,_ in ui.NAV).get(active,'Overview')
        return ui.layout(content,title,active,project,project_store.discover(PROJECTS))

    def redirect(self, destination, project='', notice=''):
        if destination not in ('/', '/projects','/investigations','/monitoring','/intelligence','/evidence','/verification'):
            destination = '/'
        location = ui.url(destination,project,**({'notice':notice} if notice else {}))
        self.send_response(303); self.send_header('Location',location); self.end_headers()

    def send_html(self, body, status=200):
        self.send_response(status)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if self.headers.get('Host') not in allowed:
            self.send_html(self.render_page('<p>Invalid local Host</p>'),400)
            return False
        return True

    def do_GET(self):
        if not self.valid_host(): return
        p = urlsplit(self.path).path
        if p == '/assets/app.css':
            body = Path(__file__).with_name('assets').joinpath('app.css').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type','text/css; charset=utf-8')
            self.send_header('Content-Length',str(len(body)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers(); self.wfile.write(body); return
        if p in ('/', '/projects', '/investigations', '/monitoring', '/intelligence', '/evidence', '/verification', '/settings'):
            try:
                query = parse_qs(urlsplit(self.path).query, keep_blank_values=True, max_num_fields=10)
                self.send_html(ui.workspace(DB,PROJECTS,TOKEN,p,query))
            except (ValueError,OSError) as exc:
                self.send_html(self.render_page('<section><h2>Unable to open workspace</h2><p>'+esc(exc)+'</p><a href="/projects">Choose a project</a></section>'),400)
        elif p.startswith('/changes/') and p[len('/changes/'):].isdigit():
            record = changes.detail(DB, int(p[len('/changes/'):]))
            if record is None:
                self.send_html(self.render_page('<p>Not found</p>'),404); return
            self.send_html(self.render_page(ui.change_detail(record,TOKEN,evidence_url),record['context']['project']))
        elif p.startswith('/changes-export/') and p[len('/changes-export/'):].isdigit():
            record = changes.detail(DB, int(p[len('/changes-export/'):]))
            if record is None:
                self.send_html(self.render_page('<p>Not found</p>'),404); return
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
                self.send_html(self.render_page('<p>Not found</p>'),404); return
            check,diff=result
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Change assessment #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Added routes:</p><pre>{esc(json.dumps(diff["added_routes"],indent=2))}</pre><p>Removed routes:</p><pre>{esc(json.dumps(diff["removed_routes"],indent=2))}</pre><p>Modified filename metadata:</p><pre>{esc(json.dumps(diff.get("modified_routes",[]),indent=2))}</pre><p>Unchanged routes: {diff["unchanged_routes"]}</p><p>Changes are not vulnerabilities. Re-run authorized investigations to evaluate them.</p></section>'))
        elif p.startswith('/risk/') and p[len('/risk/'):].isdigit():
            result=risk_detail(DB,int(p[len('/risk/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check,edges=result
            rows=''.join('<div class="event"><strong>'+esc(e['route'])+'</strong><p>AI hypothesis event #'+esc(e['hypothesis_event'])+'; localhost observation #'+esc(e['observation_event'])+'</p><p>Indicator: '+esc(e['indicator'])+'</p><p>'+esc(e['recommendation'])+'</p></div>' for e in edges)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Risk analysis #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Ollama: {esc(check["ai_status"])}</p><pre>{esc(check["ai_commentary"])}</pre><p>No relationships or vulnerabilities are automatically confirmed.</p></section><section>{rows or "No exact-route relationships found. Run AI-guided discovery and localhost verification first."}</section>'))
        elif p.startswith('/memory/') and p[len('/memory/'):].isdigit():
            result=memory_detail(DB,int(p[len('/memory/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check,links=result
            rows=''.join('<div class="event"><strong>'+esc(x['route'])+'</strong><p>'+esc(x['relation'])+'</p><p>AI event #'+esc(x['left_event'])+' and local observation #'+esc(x['right_event'])+'</p><p>'+esc(x['interpretation'])+'</p></div>' for x in links)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Evidence memory #{check["id"]}</h2><p>{esc(check["summary"])}</p><p>Only exact-route correlations. No finding automatically confirmed.</p></section><section>{rows or "No cross-module route matches yet."}</section>'))
        elif p.startswith('/live/') and p[len('/live/'):].isdigit():
            result=live_detail(DB,int(p[len('/live/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check,events=result
            rows=''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Local verification #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["summary"])}</p><p>Local test observations are not independently confirmed vulnerabilities.</p></section><section>{rows}</section>'))
        elif p.startswith('/experiments/') and p[len('/experiments/'):].isdigit():
            result = experiment_detail(DB,int(p[len('/experiments/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check,events = result
            rows = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Synthetic experiment #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["summary"])}</p><p>No live system was tested. These are simulated results, not real vulnerabilities.</p></section><section>{rows}</section>'))
        elif p.startswith('/ai-behavior/') and p[len('/ai-behavior/'):].isdigit():
            result = ai_behavior_detail(DB,int(p[len('/ai-behavior/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check,events = result
            rows = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong><pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>AI investigation #{check["id"]}: {esc(check["status"])}</h2><p>{esc(check["project"])} · {esc(check["summary"])}</p><p class="muted">All hypotheses are unverified. Filename metadata cannot prove vulnerabilities.</p></section><section>{rows or "No events yet. Refresh shortly."}</section>'))
        elif p.startswith('/behavior/') and p[len('/behavior/'):].isdigit():
            result = behavior_detail(DB, int(p[len('/behavior/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check, routes = result
            rows = ''.join('<div class="event"><strong>'+esc(r['route'])+'</strong><p>Potential investigation: '+esc(r['hypothesis'])+'</p><p>Evidence: '+esc(r['evidence'])+'</p><p class="muted">Methods and access controls unknown; no vulnerability confirmed.</p></div>' for r in routes)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a></p><section><h2>Application discovery #{check["id"]}: {esc(check["status"])}</h2><p>Project: {esc(check["project"])} · Routes: {check["route_count"]}</p><p>{esc(check["summary"])} {esc(check["error"])}</p></section><section>{rows or "No API route files found."}</section>'))
        elif p.startswith('/intelligence/') and p[len('/intelligence/'):].isdigit():
            result = check_detail(DB, int(p[len('/intelligence/'):]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            check, matches = result
            rows = ''.join('<div class="event"><strong>'+esc(m['package'])+' '+esc(m['declared'])+'</strong> · '+esc(m['advisory_id'])+'<p>'+esc(m['assessment'])+' — '+esc(m['reason'])+'</p><p>'+esc(m['summary'] or 'Advisory details unavailable')+'</p><p>'+esc(m['reference'] or 'https://osv.dev')+'</p></div>' for m in matches)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>Advisory check #{check["id"]}: {esc(check["status"])}</h2><p>Project: {esc(check["project"])} · Dependencies: {check["package_count"]} · Candidate matches: {check["match_count"]}</p><p>{esc(check["error"])}</p><p class="muted">Advisories are untrusted external information; a candidate match is not proof of exploitability.</p></section><section><h2>Candidate advisories</h2>{rows or "No matches yet; refresh if the check is running."}</section>'))
        elif p.startswith('/runs/') and p[6:].isdigit():
            result = get_run(DB, int(p[6:]))
            if result is None:
                self.send_html(self.render_page('<p>Not found</p>'),404)
                return
            run, events = result
            events_html = ''.join('<div class="event"><strong>'+esc(e['kind'])+'</strong> · '+esc(e['created'])+'<pre>'+esc(json.dumps(json.loads(e['payload']),indent=2))+'</pre></div>' for e in events)
            self.send_html(self.render_page(f'<p><a href="/">← Dashboard</a> · <a href="{esc(p)}">Refresh</a></p><section><h2>Run #{run["id"]}: {esc(run["status"])}</h2><p>{esc(run["summary"])}</p></section><section><h2>Evidence and decisions</h2>{events_html or "No events yet. Refresh in a moment."}</section>'))
        else:
            self.send_html(self.render_page('<p>Not found</p>'),404)

    def do_POST(self):
        if not self.valid_host(): return
        if self.path not in ('/run', '/intelligence/check', '/behavior/check', '/ai-behavior/check', '/experiments/check', '/live/check', '/memory/build', '/risk/analyze', '/continuous/assess', '/monitor/configure', '/changes/analyze', '/projects/create', '/investigations/start', '/verification/start'):
            self.send_html(self.render_page('<p>Not found</p>'),404)
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
            action = self.path
            if action == '/projects/create':
                created = project_store.create(PROJECTS,field('project_name'),sample=field('sample')=='yes')
                self.redirect('/projects',created.name,'created'); return
            if action == '/investigations/start':
                modes = {'changes':'/continuous/assess','inventory':'/behavior/check',
                         'ai':'/ai-behavior/check','local':'/run'}
                if field('mode') not in modes: raise ValueError('Choose an investigation type')
                action = modes[field('mode')]
                if action != '/run' and not field('project'): raise ValueError('Choose a project in the top bar first')
                if action != '/run' and field('target'): raise ValueError('Local target is only used for local application investigation')
            if action == '/verification/start':
                modes = {'offline':'/experiments/check','live':'/live/check'}
                if field('mode') not in modes: raise ValueError('Choose a verification type')
                action = modes[field('mode')]
                if not field('project'): raise ValueError('Choose a project in the top bar first')
            target, project = field('target'), field('project')
            if project and not Path(project).is_absolute():
                project = str(PROJECTS / project)
            if project:
                resolved = Path(project).resolve(strict=True)
                if resolved.parent != PROJECTS or len(resolved.name) > 128:
                    raise ValueError('Select a direct project folder under the approved projects root')
            destinations = {'/monitor/configure':'/monitoring','/continuous/assess':'/monitoring',
                '/risk/analyze':'/evidence','/memory/build':'/evidence', '/live/check':'/verification',
                '/experiments/check':'/verification','/intelligence/check':'/intelligence'}
            destination = destinations.get(action,'/investigations')
            selected_project = Path(project).resolve().name if project else ''
            if action == '/monitor/configure':
                if not project: raise ValueError('Project is required')
                monitor.configure(DB, project, PROJECTS, enabled=field('enabled')=='yes',
                    interval=int(field('interval')), use_ai=field('use_ai')=='yes')
                self.redirect(destination,selected_project,'saved' if action == '/monitor/configure' else 'completed'); return
            if action == '/changes/analyze':
                rid = int(field('investigation'))
                if changes.detail(DB,rid) is None: raise ValueError('Unknown change investigation')
                changes.analyze(DB,rid)
                self.send_response(303); self.send_header('Location',ui.url(f'/changes/{rid}',selected_project)); self.end_headers(); return
            if action == '/continuous/assess':
                if not project: raise ValueError('Project is required')
                rid = continuous_assess(DB,project,PROJECTS)
                changes.ensure(DB,rid)
                self.redirect(destination,selected_project,'saved' if action == '/monitor/configure' else 'completed'); return
            if action == '/risk/analyze':
                if not project: raise ValueError('Project is required')
                behavior_inventory(project,PROJECTS)
                risk_analyze(DB,Path(project).resolve().name,use_ai=(field('use_ai')=='yes'))
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/memory/build':
                if not project: raise ValueError('Project is required')
                from .behavior import inventory
                inventory(project,PROJECTS)
                memory_snapshot(DB,Path(project).resolve().name)
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/live/check':
                validate_plan(project,PROJECTS)
                Thread(target=live_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/experiments/check':
                validate_fixture(project, PROJECTS)
                Thread(target=experiment_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/ai-behavior/check':
                behavior_inventory(project, PROJECTS)
                Thread(target=ai_behavior_run,args=(DB,project,PROJECTS),daemon=True).start()
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/behavior/check':
                behavior_inventory(project, PROJECTS)
                Thread(target=behavior_check, args=(DB,project,PROJECTS),daemon=True).start()
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            if action == '/intelligence/check':
                from .intelligence import project_manifest
                project_manifest(project, PROJECTS)
                Thread(target=check_project, args=(DB,project,PROJECTS),daemon=True).start()
                self.redirect(destination,selected_project,'queued' if action in ('/live/check','/experiments/check','/ai-behavior/check','/behavior/check','/intelligence/check') else 'completed')
                return
            # Validate before background thread starts, then redirect to index.
            from .core import safe_local_url, inspect_project
            if target: safe_local_url(target)
            if project: inspect_project(project, PROJECTS)
            if not target and not project: raise ValueError('Provide a target or project')
            Thread(target=investigate,args=(DB,target,project,PROJECTS),daemon=True).start()
            self.redirect(destination,selected_project,'queued')
        except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.send_html(self.render_page('<section class="reading-width"><p class="eyebrow">Action not started</p><h2>Check your request</h2><p>'+esc(exc)+'</p><a href="/investigations">Return to investigations →</a></section>'),400)


def main():
    host, port = '127.0.0.1', int(os.getenv('CYBERLAB_V4_PORT','8780'))
    print(f'CyberLab {__version__}: http://{host}:{port} | model={os.getenv("CYBERLAB_MODEL","llama3.2:latest")}')
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
