"""Server-rendered CyberLab workspace. No scripts or third-party assets required."""
import html
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import urlencode
from . import __version__, projects as project_store

NAV = (('/', 'Overview', 'overview'), ('/projects','Projects','folder'),
       ('/investigations','Investigations','search'), ('/monitoring','Monitoring','pulse'),
       ('/intelligence','Intelligence','globe'), ('/evidence','Evidence','layers'),
       ('/verification','Verification','check'),('/help','How to Use','book'))
ICONS = {
 'book':'M3 4h7l2 2 2-2h7v16h-7l-2 2-2-2H3V4ZM12 6v16',
 'shield':'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3ZM9 12l2 2 4-4',
 'overview':'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
 'folder':'M3 7V5h6l2 2h10v13H3V7Z',
 'search':'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM16 16l5 5',
 'pulse':'M2 12h5l3-8 4 16 3-8h5',
 'globe':'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z',
 'layers':'m12 3 10 5-10 5L2 8l10-5ZM2 12l10 5 10-5M2 16l10 5 10-5',
 'check':'M20 6 9 17l-5-5',
 'settings':'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2',
 'arrow':'M5 12h14m-5-5 5 5-5 5',
 'plus':'M12 5v14M5 12h14',
 'lock':'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4',
 'clock':'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 7v5l3 2',
}
SOURCES = (('continuous_runs','Route comparison','/continuous/'),
           ('behavior_checks','Route discovery','/behavior/'),
           ('ai_behavior_runs','AI investigation','/ai-behavior/'),
           ('runs','Local investigation','/runs/'),
           ('intelligence_checks','Advisory check','/intelligence/'),
           ('live_runs','Local verification','/live/'),
           ('experiment_runs','Synthetic experiment','/experiments/'),
           ('memory_snapshots','Evidence memory','/memory/'),
           ('risk_runs','Risk review','/risk/'))
# Table names are adapted to the existing schema, never user input.
LABELS = {'baseline':'Baseline established','unchanged':'No changes','changed':'Changes detected',
          'pending_analysis':'Pending analysis','recommended_review':'Review recommended',
          'model_unavailable':'Model unavailable','model_invalid':'Invalid model response',
          'analysis_failed':'Analysis failed','analyzing':'Analyzing', 'completed':'Completed',
          'running':'Running','error':'Needs attention','pending':'Waiting for first check',
          'assessment_failed':'Assessment failed'}


def esc(value): return html.escape(str(value), quote=True)


def icon(name):
    return f'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="{ICONS.get(name,ICONS["shield"])}"/></svg>'


def url(path, project='', **params):
    if project: params['project'] = project
    return path + ('?' + urlencode(params) if params else '')


def button(label, path, project='', primary=False, symbol=None):
    return f'<a class="button{" primary" if primary else ""}" href="{esc(url(path,project))}">{icon(symbol) if symbol else ""}{esc(label)}</a>'


def badge(status):
    color = 'green' if status in ('completed','unchanged','baseline','enabled') else 'amber' if status in ('changed','recommended_review','pending_analysis','running','analyzing') else 'red' if status in ('error','model_invalid','analysis_failed','assessment_failed') else ''
    return f'<span class="badge {color}">{esc(LABELS.get(status,status.replace("_"," ").capitalize()))}</span>'


def layout(content, title='Overview', active='/', project='', names=()):
    nav = ''.join(f'<a class="nav-link{" active" if path == active else ""}" {"aria-current=page" if path == active else ""} href="{esc(url(path,project))}">{icon(symbol)}{label}</a>' for path,label,symbol in NAV)
    options = '<option value="">All projects</option>' + ''.join(f'<option value="{esc(n)}" {"selected" if n == project else ""}>{esc(n)}</option>' for n in names)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{esc(title)} · CyberLab {__version__}</title><link rel="stylesheet" href="/assets/app.css"></head><body>'
        '<a href="#main" class="skip-link">Skip to content</a><aside class="sidebar"><a class="brand" href="/">'
        f'<span class="brand-mark">{icon("shield")}</span><span><strong>CyberLab</strong><small>SECURITY WORKSPACE</small></span></a>'
        f'<p class="nav-label">Workspace</p><nav class="nav-group" aria-label="Main navigation">{nav}<a class="nav-link mobile-settings" href="{esc(url("/settings",project))}">{icon("settings")}Settings</a></nav>'
        f'<div class="sidebar-bottom"><a class="nav-link{" active" if active == "/settings" else ""}" href="{esc(url("/settings",project))}">{icon("settings")}Settings</a>'
        f'<div class="local-note"><i class="dot"></i> Your workspace. Your machine.<span>Projects and evidence stay local.</span></div>'
        f'<div class="release"><span>CyberLab {__version__}</span><span>Local production</span></div></div></aside><div class="app">'
        f'<header class="topbar"><div class="breadcrumb"><span>Workspace</span><span>/</span><strong>{esc(title)}</strong></div>'
        f'<div class="top-actions"><form class="project-switcher" method="get" action="{esc(active)}"><label for="workspace-project">Active project</label>'
        f'<select id="workspace-project" name="project">{options}</select><button type="submit">Open</button></form>'
        '<span class="local-status"><i class="dot"></i>Local workspace</span><span class="avatar" aria-label="Local user">CL</span></div></header>'
        f'<main id="main" class="content">{content}<footer class="footer"><span>{icon("lock")}Local-first · Review before action</span>'
        f'<span>CyberLab {__version__} &nbsp; / &nbsp; One workspace. Every investigation.</span></footer></main></div></body></html>').encode()


def heading(title, description, actions='', eyebrow='Workspace'):
    return f'<div class="page-head"><div><p class="eyebrow">{esc(eyebrow)}</p><h1>{esc(title)}</h1><p class="subtitle">{esc(description)}</p></div><div class="button-row">{actions}</div></div>'


def empty(title, description, action='', symbol='folder'):
    return f'<div class="empty-state"><div class="empty-icon">{icon(symbol)}</div><h3>{esc(title)}</h3><p>{esc(description)}</p>{action}</div>'


def consent(text='I authorize this action on the selected local project.'):
    return f'<label class="check"><input type="checkbox" name="authorized" value="yes" required><span>{esc(text)}</span></label>'


def form_open(action, token, project='', destination=''):
    return f'<form method="post" action="{action}"><input type="hidden" name="csrf" value="{esc(token)}"><input type="hidden" name="project" value="{esc(project)}"><input type="hidden" name="return_to" value="{esc(destination)}">'


def option(name, value, title, description, checked=False):
    return f'<label class="option"><input type="radio" name="{name}" value="{value}" {"checked" if checked else ""}><span><strong>{esc(title)}</strong><small>{esc(description)}</small></span></label>'


def records(db_path, project='', limit=20, base=None):
    result = []
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table,title,prefix in SOURCES:
            if table not in tables: continue
            params = (project, str(Path(base)/project),limit) if project else (limit,)
            where = ' WHERE (project=? OR project=?)' if project else ''
            rows = db.execute(f'SELECT id,created,project,status FROM {table}{where} ORDER BY id DESC LIMIT ?',params)
            for row in rows:
                item = dict(row); item.update(title=title,href=url(prefix+str(row['id']),project))
                result.append(item)
    return sorted(result,key=lambda r:(r['created'] or '',r['id']),reverse=True)[:limit]


def activity_table(rows):
    if not rows:
        return '<div class="empty-state compact"><div class="empty-icon">'+icon('clock')+'</div><h3>Your investigation history starts here</h3><p>Run your first investigation to see its progress and evidence in one place.</p></div>'
    items = ''.join(f'<tr><td><a class="record-name" href="{esc(r["href"])}">{esc(r["title"])}</a><span class="record-sub">{esc(Path(r["project"] or "—").name)} · #{r["id"]}</span></td>'
        f'<td class="col-project">{esc(Path(r["project"] or "—").name)}</td><td>{badge(r["status"])}</td><td class="muted fine col-created">{esc((r["created"] or "")[:16].replace("T"," "))} UTC</td></tr>' for r in rows)
    return f'<div class="table-wrap"><table><thead><tr><th>Activity</th><th class="col-project">Project</th><th>Status</th><th class="col-created">Created</th></tr></thead><tbody>{items}</tbody></table></div>'


def guide():
    return f'<aside class="panel guide"><p class="eyebrow">A simple workflow</p><h2>From project<br>to clear evidence.</h2><p class="guide-intro">Three steps to a useful investigation.</p><ol class="steps">'+''.join(
        f'<li><span class="step-number">{i}</span><div><strong>{title}</strong><p>{description}</p></div></li>' for i,title,description in (
            (1,'Choose your project','Open a local project or create a sample workspace.'),
            (2,'Understand what changed','Discover routes, compare changes, or ask your local model for a review.'),
            (3,'Review the evidence','Follow every observation back to its source. You decide what happens next.')))+f'</ol><div class="guide-foot">{icon("shield")}AI recommendations stay read-only. Verification always needs your approval.</div></aside>'


def need_project(project):
    return '' if project else '<div class="info-box">Choose a project in the top bar to use this tool. <a href="/projects">Add your first project →</a></div>'


def model_connection():
    """Explicit settings check: read model tags, never trigger inference."""
    import urllib.request
    from .core import NoRedirect
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        with opener.open('http://127.0.0.1:11434/api/tags',timeout=2) as response:
            raw = response.read(65537)
        if len(raw) > 65536: raise ValueError('Oversized tags response')
        data = json.loads(raw)
        if not isinstance(data,dict) or not isinstance(data.get('models'),list):
            raise ValueError('Invalid model list')
        names = [m.get('name') for m in data['models'] if isinstance(m,dict)]
        model = os.getenv('CYBERLAB_MODEL','llama3.2:latest')
        if model in names:
            return 'Model available', 'Ollama is reachable and the configured model is installed. A real recommendation still needs the live smoke test.'
        return 'Model not installed', 'Ollama is reachable, but the configured model was not listed.'
    except (OSError,ValueError,TypeError):
        return 'Connection unavailable', 'Ollama did not return a valid model list. Offline features are still available.'


def workspace(db_path, base, token, path, query):
    names = project_store.discover(base)
    project = query.get('project',[''])[0]
    if project and project not in names:
        raise ValueError('That project is not in the configured projects folder')
    if not project and 'project' not in query and path not in ('/', '/projects', '/settings', '/help') and names:
        project = names[0]
    rows = records(db_path,project,base=base)
    with sqlite3.connect(db_path) as db:
        db.row_factory = sqlite3.Row
        settings = [dict(r) for r in db.execute('SELECT * FROM monitor_settings ORDER BY project_root')]
        change_rows = [dict(r) for r in db.execute('''SELECT c.id,c.status,r.project FROM change_investigations c
            JOIN continuous_runs r ON r.id=c.assessment_id WHERE (?='' OR r.project=?) ORDER BY c.id DESC LIMIT 30''',(project,project))]
    selected_settings = next((s for s in settings if s['project_root'] == str(Path(base)/project)),{})
    active_settings = [s for s in settings if not project or s['project_root'] == str(Path(base)/project)]
    notices = {'created':'Project created. Your workspace is ready for its first investigation.',
               'queued':'Investigation started. Refresh the history below to see its progress.',
               'saved':'Preferences saved.', 'completed':'Action completed. Review the results below.'}
    notice = notices.get(query.get('notice',[''])[0],'')
    lead = f'<div class="notice" role="status">{notice}</div>' if notice else ''
    title = dict((p,n) for p,n,_ in NAV).get(path,'Settings')
    scope = f'Project: {project}' if project else 'Workspace overview'
    if path == '/':
        body = heading('A clearer view of your projects.', 'Understand changes, investigate with context, and keep the evidence that matters.',
            button('Add project','/projects',symbol='plus')+button('New investigation','/investigations',project,True,'search'),scope)
        with sqlite3.connect(db_path) as db:
            pending = db.execute('''SELECT count(*) FROM change_investigations c
                JOIN continuous_runs r ON r.id=c.assessment_id WHERE (?='' OR r.project=?)
                AND c.status IN ('pending_analysis','recommended_review','model_invalid','analysis_failed','model_unavailable')''', (project,project)).fetchone()[0]
        evidence_count = 0
        with sqlite3.connect(db_path) as db:
            for table in ('live_runs','experiment_runs','memory_snapshots'):
                evidence_count += db.execute(f'SELECT count(*) FROM {table}'+(' WHERE project=?' if project else ''),(project,) if project else ()).fetchone()[0]
        metrics = ((len(names),'Projects','folder','Available in your local workspace'),
                   (pending,'Changes to review','pulse','Pending analysis or manual review'),
                   (sum(s['enabled'] for s in active_settings),'Active monitors','clock','Runs while CyberLab is open'),
                   (evidence_count,'Evidence records','layers','Observations, experiments & memory'))
        body += '<div class="stats">'+''.join(f'<div class="stat"><div class="stat-top">{label}{icon(symbol)}</div><div class="stat-value">{value:02d}</div><div class="stat-bottom">{hint}</div></div>' for value,label,symbol,hint in metrics)+'</div>'
        from . import knowledge
        library=knowledge.status(db_path)
        total=sum(s['record_count'] for s in library)
        waiting=sum(s['stale'] or s['state']=='error' for s in library)
        body+=f'<div class="info-box">{icon("globe")} Intelligence library: <strong>{total:,} references</strong> · {waiting} sources need a fresh check. <a href="/intelligence">Review sources →</a></div>'
        project_content = ''.join(f'<div class="project-card"><div class="project-symbol">{icon("folder")}</div><div class="project-info"><h3>{esc(n)}</h3><p>Local project · Ready to investigate</p></div>{button("Open workspace","/investigations",n,symbol="arrow")}</div>' for n in names[:4])
        if not project_content:
            project_content = empty('Connect your first project','Bring a local project into focus, or try a sample to explore the workflow.',button('Add a project','/projects',primary=True,symbol='plus'))
        body += f'<div class="overview-grid"><div class="stack"><section class="panel"><div class="panel-head"><h2>Your projects <span class="count">{len(names)}</span></h2><a class="text-link" href="/projects">View all {icon("arrow")}</a></div>{project_content}</section>'
        body += f'<section class="panel"><div class="panel-head"><div class="activity-head"><h2>Recent activity</h2><span class="count">{len(rows)}</span></div><a class="text-link" href="{esc(url("/evidence",project))}">View history {icon("arrow")}</a></div>{activity_table(rows[:5])}</section></div>{guide()}</div>'
    elif path == '/projects':
        body = heading('Your projects','One place for the projects you own and the evidence you collect.',eyebrow='Workspace / Projects')
        cards = ''.join(f'<div class="project-card"><div class="project-symbol">{icon("folder")}</div><div class="project-info"><h3>{esc(n)}</h3><p>Local project folder</p></div>{button("Open workspace","/investigations",n,True,"arrow")}</div>' for n in names)
        body += f'<div class="form-layout"><section class="panel"><div class="panel-head"><h2>Local projects</h2><span class="count">{len(names)}</span></div>{cards or empty("No projects yet","Create a sample to get started, or place your project folder inside the configured projects directory.")}</section>'
        body += '<section class="panel" id="add-project"><p class="eyebrow">Get started</p><h2>Add a project</h2><p class="muted fine">Create a workspace folder. Add your existing application files to it, or start with our sample.</p>'
        body += form_open('/projects/create',token)+ '<label class="form-label" for="project-name">Project name</label><input class="field" id="project-name" name="project_name" placeholder="my-project" pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,63}" required maxlength="64">'
        body += '<label class="check"><input type="checkbox" name="sample" value="yes"><span>Include a sample project with synthetic routes</span></label>'+consent('I authorize creating this local project folder.')+'<button class="primary">Create project</button></form>'
        body += f'<details><summary>Where are my projects stored?</summary><p class="help">Existing folders placed here appear automatically:</p><code>{esc(base)}</code></details></section></div>'
    elif path == '/investigations':
        body = heading('Start with a question.','Choose what you want to understand. CyberLab keeps the investigation and its evidence together.',eyebrow=scope)
        body += '<div class="form-layout"><section class="panel"><h2>New investigation</h2>'+need_project(project)
        body += form_open('/investigations/start',token,project,'/investigations')+'<fieldset class="options"><legend>What would you like to do?</legend>'
        for value,label,hint in [('changes','Review project changes','Compare route filenames with the previous snapshot. No AI required.'),('inventory','Discover application routes','Build a read-only inventory of your Next.js API routes.'),('ai','Investigate with local AI','Ask Ollama to review route metadata and suggest questions.'),('local','Inspect a local test application','A bounded AI investigation of an approved loopback target.')]:
            body += option('mode',value,label,hint,value=='changes')
        body += '</fieldset><details><summary>Local application target (optional)</summary><label class="form-label" for="target">Local target URL</label><input class="field" id="target" name="target" type="url" placeholder="http://127.0.0.1:3000/"><p class="help">Used only for “Inspect a local test application.” An explicit loopback port is required.</p></details>'
        body += consent('I own this project or local target and authorize the selected investigation.')+'<div class="form-footer"><small>Read-only observations. No automatic remediation.</small><button class="primary">Start investigation '+icon('arrow')+'</button></div></form></section>'
        body += '<aside class="panel"><p class="eyebrow">What to expect</p><h2>Evidence, with context.</h2><p class="muted fine">Route discovery and change comparisons work offline. AI investigations use your configured local Ollama model.</p><div class="info-box">A recommendation is a question to review, not a confirmed vulnerability.</div><a class="text-link" href="/verification">Looking to run an approved test? →</a></aside></div>'
        body += f'<section style="margin-top:24px"><div class="panel-head"><h2>Investigation history</h2><a class="text-link" href="{esc(url("/investigations",project))}">Refresh history ↻</a></div>{activity_table(rows)}</section>'
    elif path == '/monitoring':
        body = heading('Keep track of what changes.','Compare route inventories on your schedule. Review each change before taking action.',eyebrow=scope)
        body += '<div class="form-layout"><section class="panel"><h2>Project monitoring</h2>'+need_project(project)
        body += form_open('/monitor/configure',token,project,'/monitoring')
        body += f'<label class="check"><input type="checkbox" name="enabled" value="yes" {"checked" if selected_settings.get("enabled") else ""}><span><strong>Enable monitoring</strong><br>Uncheck and save to pause future assessments.</span></label>'
        body += f'<label class="form-label" for="interval">Check every (seconds)</label><input class="field" id="interval" name="interval" type="number" min="30" max="86400" value="{selected_settings.get("interval",300)}" required><p class="help">Between 30 seconds and 24 hours. Only runs while CyberLab is open.</p>'
        body += f'<label class="check"><input type="checkbox" name="use_ai" value="yes" {"checked" if selected_settings.get("use_ai") else ""}><span>Ask Ollama to analyze new changes automatically<br><small>Optional. Sends bounded metadata to your local model.</small></span></label>'+consent()+ '<div class="form-footer"><small>Your settings are saved across restarts.</small><button class="primary">Save preferences</button></div></form></section>'
        body += '<aside class="panel"><p class="eyebrow">On demand</p><h2>Check for changes now</h2><p class="muted fine">Run one comparison without enabling scheduled monitoring.</p>'+form_open('/continuous/assess',token,project,'/monitoring')+consent()+'<button>Compare routes now</button></form></aside></div>'
        monitor_rows = ''.join(f'<tr><td>{esc(Path(r["project_root"]).name)}</td><td>{badge("enabled" if r["enabled"] else "paused")}</td><td>{esc(r["interval"])}s</td><td>{badge(r["status"])}</td></tr>' for r in active_settings)
        body += '<section style="margin-top:24px"><h2>Monitor status</h2>'+ ('<div class="table-wrap"><table><thead><tr><th>Project</th><th>Monitoring</th><th>Interval</th><th>Last result</th></tr></thead><tbody>'+monitor_rows+'</tbody></table></div>' if monitor_rows else empty('Monitoring is off','Choose a project and enable monitoring when you are ready.',symbol='pulse'))+'</section>'
        links = ''.join(f'<tr><td><a href="{esc(url("/changes/"+str(r["id"]),project))}">Change review #{r["id"]}</a></td><td>{esc(r["project"])}</td><td>{badge(r["status"])}</td></tr>' for r in change_rows)
        body += '<section><h2>Route comparisons</h2>'+activity_table([r for r in rows if r['title']=='Route comparison'])+'</section>'
        body += '<section><h2>Change investigations</h2>'+ ('<div class="table-wrap"><table><thead><tr><th>Review</th><th>Project</th><th>Status</th></tr></thead><tbody>'+links+'</tbody></table></div>' if links else empty('No changes awaiting review','A baseline establishes what is there. Later route changes appear here.',symbol='check'))+'</section>'
    elif path == '/intelligence':
        body = heading('Current intelligence. Clear provenance.','Refresh vulnerability and attack references, then check whether a project needs review.',eyebrow=scope)
        body += knowledge_view(db_path,token,project,query)
        body += '<div class="form-layout" style="margin-top:24px"><section class="panel"><h2>Check project advisories</h2>'+need_project(project)+form_open('/intelligence/check',token,project,'/intelligence')
        body += '<p class="muted fine">CyberLab reads your package manifest and queries OSV for candidate advisory matches. A match needs review before it becomes a finding.</p>'+consent('I authorize reading this project’s dependency manifest and sending package names to OSV.')+'<button class="primary">Check advisories '+icon('arrow')+'</button></form></section><aside class="panel"><h2>What leaves your machine?</h2><p class="muted fine">Dependency names and declared versions go to api.osv.dev. Source files and credentials are excluded.</p></aside></div>'
        body += '<section style="margin-top:24px"><h2>Advisory history</h2>'+activity_table([r for r in rows if r['title']=='Advisory check'])+'</section>'
    elif path == '/evidence':
        body = heading('Every observation has a source.','Review results, connect related evidence, and keep hypotheses separate from observations.',eyebrow=scope)
        view = query.get('view',['all'])[0]
        body += '<nav class="tabs" aria-label="Evidence views">'+''.join(f'<a class="{"active" if view == value else ""}" href="{esc(url(path,project,view=value))}">{label}</a>' for value,label in [('all','All activity'),('observations','Observations'),('risk','Risk reviews'),('memory','Evidence memory')])+'</nav>'
        groups = {'observations':('Local verification','Synthetic experiment'),'risk':('Risk review',),'memory':('Evidence memory',)}
        visible = [r for r in rows if r['title'] in groups[view]] if view in groups else rows
        body += '<section class="panel"><h2>Evidence & history</h2>'+activity_table(visible)+'</section><div class="two-columns" style="margin-top:24px">'
        for action,label,description,submit in [('/risk/analyze','Review evidence relationships','Correlate exact-route observations and hypotheses into review indicators.','Analyze relationships'),('/memory/build','Build evidence memory','Save a snapshot of related project evidence for later review.','Build memory')]:
            body += '<section class="panel"><h2>'+label+'</h2><p class="muted fine">'+description+'</p>'+need_project(project)+form_open(action,token,project,'/evidence')
            if action == '/risk/analyze': body += '<label class="check"><input type="checkbox" name="use_ai" value="yes"><span>Include a local Ollama summary</span></label>'
            body += consent()+f'<button>{submit}</button></form></section>'
        body += '</div>'
    elif path == '/verification':
        body = heading('Test deliberately. Review the result.','Run a synthetic experiment or an explicitly approved localhost verification.',eyebrow=scope)
        body += '<div class="form-layout"><section class="panel"><h2>New verification</h2>'+need_project(project)+form_open('/verification/start',token,project,'/verification')+'<fieldset class="options"><legend>Choose a test</legend>'
        body += option('mode','offline','Synthetic experiment','Uses your project’s offline authorization fixture. No live HTTP requests.',True)
        body += option('mode','live','Localhost verification','Runs bounded GET checks from your approved synthetic-account test plan.')+'</fieldset>'
        body += consent('I own this local test application and approve the selected checks using synthetic test accounts.')+'<div class="form-footer"><small>Model recommendations cannot approve tests.</small><button class="primary">Run approved test</button></div></form></section>'
        body += '<aside class="panel"><h2>Prepare your test</h2><p class="muted fine">Synthetic experiments require <code>cyberlab-test-fixture.json</code>. Localhost checks require <code>cyberlab-live-plan.json</code> and a running test application.</p><div class="info-box">A status mismatch is a review signal. It does not confirm an access-control vulnerability.</div></aside></div>'
        body += '<section style="margin-top:24px"><h2>Verification history</h2>'+activity_table([r for r in rows if r['title'] in ('Local verification','Synthetic experiment')])+'</section>'
    elif path == '/help':
        from .guide import render
        actions=button('Download guide','/help/download')
        if (Path(__file__).resolve().parents[1]/'docs/CyberLab-How-To-Use.pdf').is_file(): actions+=button('Printable PDF','/help/pdf')
        body = heading('How to use CyberLab.','Plain-language explanations and step-by-step instructions.',actions)+render()
    else:
        body = heading('Your local workspace.','Connection details and application settings, together in one place.',eyebrow='Workspace / Settings')
        body += '<div class="two-columns"><section class="panel"><h2>Application</h2><dl class="settings-list">'
        for label,value in [('Program','CyberLab'),('Release',__version__),('Runtime','Waitress · loopback-only production profile'),('Storage','Local SQLite database'),('Data directory',Path(db_path).parent),('Projects directory',base)]:
            body += f'<div><dt>{label}</dt><dd>{esc(value)}</dd></div>'
        body += '</dl><p class="help">All capabilities use this single application and release version. Existing investigation records remain available.</p></section>'
        connection, connection_detail = model_connection() if query.get('check',[''])[0]=='1' else ('Not checked','Check whether Ollama and your configured model are available. No analysis is started.')
        body += '<section class="panel"><h2>Local AI connection</h2><dl class="settings-list"><div><dt>Provider</dt><dd>Ollama</dd></div><div><dt>Endpoint</dt><dd>127.0.0.1:11434</dd></div><div><dt>Model</dt><dd>'+esc(os.getenv('CYBERLAB_MODEL','llama3.2:latest'))+'</dd></div></dl><p class="muted fine">AI is optional. Route discovery, comparisons, evidence history, and offline experiments work without it.</p><p class="fine"><strong>'+esc(connection)+'</strong></p><p class="help">'+esc(connection_detail)+'</p><a class="button" href="'+esc(url('/settings',project,check=1))+'">Check connection</a></section></div>'
        body += '<section style="margin-top:24px"><h2>Workspace configuration</h2><p class="muted fine">Directories and the model are configured when CyberLab starts. Restart after changing them.</p><details><summary>Advanced configuration</summary><pre>CYBERLAB_DATA_DIR — evidence database directory\nCYBERLAB_PROJECTS_DIR — approved projects folder\nCYBERLAB_MODEL — local Ollama model\nCYBERLAB_V4_PORT — loopback dashboard port</pre></details></section>'
    return layout(lead+body,title,path,project,names)


def change_detail(record, token, evidence_url):
    context, recommendation = record['context'], record['recommendation']
    project = context['project']
    body = heading(f'Change review #{record["id"]}', 'Follow the changed routes, the recommendation, and the evidence behind it.',
                   button('Back to monitoring','/monitoring',project), f'Project: {project}')
    body += '<div class="detail-grid"><section class="panel"><div class="panel-head"><h2>What changed</h2>'+badge(record['status'])+'</div><ul class="route-list">'
    for route in context['changed_routes']:
        diff = context['diff']
        label = 'Added' if route in diff['added_routes'] else 'Removed' if route in diff['removed_routes'] else 'Metadata changed'
        body += f'<li>{icon("folder")}<code>{esc(route)}</code><span class="badge">{label}</span></li>'
    body += '</ul><p class="help">Filename metadata only. Source contents and access-control logic have not been inspected.</p>'
    if recommendation:
        body += f'<div class="recommendation"><p class="eyebrow">Local AI recommendation</p><h3>{esc(recommendation["hypothesis"])}</h3><p class="muted fine">{esc(recommendation["reason"])}</p><p class="fine">Confidence: {esc(recommendation["confidence"])} · Suggested action: {esc(recommendation["recommended_action"].replace("_"," "))}</p></div>'
    else:
        body += '<div class="info-box">No recommendation yet. You can request a read-only analysis from your local Ollama model.</div>'
    body += '<details><summary>Technical record</summary><pre>'+esc(json.dumps(context,indent=2))+'</pre></details></section>'
    body += '<aside class="panel"><h2>Evidence sources</h2><p class="muted fine">Open a source to review the original observation.</p><ul>'
    for e in context['evidence'] + record['local_observations']:
        body += f'<li><a href="{esc(evidence_url(e))}">{esc(e["id"])}</a></li>'
    body += '</ul>'
    if record['local_observations']:
        body += '<span class="badge green">verified local observation</span><p class="help">Observed in a local synthetic test. This does not confirm a vulnerability.</p><pre>'+esc(json.dumps(record['local_observations'],indent=2))+'</pre>'
    body += f'<p><a class="text-link" href="/changes-export/{record["id"]}">Export sanitized JSON {icon("arrow")}</a></p>'
    if record['status'] in ('pending_analysis','model_unavailable','model_invalid','analysis_failed'):
        body += form_open('/changes/analyze',token,project)+f'<input type="hidden" name="investigation" value="{record["id"]}">'+consent('I authorize read-only Ollama analysis of this change.')+'<button class="primary">Request analysis / retry</button></form>'
    elif record['status'] == 'analyzing':
        body += f'<a class="button" href="{esc(url("/changes/"+str(record["id"]),project))}">Refresh analysis</a>'
    else:
        body += button('Review verification options','/verification',project)
    body += '<p class="help">This action never executes live verification or remediation.</p></aside></div>'
    return body


def knowledge_view(db_path,token,project,query):
    from . import knowledge
    from urllib.parse import quote
    sources=sorted(knowledge.status(db_path),key=lambda row:list(knowledge.SOURCES).index(row['source']))
    body='<section class="panel"><p class="eyebrow">Public reference library</p><h2>Keep your security knowledge current.</h2><p class="muted fine">Think of this as a library that receives new safety bulletins. Refreshing it updates saved reference records; it does not retrain Ollama or prove your project is vulnerable.</p>'
    if os.getenv('CYBERLAB_AUTO_INTELLIGENCE','1')!='1':
        body+='<div class="info-box">Automatic public updates are globally disabled for this process. Manual refresh still works. Enable automatic updates with the production installer’s --auto-intelligence option.</div>'
    body+='<div class="source-grid">'
    for row in sources:
        body+='<div class="source-card"><h3>'+esc(row['name'])+'</h3>'
        state='Stale / never refreshed' if row['stale'] else 'Fresh cache'
        body+=f'<p>{badge(row["state"])} <span class="badge {"amber" if row["stale"] else "green"}">{state}</span></p><p class="fine">{row["record_count"]:,} saved records</p>'
        body+=f'<p class="help">Last successful refresh (UTC): {esc(row["succeeded"] or "Never")}<br>Publisher update (UTC): {esc(row["source_updated"] or "Unknown")}</p>'
        if row['error_code']: body+='<p class="help">Last attempt: '+esc(row['error_code'])+'. Previous good records are retained.</p>'
        if row['coverage']: body+='<p class="help">'+esc(row['coverage'])+'</p>'
        body+=form_open('/knowledge/refresh',token,project)+f'<input type="hidden" name="source" value="{row["source"]}">'+consent('I approve downloading this public reference feed.')+'<button>Refresh this source</button></form>'
        body+='<details><summary>Automatic refresh preferences</summary>'+form_open('/knowledge/configure',token,project)+f'<input type="hidden" name="source" value="{row["source"]}">'
        body+=f'<label class="check"><input type="checkbox" name="enabled" value="yes" {"checked" if row["enabled"] else ""}><span>Automatically refresh this source</span></label><label class="form-label" for="feed-{row["source"]}">Refresh interval (seconds)</label><input class="field" id="feed-{row["source"]}" name="interval" type="number" min="300" max="604800" value="{row["interval_seconds"]}" required>'+consent('I approve these public-source refresh preferences.')+'<button>Save source preferences</button></form></details></div>'
    body+='</div></section>'
    q=query.get('q',[''])[0]; kind=query.get('kind',[''])[0]
    page_number=int(query.get('page',['0'])[0])
    if not 0<=page_number<=1000: raise ValueError('Invalid knowledge page')
    results=knowledge.search(db_path,q,kind,limit=16,offset=page_number*15)
    found=results[:15]
    body+='<section style="margin-top:24px"><div class="panel-head"><h2>Search the library</h2><a class="text-link" href="/help">What does this mean? →</a></div><form class="knowledge-search" method="get" action="/intelligence">'
    body+=f'<input type="hidden" name="project" value="{esc(project)}"><label class="form-label" for="knowledge-query">CVE ID, product, or attack technique</label><input class="field" id="knowledge-query" name="q" maxlength="200" value="{esc(q)}" placeholder="CVE-…, ransomware, credential access…"><label class="form-label" for="knowledge-kind">Reference type</label><select class="field" id="knowledge-kind" name="kind">'
    for value,label in [('','All references'),('exploited_vulnerability','Known exploited vulnerabilities'),('vulnerability','Recent vulnerability disclosures'),('attack_technique','Attack techniques')]:
        body+=f'<option value="{value}" {"selected" if value==kind else ""}>{label}</option>'
    body+='</select><p><button class="primary">Search references</button></p></form><p class="help">Global public references, not project findings. Up to 15 results per page are shown. Check source freshness above.</p>'
    if found:
        body+='<div class="table-wrap"><table><thead><tr><th>ID / source</th><th>Reference</th><th>Published / modified</th></tr></thead><tbody>'
        for row in found:
            href='/knowledge/'+row['source']+'/'+quote(row['external_id'],safe='')
            body+=f'<tr><td><code>{esc(row["external_id"])}</code><span class="record-sub">{esc(row["source"].upper())}</span></td><td><a href="{href}">{esc(row["title"])}</a></td><td class="fine">{esc(row["modified"][:10])}</td></tr>'
        body+='</tbody></table></div><div class="button-row" style="margin-top:18px">'
        if page_number:
            body+=f'<a class="button" href="{esc(url("/intelligence",project,q=q,kind=kind,page=page_number-1))}">← Previous results</a>'
        if len(results)>15:
            body+=f'<a class="button" href="{esc(url("/intelligence",project,q=q,kind=kind,page=page_number+1))}">Next results →</a>'
        body+='</div>'
    else: body+=empty('No matching references yet','Refresh a source above, wait for it to finish, then reload or try a different search.',symbol='globe')
    return body+'</section>'


def knowledge_detail(record):
    metadata=json.loads(record['metadata'])
    body=heading(record['external_id'],record['title'],button('Back to intelligence','/intelligence'),record['source'].upper())
    if record.get('archived_snapshot'): body+='<div class="info-box">Saved historical reference. The current publisher record may have changed or been withdrawn; verify current guidance before acting.</div>'
    body+='<div class="detail-grid"><section class="panel"><h2>What the publisher reports</h2><p>'+esc(record['summary']).replace('\n','<br>')+'</p>'
    if metadata.get('required_action'): body+='<h3>Publisher’s recommended action</h3><p>'+esc(metadata['required_action'])+'</p>'
    body+=f'<p><a class="text-link" href="{esc(record["reference"])}" rel="noopener noreferrer" target="_blank">Open official source ↗</a></p></section><aside class="panel"><h2>Read this correctly</h2>'
    if record['source']=='kev': meaning='Attackers have used this vulnerability somewhere. Check the affected product, installed version, and vendor guidance before deciding whether your project is affected.'
    elif record['source']=='attack': meaning='This describes a method attackers may use. Its presence in this library does not mean an attack occurred on your machine.'
    else: meaning='A vulnerability has been publicly disclosed. A disclosure alone does not establish that your project contains or exposes it.'
    body+='<p class="fine">'+meaning+'</p>'+f'<dl class="settings-list"><div><dt>Source modified (UTC)</dt><dd>{esc(record["modified"])}</dd></div><div><dt>Saved locally (UTC)</dt><dd>{esc(record["fetched"])}</dd></div></dl><p class="help">'+esc(metadata.get('applicability','Project applicability is not established.'))+'</p><p class="help">Saved reference revision (SHA-256):</p><code>'+esc(record.get('revision',''))+'</code></aside></div>'
    return body
