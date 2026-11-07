# CyberLab AI v4.11

Local-first cybersecurity research dashboard, Python standard library only.
Built from the supplied **v4.9**, the last actual release. No v4.10 source or
installation is assumed. Recommendations are hypotheses, never confirmed flaws.

## Prerequisites and installation on Ubuntu

Python 3.10+ and Bash are required. Ubuntu 22.04+ meets the Python requirement.
No pip dependencies, Node.js, Docker, or Codex CLI is needed to run the app.
Codex is a development tool; it is already available in the prepared cloud environment.
Ollama with `llama3.2:latest` is optional and required only for AI features.
Install Ollama using its official platform instructions, then run
`ollama pull llama3.2:latest` if you choose to use those features.

Stop v4.9 first (Ctrl+C in its terminal). Preserve its installation. Before opening
an existing database with the new release, create a consistent SQLite backup:

```bash
mkdir -p ~/CyberLab-Backups
python3 - <<'PY'
from pathlib import Path
import datetime, sqlite3
source = Path.home()/'.cyberlab-v4/investigations.sqlite3'
if source.exists():
    destination = Path.home()/'CyberLab-Backups'/('before-v4.11-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.sqlite3')
    with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as old, sqlite3.connect(destination) as backup:
        old.backup(backup)
    print('Backup:', destination)
else:
    print('No existing database; first installation')
PY
unzip -n ~/Downloads/cyberlab_v4_11.zip -d ~/
cd ~/cyberlab_v4_11
python3 -m unittest discover -s tests -v
bash ./start-cyberlab-v4.sh
```

Open the dashboard locally at `http://127.0.0.1:8780`. Expected title: CyberLab AI
v4.11. Startup now works with Ollama absent. Do not expose this local dashboard
through a public proxy. Run one CyberLab process per database.

## Configuration and migration

Defaults: `~/.cyberlab-v4/investigations.sqlite3`, `~/CyberLab-Projects`, port 8780,
model `llama3.2:latest`. Overrides: `CYBERLAB_DATA_DIR`, `CYBERLAB_PROJECTS_DIR`,
`CYBERLAB_V4_PORT`, `CYBERLAB_MODEL`. Create the parent of a custom data directory
first. `CYBERLAB_LIVE_AI=1` retains the existing optional AI experiment selector.
It does **not** enable scheduled change analysis.

Startup applies additive table/index migrations, including canonical project
roots for new AI and localhost runs. Unknown legacy roots are never inferred. Existing investigation, risk,
memory, experiment, and history records are retained. Legacy inventory rows lack
a canonical project root, so the first v4.11 assessment establishes a new baseline
instead of guessing which project owned them. The old rows remain viewable.
Only direct project folders under the approved projects root are accepted by the
web UI, preventing same-name nested projects from mixing legacy evidence.

## Demonstration and monitoring

```bash
cd ~/cyberlab_v4_11
python3 scripts/setup_demo.py
# Optional separate terminal, for the existing approved localhost test plan:
python3 scripts/demo_local.py
```

1. On the dashboard, assess `demo` and confirm project authorization. The first
   assessment is a baseline, not a change event.
2. Create a synthetic route, e.g.:
   `mkdir -p ~/CyberLab-Projects/demo/app/api/review-demo` then
   `touch ~/CyberLab-Projects/demo/app/api/review-demo/route.ts`.
3. Assess again. Follow the new Change investigation link to the exact added
   route, current assessment, and previous assessment evidence.
4. Optionally request read-only Ollama analysis. With Ollama absent the status is
   `model_unavailable`; deterministic assessment still works. Successful analysis
   yields `recommended_review` and evidence-linked, unconfirmed hypotheses.
5. To monitor, enter `demo`, choose an interval (30–86400 seconds), check
   Enable/resume, authorize, and save. Monitoring and scheduled Ollama are both
   off by default. Scheduled AI requires its own explicit opt-in checkbox.
   Uncheck Enable/resume and save to pause. An in-flight assessment may finish.

Only new changes are scheduled for AI analysis; unavailable or invalid models
require a manual retry. Processes do not persist across a shutdown; restart the
launcher to resume enabled settings. Ctrl+C or SIGTERM gracefully stops the
monitor. There is no systemd service or OS-level persistence.

Recommendations are read-only. To perform existing localhost GET verification,
review the synthetic plan and explicitly authorize that separate dashboard form.
A recommendation cannot run tools, change a plan, remediate code, or merge patches.

## Validation and expected results

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify_ollama.py  # optional, needs a running real Ollama/model
```

For a quick functional test with an isolated temporary database and projects:

```bash
python3 scripts/smoke_test.py
# Also require a real local model and a validated change recommendation:
python3 scripts/smoke_test.py --live-ollama
# Rebuild the ZIP deterministically from the current source:
python3 scripts/package_release.py
```

The offline smoke test prints PASS and exits zero only when its selected real
HTTP, restart, authorization, monitoring and provenance tests pass. The optional
live check returns nonzero when Ollama is unavailable or rejects the change schema.
Neither command touches your personal database.

The test suite includes real local HTTP requests, safe synthetic verification,
mocked models, migration, persistence, pause/resume and concurrency checks. See
TEST_RESULTS.md for observed counts and live-integration limitations.
`verify_ollama.py` must print `PASS: Live Ollama JSON response verified.` and exit
zero for a live integration pass. A failure is separate from the offline suite.

## Limitations

* Inventory reads filenames, not source content, HTTP methods or access-control
  logic. Only added/removed paths and filename metadata changes are detected;
  editing source without changing filenames is invisible.
* One unchanged marker is saved after each transition; further identical
  assessments reuse it. Change events remain immutable and unique per assessment.
* AI context includes current/previous inventory evidence and at most 12
  root-scoped, sanitized prior hypothesis/localhost-observation references.
  Legacy records lack root identity and remain excluded; existing history pages
  still work. No raw hypothesis prose, bodies or credentials enter this context.
  Later observations are displayed separately without changing the saved prompt.
* Dynamic matching supports exact paths and an unambiguous single-segment
  `[parameter]`. Catch-all and optional/group patterns are unsupported; ambiguous
  matches are rejected. Relationships never confirm vulnerabilities.
* Model field/action/evidence validation cannot prove the truth of model prose.
  Review every recommendation. No vulnerability confirmation is automated.
* NVD ingestion, vector databases, automatic patch generation, and broad dynamic
  scanning from the aspirational specification are not implemented by this release.
* Ubuntu and real Ollama validation must be completed on your machine; the current
  cloud validation used Debian and mocked Ollama responses.

## Rollback

Stop v4.11. Keep its database as a separate archive if you want its new history.
For a clean rollback, restore the pre-upgrade SQLite backup to a **different data
directory** first, verify it with SQLite `PRAGMA integrity_check`, and then choose
when to replace your active database while all CyberLab processes are stopped.
v4.9 does not support `CYBERLAB_DATA_DIR`, so its default database path must hold
the chosen backup before launching the preserved v4.9 installation. Never copy a
backup over a live SQLite database or delete an installation to roll back. New
v4.11 history will not exist in a pre-upgrade backup.
