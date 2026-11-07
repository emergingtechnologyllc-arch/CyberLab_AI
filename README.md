# CyberLab

One local security workspace for project discovery, investigations, monitoring,
intelligence, verification and evidence. All capabilities run in one application,
with one release version.

![CyberLab workspace](docs/overview.png)

[Download the current program](https://github.com/emergingtechnologyllc-arch/CyberLab_AI/raw/refs/heads/main/cyberlab-ai.zip)

## Run

Requires Python 3.10+ and Bash (Ubuntu 22.04+). No pip packages, Node.js, or build
step is needed to run CyberLab. Ollama is optional for AI features.

Unzip `cyberlab-ai.zip` into a **new directory**, then:

```bash
cd cyberlab-ai
python3 scripts/smoke_test.py
bash ./start.sh
```

Open `http://127.0.0.1:8780`. Stop the old CyberLab process before using the same
port. `start-cyberlab-v4.sh` remains a compatibility wrapper for `start.sh`.

## The workspace

- **Overview**: project counts, changes awaiting review and recent activity.
- **Projects**: open a project, create a workspace, or create a synthetic sample.
- **Investigations**: choose route discovery, change comparison, local AI review,
  or a bounded local application investigation in one guided form.
- **Monitoring**: compare now, configure schedules, pause/resume and review changes.
- **Intelligence**: check declared npm dependencies against OSV advisories.
- **Evidence**: browse history, correlate risk indicators and build evidence memory.
- **Verification**: explicitly approve offline experiments or localhost test plans.
- **Settings**: see storage, release and model configuration; check Ollama connectivity.

Select a project in the top bar once and keep that context as you navigate.
Tools open the first available project when no context is supplied; selecting
“All projects” keeps a global view. Task forms require a project except for a
local-target-only investigation.

### Try it without configuring an application

1. Open **Projects → Add a project**. Give it a name and select **Include a sample
   project with synthetic routes**. Authorize creating the local folder.
2. Open that workspace and start **Review project changes**. The first comparison
   establishes a baseline; it does not invent a change.
3. Run **Verification → Synthetic experiment** to create offline test evidence.
4. See results in **Evidence**. Add/remove a sample route file and compare again
   to see a persisted change review with source links.
5. Enable **Monitoring** only if desired. Scheduled AI has a separate opt-in.

Sample localhost plans target `127.0.0.1:3999`. To use those plans, run
`python3 scripts/demo_local.py` in a separate terminal and authorize the localhost
checks in Verification. The offline experiment does not need this server.

## Upgrade and preserve data

The former version directories are replaced by a single source tree. The prior
v4.11 ZIP is retained in `releases/` for reference. Earlier capabilities are
part of the current application; you do not launch them separately.

The default database remains `~/.cyberlab-v4/investigations.sqlite3` and the default
projects folder remains `~/CyberLab-Projects`. New code uses additive migrations;
existing histories are preserved. Unknown legacy project roots are never guessed.
No database is included in the ZIP.

Before opening an existing database, stop CyberLab and make a consistent backup:

```bash
mkdir -p ~/CyberLab-Backups
python3 - <<'PY'
from pathlib import Path
from datetime import datetime
import os, sqlite3
root = Path(os.getenv('CYBERLAB_DATA_DIR', str(Path.home()/'.cyberlab-v4')))
source = root/'investigations.sqlite3'
if source.exists():
    destination = Path.home()/'CyberLab-Backups'/('cyberlab-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.sqlite3')
    with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True) as old, sqlite3.connect(destination) as backup:
        old.backup(backup)
    print('Backup:',destination)
else:
    print('No database at:',source)
PY
```

If you used a custom data/projects directory in the previous release, use the
**same environment variables** for backup and the new launcher:

```bash
CYBERLAB_DATA_DIR=/your/existing/data \
CYBERLAB_PROJECTS_DIR=/your/existing/projects \
bash ./start.sh
```

If v4.11 was installed in a temporary test directory, its data is under that
parent directory's `data/` and `projects/`, not necessarily the default locations.
Settings in the running old app show the paths. Keep the old installation until
you have checked your evidence in the new one.

To roll back: stop the new process, preserve its database separately, and use a
pre-upgrade backup with the preserved old installation. Never copy a backup over
a running database. Newer evidence will not appear in a pre-upgrade backup.

## Configuration

| Variable | Default |
|---|---|
| `CYBERLAB_DATA_DIR` | `~/.cyberlab-v4` |
| `CYBERLAB_PROJECTS_DIR` | `~/CyberLab-Projects` |
| `CYBERLAB_MODEL` | `llama3.2:latest` |
| `CYBERLAB_V4_PORT` | `8780` |
| `CYBERLAB_LIVE_AI` | off; existing optional local test selector |

Storage/model settings take effect on restart. Existing project folders directly
under the configured project root appear automatically; symlinks are excluded.
Create the parent of a custom data directory before startup. Run one CyberLab
process per database. The dashboard binds to loopback; it is not a public service.

## Tests

```bash
python3 scripts/smoke_test.py               # isolated functional checks
python3 -m unittest discover -s tests -v    # complete regression suite
python3 scripts/smoke_test.py --live-ollama # additionally require real local AI
```

Offline tests create temporary databases and project folders. They do not modify
your personal database. Live-model checks fail with a nonzero exit status when
Ollama/model/schema validation is unavailable; they are not replaced by mocks.

Optional development browser checks require Playwright and an installed Chromium:

```bash
python3 scripts/browser_check.py --screenshots /tmp/cyberlab-ui-review
```

The browser check launches its own isolated server and verifies the full project
workflow and eight pages at desktop, tablet and phone widths. These browser tools
are **not runtime dependencies** of CyberLab.

## Releases going forward

`cyberlab/__init__.py` is the authoritative release version. The application frame,
settings, server banner and request user agents read it. Update it for each release
and describe changes in CHANGELOG.md; do not create another version-specific source
folder or put historical module versions in the interface.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/smoke_test.py
python3 scripts/package_release.py
```

Packaging deterministically rebuilds `cyberlab-ai.zip` with a stable `cyberlab-ai/`
root from an explicit allowlist. It includes Python, CSS, launchers, tests and docs;
it excludes database files, caches, credentials and historical releases. Test a
fresh extraction before publishing. Existing data directories keep their names
across releases so a version bump never silently creates a new database.

## Scope and limits

Route discovery reads filenames, not source contents or authorization logic.
Model input is bounded metadata and sanitized root-scoped evidence references.
Models return hypotheses, not confirmed vulnerabilities. Recommendations cannot
run tests, commands, remediation or merges. Local verification requires separate
explicit approval and bounded synthetic-account test plans.

Ollama failures do not stop offline workflows. Monitoring runs only while CyberLab
is open; no OS-level service is installed. Catch-all/ambiguous dynamic routes are
not correlated. Legacy evidence without root provenance stays viewable but is
excluded from new root-scoped model context.

The larger NVD/vector-database/autonomous-remediation specification is future work,
not a capability claim. See [TEST_RESULTS.md](TEST_RESULTS.md) for platform and
live-model validation limits, and [ANALYSIS.md](ANALYSIS.md) for engineering context.
