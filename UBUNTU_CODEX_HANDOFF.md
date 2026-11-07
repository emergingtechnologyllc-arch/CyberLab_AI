# CyberLab development handoff

This repository now contains **one application at the repository root**. Do not
create another version-specific source folder. The authoritative release version
is `cyberlab/__init__.py`; update it and CHANGELOG.md as development moves forward.
The current release is 4.12.0. The old v4.11 archive is historical, not current code.

## Work in the existing checkout

```bash
python3 -m unittest discover -s tests -v
python3 scripts/smoke_test.py
bash ./start.sh
```

Python 3.10+ and Bash suffice; no runtime pip/npm installation or frontend build
is needed. `start-cyberlab-v4.sh` remains a compatibility wrapper. The dashboard
binds to loopback port 8780. Use isolated `CYBERLAB_DATA_DIR` and
`CYBERLAB_PROJECTS_DIR` during development; never overwrite a personal database.
Read README.md for backups, migration, rollback and the unified interface workflow.

## GUI and versioning

`cyberlab/ui.py` renders the shared frame and task pages. `cyberlab/assets/app.css`
contains the responsive design. The server serves that fixed asset path under CSP;
no JavaScript/CDN dependencies are needed. The selected project travels with
navigation and forms. Preserve backend authorization/CSRF checks, source links,
root-scoped evidence and separate consent for localhost verification.

Keep the overview concise. Keep specialized actions on their respective pages.
Do not reintroduce historical module versions or the old stack of duplicate forms.
Run the optional real-browser development check (requires Playwright/Chromium):

```bash
python3 scripts/browser_check.py --screenshots /tmp/cyberlab-ui-review
```

It creates an isolated application instance, uses real forms to create a sample
project and evidence, and checks eight pages at desktop/tablet/phone sizes.

## Validate and deliver

The cloud suite has 76 passing tests, plus a standalone smoke workflow and Chromium
browser checks. Fresh-extraction results and platform limits are in TEST_RESULTS.md.
Ubuntu users previously verified the v4.11 offline smoke test; **v4.12 Ubuntu and
real Ollama remain unverified here**. Do not relabel Debian or mocked checks as
Ubuntu/live-model results.

```bash
python3 scripts/smoke_test.py --live-ollama
python3 scripts/package_release.py
```

The optional live smoke must obtain a real local model response and validate a
change recommendation against actual evidence IDs. When Ollama is absent, report
the actual failure separately and continue offline work.

The package command rebuilds `cyberlab-ai.zip` with a stable `cyberlab-ai/` root,
including CSS, Python, tests and docs while excluding history archives, secrets,
databases and caches. Run tests from a fresh extraction before publication.
Preserve existing features and data. Prior evidence is used only with proven
canonical-root provenance; legacy unknown-root rows remain viewable but excluded.
Do not implement arbitrary model commands or automatic remediation/merging.
