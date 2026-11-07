# CyberLab local-production handoff

The single current application is at the repository root. Version source:
cyberlab/__init__.py, currently 4.13.0. Never create a parallel version-specific
source tree. Read HOW_TO_USE.md, PRODUCTION.md and TEST_RESULTS.md first.

Install with `python3 scripts/install_production.py` from the extracted current
source root. Its pinned/hash-verified Waitress wheel is bundled for offline runtime
installation. It backs up existing SQLite data, stages/smoke-tests a private release,
then switches the stable launcher. Use the same data/projects paths as the existing
app when preserving history. No normal-user install needs sudo except separately
installing Ubuntu python3-venv if absent. `--enable-service` explicitly opts into a
systemd user service; cloud syntax checks are not Ubuntu service-start evidence.

Default public-source refresh retrieves CISA KEV, CVE Program deltas, and MITRE
enterprise ATT&CK from fixed official GitHub publisher URLs. No model weights are
trained. Observed CVEs are durably queued and processed in bounded batches. Cache
freshness, coverage gaps and errors remain explicit. Immutable record revisions
preserve citations after source changes. Root-proven OSV aliases gate related CVE
retrieval into AI context; public records never prove project exploitability.

The source/runtime checks include 108 passing unit/integration regressions, 14
isolated smoke checks, browser workflow and 27 responsive page checks. See actual
release extraction/installer results in TEST_RESULTS.md. Live CISA/CVE/ATT&CK were
verified; OSV and NVD requests were denied by the cloud network. NVD integration is
not implemented. Real Ollama and actual Ubuntu user-service operation remain unverified.

For development:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links vendor --require-hashes -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/smoke_test.py
```

Optional real integration: `.venv/bin/python scripts/smoke_test.py --live-ollama`.
Public refresh CLI: scripts/refresh_intelligence.py with an explicit --data-dir.
The /healthz endpoint verifies runtime/database liveness, not feed/model success.

Optional Playwright/Chromium tools: scripts/browser_check.py and
scripts/build_guide_pdf.py. They are development tools, not runtime dependencies.
The in-app guide uses HOW_TO_USE.md; regenerate the printable PDF after edits.

Release packaging uses cyberlab/distribution.py's shared allowlist and dependency
checksum validation. `python3 scripts/package_release.py` creates cyberlab-ai.zip.
Include the guides/PDF and wheel; exclude personal data, virtualenvs and old releases.
Test a fresh extraction and the installer before publishing. Do not call Ubuntu,
Ollama, external OSV, or systemd activation verified without actual target-host evidence.
Preserve authorization, root isolation, separate approval for active verification,
loopback-only binding, CSRF, bounded jobs, backups and existing evidence. Never
execute model-provided commands or silently replay interrupted verification jobs.
