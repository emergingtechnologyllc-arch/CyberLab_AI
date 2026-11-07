# CyberLab 4.12.0 validation

Validation host: Debian GNU/Linux 13, Python 3.12.14. Browser: system Chromium
controlled by Playwright. No personal Ubuntu installation or database was changed.

| Check | Result |
|---|---|
| `python3 -m unittest discover -s tests -v` | 76 passed, 0 failed, 0 skipped |
| `python3 scripts/smoke_test.py` | 11 passed; PASS, exit 0 |
| Fresh ZIP extraction: full suite | 76 passed, 0 failed, 0 skipped |
| Fresh ZIP extraction: standalone smoke | 11 passed; PASS, exit 0 |
| `python3 scripts/browser_check.py --screenshots …` | Passed functional workflow and 24 responsive page checks |
| `python3 -m py_compile cyberlab/*.py` | Passed |
| Deterministic ZIP builds from identical source | Identical SHA256 hashes |
| Legacy `start-cyberlab-v4.sh` wrapper | HTTP 200 with current CyberLab release |
| Real Ollama for this release | Not run; no local service/model available |
| Ubuntu 4.12 acceptance | Not run; cloud host is Debian |

## What ran

The 76-test suite retains all original 39 backend regressions and tests added in
the v4.11 work. UI-specific assertions were updated for the deliberate navigation
and version changes; authorization, persistence and evidence assertions remain.
The new checks cover all workspace routes, CSS delivery, fixed asset paths,
non-destructive project creation, sample files, invalid paths and modes, CSRF,
project context, literal project-name filtering and read-only model-tag checks.

The standalone smoke command starts its own isolated subprocess with temporary
storage. It exercises real HTTP requests and restarts, source-linked evidence,
project creation, authorization rejection, monitoring pause/resume and provenance.
It neither reads nor changes the user's personal database.

The Chromium workflow uses actual forms to create a sample project, establish a
baseline, add a real synthetic route file, compare it, open the resulting change
review, run an offline verification, and enable/pause monitoring. It confirms that
scheduled AI stays off unless opted in. It visits Overview, Projects,
Investigations, Monitoring, Intelligence, Evidence, Verification and Settings at
1440×1000, 768×1024 and 390×844, checking successful responses and absence of document
horizontal overflow. Screenshots were inspected; mobile navigation exposes every
destination and activity tables remove redundant columns on narrow screens.

Fresh package tests execute **inside the extracted application directory**, so
imports, launchers and CSS are verified independently of the original checkout.
The ZIP contains no caches, databases, .env files or prior release archives.

## Limits

AI successes in regression tests use mocks. The Settings connection check reads
Ollama's model list; this alone does not establish generation compatibility.
Use `python3 scripts/smoke_test.py --live-ollama` on a machine with Ollama/model
running to require a real schema-valid recommendation tied to actual evidence.
The previously observed live smoke failure was connection refused on loopback.
Offline tests do not validate external OSV access.

The user reported a successful v4.11 smoke test and launcher on Ubuntu. That is
not a v4.12 Ubuntu result. The new GUI was tested in Chromium on Debian; the user
must verify their installed browser and local model after upgrading.

No vulnerability was confirmed. Test status mismatches are synthetic observations,
and AI suggestions remain read-only until a separate verification is approved.
