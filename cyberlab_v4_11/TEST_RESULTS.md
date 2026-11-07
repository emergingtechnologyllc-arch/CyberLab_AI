# Validation results — November 7, 2026

Host: Debian GNU/Linux 13 cloud environment, Python 3.12.14.
No user Ubuntu machine or production database was accessed.

| Check | Result |
|---|---|
| Supplied v4.9: `python3 -m unittest discover -s tests -v` | 39 passed, 0 failed, 0 skipped |
| v4.11: same command | 67 passed, 0 failed, 0 skipped |
| Fresh release ZIP extraction: same command | 67 passed, 0 failed, 0 skipped |
| `python -m py_compile cyberlab/*.py` | Passed |
| `python3 scripts/smoke_test.py` | 6 passed; offline functional checks passed |
| `python3 scripts/smoke_test.py --live-ollama` | Offline 6 passed, then failed exit 1: Ollama connection refused |
| Two deterministic package builds | Identical SHA256 hashes |
| Running launcher, isolated cloud data/projects directories | Started without Ollama |
| Representative dashboard HTTP GET | 200, v4.11 change controls present |
| 100 identical assessments, fresh DB | 2 rows: baseline + one unchanged marker |
| `python3 scripts/verify_ollama.py` | Failed, exit 1: loopback connection refused |
| Ubuntu validation | Not run; current host is Debian |
| Real Ollama recommendation | Not run; no Ollama service/model installed here |

The 28 new tests cover baseline semantics, unchanged deduplication, added/removed
and filename metadata changes, project-root isolation, conservative dynamic matching,
legacy migration, invalid model actions/evidence/JSON, timeout/unavailable model,
restart recovery, concurrent analysis and assessment, opt-in monitoring, pause/resume,
root index mapping, real HTTP dashboard/export/history/security behavior, root-scoped
prior evidence, sanitized exports, event links, observed local status, and revocation
of scheduled AI during in-flight assessment.

The HTTP subprocess tests use temporary data and projects. They create a synthetic
route change, persist a mocked recommendation linked to actual assessment IDs,
check HTML escaping and JSON export, stop/restart the app, and verify retained
recommendations and paused settings. They check risk, memory, and assessment pages;
the original 39 tests retain existing experiment and localhost-verification checks.
No assertion was removed or skipped to obtain a passing result.

No CPU throughput benchmark was run. The measured optimization is write-count
reduction on stable inventories; 100 calls used to produce 100 rows and now produce
a baseline and a single unchanged marker. Future route transitions retain their
own assessment history.

Offline smoke checks also pass from a fresh ZIP extraction.
All AI successes in the suite use mocked responses. Real local HTTP test traffic
is synthetic and does not establish application vulnerabilities. A status mismatch
remains a review signal. An Ubuntu operator should run the live Ollama check after
installing/starting Ollama and the configured model, then exercise a manual change
recommendation in the dashboard.
