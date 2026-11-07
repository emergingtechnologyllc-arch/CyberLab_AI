# CyberLab 4.13.0 — local production validation

Host: Debian GNU/Linux 13, Python 3.12.14, Waitress 3.0.2. Optional browser tooling:
system Chromium/Playwright. No personal Ubuntu installation or database was accessed.

## Executed checks

| Check | Observed result |
|---|---|
| Complete regression suite | 108 passed, 0 failed, 0 skipped |
| Isolated offline smoke | 14 passed; exit 0 |
| Waitress health, HEAD/method/body limits | Passed real HTTP checks |
| Public CISA KEV download and normalization | Passed: 1,769 saved records |
| Public MITRE enterprise ATT&CK download/normalization | Passed: 706 active technique records |
| Public CVE Program delta and documents | Passed; initial 1-record delta, later windows processed |
| Persistent CVE backlog | Live run processed 20 records and retained 4 pending; mocked 304 catch-up passed |
| Actual production installer | Passed offline hash-verified dependency install and isolated smoke before activation |
| Stable installed launcher | Running; /healthz returned status ok, transport waitress, database ok, intelligence worker running |
| Generated systemd user unit syntax | Passed systemd-analyze --user verify after setting XDG_RUNTIME_DIR to a writable temporary directory |
| Actual systemd service enable/start | Not run; no live Ubuntu user manager available in this cloud validation |
| Chromium application workflow | Passed project, investigation, comparison, change review, verification, monitoring |
| Responsive browser checks | 27 pages: nine destinations × desktop/tablet/phone sizes |
| Browser live-cache search/detail and guide | Passed actual cached references and in-app guide |
| Live OSV request | Blocked by this cloud's outbound proxy: HTTP tunnel 403 |
| Live NVD connectivity probe | Blocked by this cloud's outbound proxy: HTTP tunnel 403; NVD integration is not implemented |
| Real Ollama inference | Not verified; no local Ollama service in this execution environment |
| Ubuntu 4.13 runtime/service/model acceptance | Not run; requires the user's Ubuntu host |

Source counts are observations from the validation run, not immutable current-world
statistics. Publisher contents can change. The CVE library grew to 41 stored records
as later windows arrived; a bounded backlog is explicitly separate from saved records.
A fresh delta/window does not imply a complete historical CVE mirror.

## Regression and failure-path evidence

The original 39 backend regressions remain, with the existing UI/4.11/4.12 tests.
New production checks cover atomic cache replacement, invalid snapshots, no-cache
304 handling, successful conditional refresh, fixed publisher destinations,
CVE rejection, durable backlog and 304 processing, cancellation on changed source
preferences, duplicate leases, literal search, stale-state persistence, root-proven
advisory aliases, source context links, and immutable historical reference revisions.

Runtime tests cover bounded/deduplicated jobs, cancellation of queued work during
shutdown, single-instance locking, consistent private/exclusive backups, release
transition backups, interrupted-run recovery and directory-walk budgets. Installer tests cover per-setting
systemd path quoting, symlink refusal, unmanaged-file protection, code/config
activation with previous-release retention, and rejection of a tampered wheel.

HTTP tests cover production health, HEAD, unsupported methods, body limits, existing
CSRF/authorization rules, new source configuration validation, the guide/download,
project isolation, restart persistence and existing risk/memory/history endpoints.
Offline tests use temporary data/projects and disable public background refresh;
they do not replace public network tests or real-model checks with a passing label.

## Release gates

The independent fresh ZIP extraction passed the full 108-test suite, all 14 smoke
checks, the Chromium workflow and 27 responsive page checks. Installation from that
extraction passed its offline hash-verified runtime installation and smoke gate.
An actual installed-instance reinstall retained saved paths, port and refresh
preferences, kept the previous code release, created a database backup, and showed
the original baseline evidence after restart. The installed printable PDF download
was checked for a valid PDF signature.

Two package builds from identical source produced matching SHA256 hashes. The
shared allowlist includes the production wheel, Markdown/operations guides and a
9-page printable PDF, while excluding caches, virtual environments, databases,
credentials and historical release archives. The PDF was inspected and its text
was extracted to confirm the first/last topics, installation commands and coverage
limitations; it contains no JavaScript.

Ubuntu/Python 3.10 and 3.12 CI jobs were added for regression, offline installation
and package/source consistency checks. Their remote execution result is not claimed
by these local validation results.

## Interpretation

This is an implemented and tested **single-user local production profile**, not a
security certification or an Internet-facing multi-user service. Model successes
in the regression suite use mocks. Source data is public reference context, never
proof of project exploitability. An observation/status mismatch alone is not a
confirmed vulnerability. Keep Ubuntu service, live-model and external OSV results
separate from the cloud checks that actually passed.

The OSV hostname has been added to the cloud configuration draft for review; saving
that draft is not proof that outbound access has been applied or verified.
