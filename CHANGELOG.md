# 4.13.0 — Local production profile and current reference intelligence

* Replaced the development HTTP transport with pinned, verified Waitress WSGI.
* Added request limits, bounded/deduplicated background jobs, an instance lock,
  private database permissions, WAL, release-transition backups and /healthz.
* Added an offline-capable production installer, stable launcher/configuration,
  tested staging before activation, retained previous releases, checksum checks,
  unmanaged-file protection and an opt-in systemd user service.
* Added persistent CISA KEV, CVE Program delta and MITRE enterprise ATT&CK reference
  ingestion from fixed official publisher repositories, with conditional requests,
  atomic cache replacement, generation/lease guards, freshness and audit states.
* Added a persistent CVE backlog so observed records beyond one batch carry forward,
  including when a later index returns not-modified. Coverage gaps remain explicit.
* Connected bounded related CVE references to AI context through root-proven OSV
  advisory aliases. This is retrieval, not model training or vulnerability proof.
* Added Intelligence search, paginated results, readable reference details and
  separate public-refresh preferences. Retained independent consent for active tests.
* Archived immutable public-reference revisions so historical citations survive
  publisher changes or removals. Interrupted jobs retain partial evidence and are
  marked for review after restart instead of silently replaying.
* Added How to Use navigation, a 21-topic ELI5/operator guide, in-app rendering,
  Markdown download and print/PDF support, plus production and attribution docs.
* Added Ubuntu/Python 3.10 and 3.12 CI checks, offline installation and package/source
  consistency verification. CI execution results are separate from local validation.
* Preserved the existing workflows and backend regression tests. Added feed,
  deployment, HTTP, backup, queue, provenance, checksum and refusal-path tests.

# CyberLab release history

## 4.12.0 — Unified workspace

* Replaced the stacked, version-labeled forms with a responsive light workspace,
  persistent navigation and separate pages for each task.
* Added overview metrics, project selection, activity tables, guided investigation
  choices, source-linked change reviews and readable status badges.
* Added project creation and a complete sample workspace with both an offline
  fixture and a localhost verification plan. Existing directories are never overwritten.
* Unified all existing capabilities into a single root-level application. Historical
  v4.11 source is retained only as a release archive.
* Centralized the release version in cyberlab/__init__.py; the UI, server banner,
  settings and HTTP user agents use it. Removed historical module version labels.
* Added a stable start.sh launcher and cyberlab-ai.zip package name; retained the
  prior launcher command as a compatibility wrapper.
* Added explicit model connectivity checking in Settings without triggering AI.
* Preserved existing POST endpoints, authorization/CSRF checks, scoped evidence,
  additive database migrations and offline operation.
* Added HTTP workspace regressions and a real Chromium browser workflow covering
  project creation, route comparison, change review, verification, monitoring and
  24 responsive page checks.

# v4.11 — based directly on v4.9

v4.10 was never created. The supplied v4.9 is preserved separately.

* Removed the unconditional Ollama availability check from the launcher.
* Added opt-in, bounded scheduled filename inventory monitoring, persisted
  configuration, pause/resume, graceful shutdown, and a separate scheduled AI opt-in.
* Added project-root identity and an index to change assessments with an additive
  migration; legacy snapshots remain readable and new roots get a fresh baseline.
* Baselines no longer report their initial routes as newly detected changes.
* Repeated identical assessments reuse one unchanged marker, limiting writes.
* Linear-time metadata grouping and filename metadata comparison; no source reads.
* Added idempotent change investigation records with genuine assessment references,
  strict Ollama schema/action/evidence validation, capped responses and bounded input,
  safe failure states, concurrency claims, restart recovery, and manual retries.
* Added conservative dynamic route relationships and explicit ambiguity rejection.
* Added dashboard monitoring controls, manual analysis, escaped detail pages,
  evidence links and sanitized JSON export.
* Added local Host validation, duplicate-form rejection, project scope checks,
  isolated data directory configuration, and root-level pages/api/index mapping fix.
* Kept all 39 baseline regression tests and added release-specific tests.

Not claimed: automatic remediation, zero-day detection, Ubuntu installation
verification, live Ollama compatibility, or complete implementation of the broader
system specification. Change recommendations include root-scoped prior evidence; legacy unknown-root records remain excluded.

## Completion follow-up

* Added canonical-root provenance to new hypothesis and localhost runs, with
  additive migrations and no identity inference for legacy records.
* Included up to 12 minimal prior evidence summaries in change analysis, with
  genuine event/run references, deterministic dynamic matching and safe status
  classifications. Actual observation provenance is displayed separately;
  later evidence never rewrites the saved model input.
* Fixed evidence links for different source types and display of verified local
  observations, which still cannot confirm vulnerabilities.
* Added generation checks for monitoring consent so stale scheduled AI and stale
  status updates cannot override a newer pause or settings change.
* Added standalone isolated smoke testing, optional real-model recommendation
  validation and deterministic ZIP packaging from an explicit file allowlist.
