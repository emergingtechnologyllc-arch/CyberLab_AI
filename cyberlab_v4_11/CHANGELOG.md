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
