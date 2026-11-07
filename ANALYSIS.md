# Local production transition

The previous unified interface ran on Python's development HTTP server and did
not provide a persisted, freshness-aware global threat reference library. This
release keeps its existing local authorization boundaries but replaces the HTTP
transport with Waitress and adds explicit resource limits and lifecycle controls.

Production installation stages and tests a private release before changing the
stable current pointer. Data lives outside code. Both installer and runtime make
consistent, exclusive SQLite backups instead of overwriting an existing notebook.
The managed installation marker prevents accidental replacement of unrelated files.
The optional user unit is generated with correct per-setting path quoting and was
checked by systemd-analyze; this does not establish actual Ubuntu service startup.

Public-source ingestion is separate from project jobs and model inference. CISA
and ATT&CK snapshots are parsed completely inside fixed response budgets and
committed atomically. CVE deltas feed a durable bounded backlog; completed records
and pending work have distinct states. Source failures retain previous good data.
Both the public library and its UI expose provenance, freshness and coverage limits.

The library is not a fine-tuning pipeline. Related records are retrieved only after
an explicit root-proven package advisory check provides matching CVE aliases.
Model-selected evidence IDs still must exist in the bounded supplied context;
reference records never become proof of an application vulnerability by association.

The current architecture is a single-user local production profile. Remote user
accounts, broad dynamic scanning, universal language support, complete historical
CVE mirroring and autonomous remediation are not implied by this transition.

Earlier implementation notes follow for history.

# Unified workspace design and implementation

The old dashboard exposed the release history as separate version-labeled forms.
It repeated the project input and safety text, hid the workflow, and made every
capability compete for attention on a long page. The source layout also suggested
that users should choose between independent programs.

The current application retains the existing backend capabilities and data model,
but uses a shared server-rendered frame, task navigation and selected-project
context. The overview presents real database counts and activity; it does not
invent a security score or claim that a project is safe. New investigation choices
dispatch to the existing allowlisted controllers. The separate verification page
keeps consent for active checks explicit. Detail pages share the workspace style;
change reviews prioritize readable route changes and recommendations, with raw
technical metadata collapsed behind an expander.

The UI requires no JavaScript, CDN, fonts or third-party runtime dependencies.
All content is escaped and the CSS is served from a fixed allowlisted asset path
under the existing CSP. Mobile navigation keeps every destination accessible;
activity tables hide redundant columns on small screens instead of clipping text.
Project creation uses a bounded name and exclusive directory creation, never
an overwrite. History filters use exact project names/roots rather than LIKE
patterns, avoiding wildcard confusion in names containing underscores.

The source now has one root-level Python package, scripts directory and test suite.
The version constant drives visible release metadata and HTTP user agents. ZIP
packaging includes CSS explicitly and keeps one stable application root and name.
Historical releases remain archives, not alternative current source directories.

Earlier inspection notes follow for engineering history.

# Inspection and optimization report

The supplied archive contains v4.9, not the v4.10 described in the handoff.
Its baseline has 39 passing tests and uses Python's standard library. It already
provides read-only route discovery, OSV dependency checking, synthetic experiments,
explicitly approved localhost GET verification, Ollama hypotheses, and risk/memory
correlation. It is not the autonomous patching platform described by the broader
specification.

Concrete findings addressed in the separate v4.11 tree:

* The launcher required Ollama for all features despite deterministic workflows.
* Every unchanged assessment inserted another identical snapshot.
* First-baseline details presented every route as added.
* Assessment history was keyed by basename only and lacked a project-root index.
* Change comparison tracked route names only, losing filename metadata changes.
* No scheduled monitoring or evidence-linked change recommendation pipeline existed.
* Dashboard POST validation accepted duplicate fields; Host headers were unrestricted.
* pages/api/index.ts mapped incorrectly to /api/index.
* Package __version__ still said 4.1.0.

The implementation keeps legacy code and tests, adds targeted checks for the new
workflow, and avoids external dependencies. Deduplication retains one explicit
unchanged marker for compatibility with v4.9's status API. No claim of overall
CPU or throughput improvement is made without a workload benchmark.

The completion follow-up adds root provenance to new hypothesis/observation
runs and admits bounded, sanitized, deterministic summaries into change analysis.
Legacy name-only rows are preserved and excluded rather than guessing ownership.
Monitoring settings now carry a generation counter, checked transactionally when
claiming scheduled AI; stale work cannot override newly saved pause settings. The broader NVD/vector/patching specification remains future work.
Monitor settings support one process per database, not distributed scheduling.
Model prose is untrusted even when its JSON schema and evidence IDs are valid.
