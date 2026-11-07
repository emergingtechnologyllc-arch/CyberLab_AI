# Local production deployment

CyberLab 4.14 uses Waitress 3.0.2 as a pinned, hash-verified WSGI transport. It is a
single-user local application, not a publicly exposed multi-tenant service. See
HOW_TO_USE.md for the complete plain-language operator walkthrough.

## Installation

Run as the normal Ubuntu user from the extracted application root:

```bash
python3 scripts/install_production.py
```

Optional flags: `--data-dir`, `--projects-dir`, `--prefix`, `--model`, `--port`,
`--no-auto-intelligence`, and `--enable-service`. Existing saved paths are retained
on subsequent installer runs unless overridden. Defaults are private data at
`~/.cyberlab-v4`, projects at `~/CyberLab-Projects`, and the stable launcher at
`~/.local/share/cyberlab/start.sh`.

The installer validates its release allowlist and vendored wheel checksum, backs
up an existing database, copies code to a new managed release directory, creates
an isolated virtual environment, installs the wheel offline with pip hash checks,
and runs isolated smoke checks before activation. A previous code release is
retained behind the stable install prefix for recovery; there is one current app.
The wheel excludes the need for a production package-index download. Python venv
support is required (`python3-venv` on Ubuntu when not already installed).

No service is installed or started unless `--enable-service` is requested. That
option manages a marked systemd user unit and refuses to overwrite an unrelated
unit or kill an unknown process occupying the port. The user manager must be
available; login persistence and lingering depend on the host configuration.
The cloud environment does not prove Ubuntu user-service operation.

## Runtime boundaries

- Bind: 127.0.0.1 only. Exact local Host validation and CSRF/authorization remain.
- Waitress: four request threads, 50 connection limit, 30-second channel timeout,
  16 KB header limit, 8 KB transport body limit, 4 KB application POST limit.
- Background user jobs: two workers, six total queued/running slots, deduplicated
  action keys. Busy responses return 429.
- One application process per data directory, enforced with a Linux file lock.
- Private umask and database file permissions, SQLite WAL, bounded connection waits.
- Existing SQLite database is backed up before first use by a new release; additive
  migrations preserve records. Backup files are mode 0600 and integrity checked.
- SIGTERM/Ctrl+C stop scheduled work, cancel not-yet-started user jobs, and close
  the job/HTTP workers. Public CVE backlog records remain persistent. Service stop
  timeout is 120 seconds to accommodate bounded in-flight package/model requests.
- Errors exposed by new feed/runtime paths use short error codes, not raw remote
  bodies, prompts, request payloads or secrets.

After an unexpected exit, interrupted user runs are marked as errors on restart,
with their partial observations preserved and no automatic replay. Recovery counts
are audited. Public source leases expire independently so a concurrent explicit
CLI refresh is not mistaken for an abandoned application job.

No remote account system, TLS termination, SSO, public API, or organizational
multi-user access is provided. Run on a trusted local workstation. Do not make the
loopback dashboard Internet-accessible. This is an implemented and tested local
production profile, not a certification or a promise of complete threat coverage.

## Public intelligence

The library contains separately timestamped CISA KEV, recent CVE Program records,
and MITRE enterprise ATT&CK techniques. Sources are fixed official GitHub publisher
URLs. TLS validation stays enabled; redirects and advisory-provided fetch URLs are
not followed. CVE document URLs are derived from strict CVE identifiers.

KEV and ATT&CK are atomically replaced only after a complete bounded parse; failed
refreshes retain good cache data. CVE updates use the publisher's current bounded
delta windows (maximum 20 documents processed per refresh). Observed but unprocessed
records are queued persistently, including when the next index is unchanged. Rejected
CVEs are deleted when seen. This does not backfill every vulnerability and can miss
unobserved deltas during offline periods or between publisher windows. The UI reports this coverage limitation even when the refresh is fresh.

Normalized reference revisions are archived for stable historical citations even
when an active source record changes or is removed. Every source has its own saved
interval, conditional-GET cache, generation check,
lease, freshness display and refresh audit. A setting change cancels an outdated
refresh's commit. Public-feed downloads are enabled by default in the installed
profile and do not send project files or trigger Ollama. A source can be paused
in the UI; `--no-auto-intelligence` disables the background refresher globally.

Related cached CVE references reach the model only after an OSV candidate match
with proven project-root provenance links an exact advisory/CVE alias. This is
retrieval context, not model training or a project finding. Unmatched public records
remain searchable for human review; they are not injected as arbitrary instructions.

## Operator checks

```bash
cd "$HOME/.local/share/cyberlab/current"
.venv/bin/python scripts/smoke_test.py
.venv/bin/python scripts/refresh_intelligence.py --status
.venv/bin/python scripts/refresh_intelligence.py
.venv/bin/python scripts/smoke_test.py --live-ollama
```

The refresh script uses the configured data directory; set `CYBERLAB_DATA_DIR` or
`--data-dir` when it differs from the default. A service's saved config is applied
by its stable launcher, not automatically inherited by a new terminal.

The live-model check is optional but necessary before claiming real Ollama
compatibility. The /healthz endpoint checks process/database readiness only; source
freshness and model readiness are independent. Keep actual host, test outcomes,
failed source checks and skipped integrations distinct in TEST_RESULTS.md.

## Recovery

Stop the process before a rollback. Keep the current database separately. Restore
an integrity-checked pre-upgrade backup into a separate directory, then select it
when launching preserved previous code. Do not overwrite a live database or expect
a pre-upgrade backup to contain later evidence. Do not delete the previous install
until data and application validation complete.


## 4.14 upgrade notes

Migrations add project identities, passport fields, component inventory/coverage,
and CVE retry state. Existing records remain. Only explicitly stored canonical
roots establish historical ownership; name-only rows are not reassigned. Preserve
configured projects paths across upgrades. The release startup backs up the database
before these migrations. The installer also creates a pre-install backup.

The briefing compares both manifest and lockfile hashes. It does not label an old
check current merely because the lockfile stayed unchanged. Declared passport data
is kept local and does not authorize checks. Lockfile queries use npm package names
and exact versions when available; registry credentials/URLs are not sent to OSV.
