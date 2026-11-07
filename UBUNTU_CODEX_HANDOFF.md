# Ubuntu Codex: validate CyberLab AI locally

Cloud completion status: 67 regression tests and 6 offline smoke checks pass.
Use `python3 scripts/smoke_test.py` from `cyberlab_v4_11/` for isolated testing,
`python3 scripts/smoke_test.py --live-ollama` for required real-model testing,
and `python3 scripts/package_release.py` to rebuild the release ZIP.
Ubuntu acceptance and real Ollama remain unverified; the available cloud host
is Debian and has no Ollama service. Treat the checklist below as acceptance
criteria to verify, rather than reimplementing features already present.

The user requests that you finish the local project and provide a program they can
run to test the outcome. Treat this as an implementation task, not just a review.
Work in this existing checkout. Preserve user changes and existing installations;
do not create another worktree unless requested.

## Verified starting point

- Actual upstream baseline was v4.9. v4.10 never existed.
- Current source is `cyberlab_v4_11/`; the root ZIP is a previous build, not an
  automatically synchronized output.
- Read its README.md, ANALYSIS.md, CHANGELOG.md and TEST_RESULTS.md before editing.
- Cloud validation: 67 tests passed on Debian 13 / Python 3.12.14, including the
  original 39 regressions. Ubuntu and real Ollama have NOT been verified.
- Current implementation provides opt-in scheduled filename inventory assessment,
  persisted changes, bounded read-only Ollama recommendations, and manual review.
- Completion follow-up: recommendations now use current/previous inventory snapshots plus bounded root-scoped prior evidence.
  New hypothesis/live runs now capture canonical roots; old unknown-root records
  remain excluded. The earlier provenance implementation gap is resolved.
- No automatic remediation, NVD/vector pipeline or zero-day detection is implemented.
  Do not describe those aspirational capabilities as working.

## Acceptance checklist (implementation completed in cloud; verify locally)

1. Inspect the Ubuntu runtime, checkout changes, Python/Codex versions, local
   installations, Ollama availability and model names. Never print credentials.
   Do not assume the user has installed this release. Do not overwrite a running
   installation or its database. Use temporary data/projects for development.
2. Run `python3 -m unittest discover -s tests -v` from `cyberlab_v4_11/` and record
   actual outcomes. Investigate failures before continuing.
3. Complete evidence-grounded change analysis: add additive provenance migrations
   for canonical project roots in new hypothesis/live evidence, without guessing
   identities for legacy records or destroying data. Incorporate bounded,
   sanitized prior summaries only when their project/root provenance is proven.
   Link genuine evidence IDs; preserve raw route and normalized pattern, record
   deterministic matching rules, reject ambiguous dynamic matches, and exclude
   raw bodies, secrets, source contents, and model prompts from exported records.
4. Preserve strict model schemas, action allowlists, response/input limits,
   evidence-ID checks, unavailable/timeout/invalid responses, opt-in scheduling,
   deduplication, pause/resume, project isolation and graceful shutdown. Review
   races between changing settings, in-flight analysis, and shutdown; add tests
   where the behavior could violate consent or duplicate work.
5. Display actual observation provenance and the states no changes, pending
   analysis, recommended review, model unavailable, analysis failed and verified
   local observation. An observation is not a confirmed vulnerability. Ensure
   every evidence link resolves, HTML is escaped, JSON export is sanitized, and
   new POST actions require CSRF and explicit authorization.
6. Keep model suggestions read-only. Any verification requires a separate explicit
   user approval and the existing localhost-only, bounded synthetic-test plan.
   Never implement arbitrary commands, exploitation, credential guessing,
   unrestricted scanning, automatic patch application or merging.
7. Run a synthetic end-to-end scenario on Ubuntu: fresh baseline, route addition,
   persisted change, valid mocked recommendation, approved local observation,
   evidence-linked display/export, pause/resume and process restart. Verify old
   risk, memory, history and synthetic experiment features still work. Add
   regression and adversarial tests for all newly implemented behavior.
8. Run `python3 scripts/verify_ollama.py` if Ollama/model is available, and exercise
   a real change recommendation through the new schema. Report these separately
   from mocked tests. If Ollama is unavailable, continue independent work and
   report the missing prerequisite; do not fake a pass. Do not download large
   models or change system services without appropriate user authorization.
9. Fix confirmed defects and optimize measured bottlenecks. Preserve existing
   features, data and tests. Use the Python standard library unless a dependency
   has a clear demonstrated need.

## Deliverables and local validation

- Complete runnable source and updated README.md, CHANGELOG.md, ANALYSIS.md and
  TEST_RESULTS.md with exact commands, counts, skipped/unrun checks, platform,
  live Ollama results and known limitations.
- A reproducible packaging command/script that rebuilds `cyberlab_v4_11.zip`
  from the current release tree, excluding caches, databases, credentials and
  local runtime state. Test the ZIP from a fresh extraction, in that directory.
- Safe Ubuntu installation instructions: stop the prior process, consistent
  SQLite backup, side-by-side installation, additive migration and rollback.
  Never replace the personal database without explicit approval.
- A synthetic smoke-test command that uses isolated temporary data/projects,
  produces clear pass/fail output and a nonzero exit on failure, and does not
  require a user's personal database. Keep live-model checks optional and honest.
- Finish with the exact ZIP path and commands the user can run to test it.
  Do not declare completion while acceptance failures are unexplained.

If a decision or missing local credential is genuinely required, complete all
independent work before asking. Never ask for secret values in chat. Do not push
or publish local changes unless the user authorizes that action in this session.
