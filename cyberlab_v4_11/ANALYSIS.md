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

Known limits and remaining engineering work: model context currently uses genuine
inventory snapshots only. Root-safe provenance must be added to the older
name-scoped hypothesis/observation schemas before incorporating them into new
recommendations. The broader NVD/vector/patching specification remains future work.
Monitor settings support one process per database, not distributed scheduling.
Model prose is untrusted even when its JSON schema and evidence IDs are valid.
