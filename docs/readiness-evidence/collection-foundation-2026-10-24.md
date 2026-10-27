# Universal collection Phase 1 and Phase 2 Linux increment — execution record

**2026-10-24 UTC · baseline `54012209732c30d6f07e24bb8bd7d2ca0cdbef92`**
**Branch `arena/bb4b80dd-cryproscan` · PR34 · no deployment/bank acceptance**

[Phase 1 guide](../bank-environment/62-universal-collection-foundation.md) ·
[Phase 2 Linux scope/remaining work](../bank-environment/63-linux-collection-phase-two.md) ·
[Replay notes](collection-foundation-2026-10-24/README.md).

## Order and delivered behavior

1. Built and passed the initial **18 Phase 1 integration checks before extending
   Linux collection**: stable scoped registry, current admin/CISO authorization,
   offline job handoff, existing one-use evidence intake, central evidence envelope,
   six-domain projections, reader restrictions, foreign-scope refusal, revocation,
   fresh authorization on updates and atomic audit failures.
2. Extended the Linux adapter with explicitly approved literal OS-release metadata,
   target-spec CLI, per-fact source/identity references, pinned strict envelope and
   target schemas, version-history identity tests and honest partial/failed status.
3. Added real PostgreSQL row-lock, revocation/intake ordering and duplicate-completion
   concurrency witnesses, plus current-source regression/frontend/schema gates.

Existing database/evidence/host/CBOM paths are reused, not replaced by another
inventory. A fact is imported once, centrally normalized, referenced by multiple
BOM domains and never promoted from a library/vendor/config claim to runtime use.

The first adapter is offline Linux only. Handoff says AWAITING_EVIDENCE, not
"remote process running". Registry-bound old intake rechecks current authorization
under the same target mutex used for withdrawal. Completed historical evidence
remains inspectable without renewing authority. Job completion is a separate
reference transaction after durable intake; retry does not recollect evidence.

Stable metadata slots persist across software version changes, while individual
observations and source digests change. They are not attested asset identities.
Coverage is approved-input counts only; whole-host percentage is null. All six
domains remain present, but unsupported NBOM/HBOM/VBOM projections are empty and
operational use UNKNOWN, not absence of risk. Internal projections are not standard
CycloneDX documents; existing native 1.6 CBOM retains its own validation path.

## Final current-source gates

| Gate | Observed final result | Artifacts |
|---|---|---|
| Selected foundation/Linux/host/graph/SBOM/SSH/schema/evidence/database/API regression | **1,561 passed, 1 skipped**, 12 warnings, 346.52s; exit 0 | [Transcript](collection-foundation-2026-10-24/regression.txt), [JUnit](collection-foundation-2026-10-24/regression.xml) |
| Owned PostgreSQL 16.2 host + graph + foundation/Linux contracts | **81 passed**, 6 warnings, 259.57s; exit 0 | [Transcript](collection-foundation-2026-10-24/postgres.txt), [JUnit](collection-foundation-2026-10-24/postgres.xml) |
| Full frontend suite | **614 passed**, 58 files, 181.75s; exit 0 | [Transcript](collection-foundation-2026-10-24/frontend.txt) |
| TypeScript + production frontend build | Passed; build 3.19s; exit 0 | [Transcript](collection-foundation-2026-10-24/frontend.txt) |
| Changed Python Ruff / pip consistency / staged whitespace | Passed | [Quality](collection-foundation-2026-10-24/quality.txt) |
| Owned PostgreSQL cleanup | No owned witness directories/server processes remained on inspection | [Cleanup](collection-foundation-2026-10-24/cleanup.json) |

The selected regression includes **26 foundation API cases plus 13 new Linux/schema/CLI
cases**. PostgreSQL adds **19 foundation/Linux cases** to the existing 62 host/graph
cases; frontend adds **one OS-metadata panel case**. These counts overlap and are not
summed into distinct bank validations. One native-Windows fixture skips on Linux.

[Selected source/artifact commitments](collection-foundation-2026-10-24/manifest.json).


Tests overlap old host/graph/schema/API checks and are not summed as bank coverage.
Warnings remain in raw transcripts. Elapsed suite/build time is not a p95/p99,
capacity, throughput or 20% optimization qualification.

## Explicitly unfinished / not qualified

- Phase 2 live service/process/listener, hardware/TPM/HSM and runtime attribution
  work is **not complete**. The implemented Linux profile is OS-file declaration,
  existing package/header/certificate/TLS-config metadata, not a full host scan.
- Other collector families are catalogued as unavailable, not enabled/qualified.
- All new collection routes remain blocked in controlled production. No rootful
  container, Docker socket, remote shell, Domain Admin, privileged host scanner,
  new production worker path or customer deployment was used.
- No physical-host/clock/source authenticity, signed release, WORM certification,
  production DB grant assurance, full global audit walk on each read, deployed
  bank controls, Windows execution or bank acceptance.
- No whole-estate dependency proof, migration readiness, policy/risk grade adoption,
  inferred PQC use, full collector migration or completed ten-phase program.

Local integrity hashes and append-only application controls are not protection
against a privileged attacker rewriting both source/history and audit storage.
Publication requests `[skip ci]`; no workflows changed/manual CI invoked, merge,
release or deployment is part of this increment.
