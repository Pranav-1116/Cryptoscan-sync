# Host-to-six-BOM metadata graph — implementation and execution evidence

**2026-10-24 UTC · baseline `455cb5e7d1fc18d3753472586de0fc77e0eeaf2b`**
**Branch `arena/bb4b80dd-cryproscan` · PR34 · no deployment or bank acceptance**

[Operator/API/data guide](../bank-environment/61-host-to-six-bom-associations.md) ·
[Ten-point acceptance ledger](../bank-environment/60-host-first-product-acceptance.md) ·
[Replay/artifact notes](host-estate-graph-2026-10-24/README.md).

## Delivered, with honest boundaries

- Existing approved host source closes through original snapshot/manifest, scan,
  EvidenceRecords/source projection/chain before proposal, review or graph read.
- Explicit host input/fact→existing SBOM binding/exact versioned package, successful
  supported SSH phase receipt, hardware, vendor or deployment identity. CBOM
  certificate/config facts and scope/receipt containment have their own provenance.
  The joined synthetic witness represents **all six BOMs** without inferred use.
- Current human analyst/admin/CISO proposal; a different current admin/CISO review;
  append-only expected-revision retraction; auditor/viewer read/export only. The
  generic assurance review path cannot bypass the stricter host adapter.
- Target digest commitment and current revalidation. Reopened original SBOM bytes,
  explicit same-system/environment deployment, lifecycle/expiry, changed hardware
  or supplier claims, failed/unsupported/stale endpoint observations and foreign
  identities cannot silently survive as active reviewed associations.
- `STALE`/`RETRACTED` history heads are retained but excluded from current edges.
  Full checked revision/audit receipt closure detects changed/missing predecessor
  data and removal of just a retraction tail. Budget/host-integrity failure returns
  409, not a truncated apparently complete graph.
- Atomic append/audit rollback; PostgreSQL concurrent reviews commit once and the
  existing approval-row lock serializes association count. Existing host request,
  strict JSON, read/write rate and no-store controls cover all new routes.
- Existing CBOM console gains explicit fact/target selection, checked target digest,
  review/retraction controls, six-domain provenance table and authenticated graph
  export, with private-scope generation fences and no automatic requests/retries.
- Custom versioned graph JSON is **not CycloneDX**. No declaration becomes a native
  `dependencies` edge. Existing host CBOM still uses the pinned official 1.6
  validation path; schema validity is not a dependency, interoperability or bank
  compliance claim.

Every reviewed association remains **DECLARED**, original host source **IMPORTED**,
actual runtime/PQC use **UNKNOWN**. EC subject-key family is not inferred ECDSA/ECDH
application use; vendor ML-KEM support is not bank HSM usage. No existing scan,
asset-policy/risk rollup, host-attestation or complete-coverage grade is promoted.

## Final current-source gates

| Gate | Observed final result | Artifacts |
|---|---|---|
| Selected host/graph/SBOM/SSH/schema/evidence/database/API regression | **1,522 passed, 1 skipped**, 12 warnings, 189.68s; exit 0 | [Transcript](host-estate-graph-2026-10-24/regression.txt), [JUnit](host-estate-graph-2026-10-24/regression.xml) |
| Actual owned PostgreSQL 16.2, host + graph contracts, concurrency and atomic audit failures | **62 passed**, 6 warnings, 101.22s; exit 0 | [Transcript](host-estate-graph-2026-10-24/postgres.txt), [JUnit](host-estate-graph-2026-10-24/postgres.xml) |
| Full frontend suite | **613 passed**, 58 files, 185.72s; exit 0 | [Transcript](host-estate-graph-2026-10-24/frontend.txt) |
| TypeScript + production frontend build | Passed; build 1.59s; exit 0 | [Transcript](host-estate-graph-2026-10-24/frontend.txt) |
| Changed Python Ruff / pip consistency / staged whitespace | Passed | [Quality](host-estate-graph-2026-10-24/quality.txt) |
| Owned disposable PostgreSQL cleanup | No owned witness directories/server processes remained on inspection | [Cleanup](host-estate-graph-2026-10-24/cleanup.json) |

The selected regression includes **58 graph-specific cases**; PostgreSQL includes
**40 graph cases plus 22 baseline host cases**. The frontend includes **15 new
association-panel cases**. These are overlapping engineering witnesses, not a
58/40/15 bank-estate coverage or certification score.

Selected source/artifact commitments: [manifest](host-estate-graph-2026-10-24/manifest.json).

Counts overlap existing tests, not distinct bank validations. Frontend tests use
jsdom/stubbed fetch; no native built-browser/deployed-estate acceptance is claimed.
The selected regression retains a native Windows skip on Linux. Existing Pydantic,
field-shadowing, Starlette/Alembic warnings are retained in transcripts.

The original exploratory runs passed before the final proposer-preservation and
configuration-domain fixes. Those were **repeated**; only final backend artifacts
are used for this report. Early fixture mistakes (wrong admin principal, missing
synthetic receipt time and mocked query-path matching) were corrected rather than
being represented as green gates. No performance comparison is claimed from run
elapsed time or worker-count choices.

## Not qualified by these tests

- Native Windows Server execution, physical host identity or hostile clock/storage.
- Controlled production host/association admission: still **409**. No positive
  admission→queue→worker→isolated read-only host scanner execution witness.
- Real HSM mechanisms/operations, cloud KMS use, live TLS negotiation or joined bank
  deployment. SSH acquisition is stubbed; synthetic identity rows are not devices.
- Firmware/PQC capability truth, observed release installation or application crypto
  invocation; metadata association review never changes these to observed use.
- Deployed TLS/secrets/monitoring, independent security review, production DB grants,
  external immutable audit anchors, bank approval, HA/SLA or performance targets.
- Complete estate-wide risk/drift/timeline/crypto-agility UI or all ten requirements.

Audit cross-checks cover selected local receipts, not a full global audit walk on
every request and not an attacker able to rewrite both history and audit storage.
Read-time projection is not an atomic snapshot across SQL/filesystem stores.
Production controls and independent review remain necessary.

Publication uses an owned `[skip ci]` commit on the current branch; no workflow
configuration changes, manual CI invocation, merge, release or deployment is part
of this increment. See manifest for selected source and artifact SHA-256 values.
