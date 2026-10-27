# Shared collection snapshots and metadata drift — engineering evidence, 2026-10-26

## Decision and scope

**Scoped engineering validation PASS.** This is a working stored-evidence product increment, not another scanner or an external-acceptance checklist. Host and OCI collection jobs now share durable source-revalidated snapshots, six-domain references, an evidence-supported metadata graph and immutable fact-multiset drift.

[Guide 85](../bank-environment/85-shared-collection-snapshots-and-drift.md) · [API](../api-reference/collection-snapshots.md) · [Runbook](../runbooks/collection-snapshots.md).

No actual bank estate register, bank image, approved physical-HSM/native-Windows return, independent customer custody or acceptance statement was supplied. This work does not claim those external gates. No new production execution, credentials, endpoint probing, scheduler, database migration, dependency manifest or frontend integration was added. The existing API application only registers the new router.

## Source isolation

The exact additive publication candidate was assembled from published `0eb2c24e7fe29bb3d5603a5747e2f1c8017ca3b0` plus this increment in `/home/user/.cache/collection-views-release`. Existing locally modified/deleted collector, API, schema, UI and documentation paths were not restored or included in this publication. **4,833 outside-owned path fingerprints** were recorded and checked unchanged before publication; **499 unrelated tracked changes** remain preserved.

The same new shared/HTTP contracts also passed against the current workspace, without restoring its deleted modules. The broader compatibility gates use the published dependency tree so they do not silently publish the unrelated pending deletions. Exact feature/test/schema commitments and retained artifact SHA256 values are recorded in the [integrity manifest](collection-snapshots-2026-10-26/evidence-manifest.json).

## Completed gates

| Gate on exact additive candidate | Result | Retained output |
|---|---|---|
| All shared models + all inventory tests | **1,732 passed / 22 skipped / 1 warning**, 41.21 s | [Log](collection-snapshots-2026-10-26/models-inventory.txt), [JUnit](collection-snapshots-2026-10-26/models-inventory.xml) |
| Existing graph engine + drift suites | **322 passed / 6 live cases deselected**, 7.47 s | [Log](collection-snapshots-2026-10-26/graph-drift.txt), [JUnit](collection-snapshots-2026-10-26/graph-drift.xml) |
| Foundation, new snapshot HTTP, existing OCI HTTP and truth review | **108 passed / 6 warnings**, 90.59 s | [Log](collection-snapshots-2026-10-26/workflow.txt), [JUnit](collection-snapshots-2026-10-26/workflow.xml) |
| Host evidence/associations/worker and Linux compatibility | **156 passed / 6 warnings**, 156.78 s | [Log](collection-snapshots-2026-10-26/host-compatibility.txt), [JUnit](collection-snapshots-2026-10-26/host-compatibility.xml) |
| Existing OCI-content, TLS and Windows candidate API compatibility | **53 passed / 3 skipped / 6 warnings**, 54.35 s | [Log](collection-snapshots-2026-10-26/adapter-compatibility.txt), [JUnit](collection-snapshots-2026-10-26/adapter-compatibility.xml) |
| New contract/race cases on a freshly owned PostgreSQL | **14 passed / 6 warnings**, 44.70 s | [Log](collection-snapshots-2026-10-26/postgres-tests.txt), [JUnit](collection-snapshots-2026-10-26/postgres-tests.xml), [cleanup](collection-snapshots-2026-10-26/postgres-cleanup.txt) |
| Final new contracts against current workspace | **61 passed / 6 warnings**, 31.70 s | [Log](collection-snapshots-2026-10-26/workspace-focus.txt), [JUnit](collection-snapshots-2026-10-26/workspace-focus.xml) |
| Nine new Python module/helper files lint/format, installed-dependency consistency, three schemas, five public artifacts and recomputation | **PASS** | [Static checks](collection-snapshots-2026-10-26/static-checks.txt) |

The five disjoint candidate regression groups total **2,371 passed, 25 skipped, 6 live cases deselected**. PostgreSQL and focused workspace gates repeat selected contracts; do not sum them as distinct capability or performance results. The new contracts comprise **35 shared-model/pure projection cases and 26 HTTP cases**; PostgreSQL repeats selected controls plus two actual concurrent-writer races.

The 25 skips are ten real Windows/interface cases, thirteen optional actual-hybrid-provider cases, one opt-in native namespace case and one missing optional PyOpenSSL adapter. Six live graph/drift cases are excluded by the existing `not live` test configuration. None is qualification PASS. Existing deprecation/model-shadow and deliberately malformed-fixture serialization warnings remain. The PostgreSQL helper also emits an environment runtime-directory fallback warning without skipping database execution.

An initial expanded single invocation hit its explicit **210-second runner limit**, with no final JUnit/verdict. Its [partial log](collection-snapshots-2026-10-26/exploratory-timeout.txt) and [command](collection-snapshots-2026-10-26/exploratory-command.txt) are retained as **incomplete, not PASS**. It was terminated, no pytest process remained, and work was split into the completed bounded groups above. This timeout is not a product performance measurement.

## Controls actually executed

- Original host closure / OCI bound return revalidation before snapshot creation; exact expected source commitment and terminal job requirements.
- Durable immutable snapshot with six views sharing the same retained observation references; graph endpoints are closed and every edge has evidence support.
- Imported provenance and original local basis preserved; OCI vendor declarations remain declared-only; pinned config does not inflate approved-input counts.
- Stable host and OCI metadata-slot identity across recollection/version changes; new evidence IDs/time alone do not create semantic drift.
- Full fact-hash multiset comparison preserves duplicate multiplicity, not just set membership/count or package names.
- Successive OCI image version, missing-source and narrowed-scope cases distinguish changes, gaps and out-of-scope records through actual capture/intake/HTTP flows.
- Failed receipt cannot supply positive observations; disappearance after failed source is unresolved, not removed. New visibility is not proof of installation.
- Same family/registered target/system/environment and forward nonoverlapping collection windows enforced.
- Exact-estate root records hidden from foreign/unselected administrator sessions; readonly/auditor accounts inspect but cannot POST.
- Source-revalidated paginated summaries and `no-store` history reads.
- Original source, snapshot, graph, projection and drift tampering fail even where a local revision hash was recomputed. A hash alone does not establish source authenticity.
- Audit failure rolls back snapshot/drift rows; duplicate snapshot and duplicate drift writers on real PostgreSQL produce exactly one 201, one 409, one row and one creation audit entry.
- Historical snapshot materialization after revocation does not authorize further collection; existing admission and truth-review regressions remain passing.
- Controlled-production boundary stays closed. No operational `USES_HSM`/deployment edge, automatic alert, remediation task or approved business baseline is created.

The PostgreSQL server and every case database were newly owned disposable sandbox resources. The helper never uses a customer database URL. [Cleanup](collection-snapshots-2026-10-26/postgres-cleanup.txt) confirms the server stopped and temporary data/parent were removed.

## Retained public synthetic witness

Five actual HTTP artifacts from the later-failed-certificate case are retained:

1. [Baseline original normalized source](collection-snapshots-2026-10-26/public-witness/baseline-source.json).
2. [Baseline stored snapshot/views/metadata graph](collection-snapshots-2026-10-26/public-witness/baseline-snapshot.json).
3. [Candidate original normalized source](collection-snapshots-2026-10-26/public-witness/candidate-source.json).
4. [Candidate stored snapshot/views/metadata graph](collection-snapshots-2026-10-26/public-witness/candidate-snapshot.json).
5. [Stored metadata drift](collection-snapshots-2026-10-26/public-witness/metadata-drift.json).

These use disposable local fixture files and test user/estate labels, not a real bank. The baseline has three parsed inputs out of four; the candidate has two. Its formerly returned certificate cannot be read. The stored comparison reports one `UNRESOLVED_COLLECTION_GAP`, keeps absence/removal unproven and retains the other two unchanged slots. This demonstrates error semantics, not that a customer certificate was physically removed.

No credential, private key, raw certificate body or password directive is retained. Original source envelopes contain normalized typed facts and commitments, not original signed customer returns. Their source authenticity remains unproven. The verifier checks the two canonical envelopes, per-observation fact/evidence links, stored row hashes, normalized snapshot/schema equivalence, complete six-view/graph recomputation, both drift source commitments and exact drift recomputation.

## Reproduction and limits

[Bounded runner](collection-snapshots-2026-10-26/run-tests.py), [owned PostgreSQL helper](collection-snapshots-2026-10-26/run-owned-postgres.py), [offline artifact verifier](collection-snapshots-2026-10-26/verify-artifacts.py), [environment](collection-snapshots-2026-10-26/test-environment.txt) and per-suite command files accompany the results. The runbook lists commands and explains that reproducing in place overwrites log/artifact files; use a disposable copy for protected evidence.

Hashes and this manifest are unsigned engineering integrity only, not trusted custody, independent assessment or physical truth. Full-repository/frontend, real provider/live graph, actual customer image/estate, Windows/physical HSM, HA/recovery, latency/throughput targets and SLA qualification were not rerun or claimed. Other collector families and threat-intelligence UI still need explicit adapters/integration into this snapshot path; the architecture is not globally complete.
