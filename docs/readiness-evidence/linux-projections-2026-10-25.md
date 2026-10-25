# Local readiness — Linux relationships and standard software export

Date: 2026-10-25 UTC. Baseline: `392063f479b1b7a015d3bd09c939b1faccb5f496` on `arena/bb4b80dd-cryproscan`.

## Delivered decision

Publish the identified Phase 2 local graph/export implementation gates for review. The previous intermediate response is unchanged; a **separate real CycloneDX 1.6 document** is now produced and validated before return. Native composition is explicitly incomplete. This is not a claim of complete Linux estate inventory or production/bank qualification.

- Typed graph retains every original fact node and all eight approved-input surface outcomes. Two exact unambiguous metadata-join rules are implemented; edges are explicitly INFERRED, with endpoint and evidence references. Missing/ambiguous joins and six unsupported patterns remain visible.
- Standard software export uses the pinned official offline BOM/SPDX/JSF schemas. Invalid output or schema-integrity failure returns 503, not a downloadable fallback. Package type uses the specification's documented application fallback with an explicit not-observed-classification property.
- Both outputs reuse the verified original intake and historical approved target. No rescan, new service/table, remote collector admission or v1 raw-envelope/default change.
- Existing UI gains an explicit graph read and authenticated standard software download. Private-scope fences, bounded graph wait and existing download guards remain enforced.

## Completed final gates

These counts overlap and must **not** be summed.

| Gate | Final outcome | Boundary |
|---|---|---|
| Selected Python regression | **1,578 passed; 3 skipped** | All inventory, shared-model and CBOM tests plus selected software/foundation/coverage/host-evidence/worker API tests. Includes final graph derivation label and strict refusal of promoting edges to OBSERVED. Three genuine Windows-native skips. Not the entire Python/all-API suite. |
| Owned disposable PostgreSQL | **34 passed** | Host-evidence + coverage + software contracts and four graph/standard-export cases, including admitted synthetic runtime metadata. Cleanup completed; no customer database touched. |
| Full frontend | **677 passed in 62 files** | All local frontend tests with two workers, including proof/context/timeout/export refusal behavior and existing authenticated-download privacy tests. |
| TypeScript and production build | **PASS / PASS** | `tsc --noEmit` and Vite build, not production deployment. |
| Static/dependency checks | **PASS** | Ruff on changed Python files; pip check. |
| Model/schema integrity | **PASS** | Three graph model JSON Schemas checked with Draft2020-12; existing official CycloneDX BOM/SPDX/JSF schema integrity checked offline. Export fixture documents additionally validated by the official document validator in the tests. Model-schema checking alone is not CycloneDX validation. |
| Source-lock scope witness | **PASS** | Candidate source-lock builder includes the new shared model. No signed lock, operator approval or host attestation generated. Old lock scopes are not silently extended. |

## Important positive and negative witnesses

- A synthetic authorized runtime intake produces only process-incarnation/mapped-path and reported-unit joins. Subsequent reads deliberately prohibit runtime collection and still succeed; these joins never become SBOM dependencies.
- Same PID with different boot/start ticks, missing process observation, missing unit name, duplicate candidate process/unit, unsupported relationships, forged endpoint/proof/edge ID and promoted OBSERVED/completeness claims refuse or remain unresolved.
- Candidate output is bounded to 20 IDs with actual count and truncation disclosure, not all-pairs edges or a silent first winner.
- Original-source tampering returns 409; foreign estate and unselected administrator return 404. Repeated reads are deterministic, do not insert scans/evidence/audits, and retain historical results after authorization revocation without authorizing new collection.
- Unknown package version is omitted from native version, not replaced with a fictional version. Unresolved groups are omitted with disclosure. Mapped paths are not file-artifact components.
- Failed package input remains an explicit failure in a valid incomplete standard file-only export. No package absence/host completeness follows from that document.
- Each modified pinned schema fails export closed; illegal component fields/types/spec versions, duplicate references and dangling dependencies fail official validation. No standard validator was weakened.
- The multiple-record export-omission and 25-candidate budget witnesses use explicitly synthetic DTOs; they do not claim those records were admitted as real host observations.

No actual systemd service or bank hardware was exercised by the new synthetic runtime injection. Existing native ordinary-user sandbox inventory tests are not bank environment qualification. Fixtures labeled `prod` are still synthetic test data.

## Reproduction

From repository root using the existing validation environment:

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:):$PWD/services/api/tests/unit"
/home/user/qualify-venv/bin/pytest services/inventory/tests shared/shared_models/tests services/cbom/tests \
  services/api/tests/unit/test_linux_phase2_projections.py \
  services/api/tests/unit/test_linux_software_inventory.py \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_collection_surface_coverage.py \
  services/api/tests/unit/test_host_evidence.py services/api/tests/unit/test_host_worker.py -q
/home/user/qualify-venv/bin/python scripts/validate_host_evidence.py \
  --acknowledge-local-synthetic --include-surface-coverage --include-linux-software \
  --include-linux-projections --junitxml=/home/user/linux-projections-postgres.xml
(cd frontend && npm test -- --run --maxWorkers=2 && npm run typecheck && npm run build)
```

The first 33-contract run had one failed **test fixture**: it altered the coverage's package input count without updating the mirrored `package_inputs` value. The existing strict validator correctly refused it. The fixture was corrected to preserve both views; no validation assertion or product guard was weakened. The initial failure is retained as `initial-contracts.txt` and is not presented as a passing gate. Final full-suite outputs above include the corrected fixture and final INFERRED-edge schema.

## Integrity and limitations

The adjacent [`linux-projections-2026-10-25/manifest.json`](linux-projections-2026-10-25/manifest.json) hashes 16 source/doc files and 10 artifacts. Console text has ANSI display escapes removed; JUnit XML is copied verbatim. Commitments support consistency/review, not authorship, organizational independence or host authenticity.

Real assigned operators must still return scoped evidence and reviewers must complete the existing qualification workflow against an approved release. No credentials/private keys, real approvals, independent signatures, dispatches or external returns were requested, created or sent. No workflow files changed; publication uses the requested `[skip ci]` marker, not a guarantee every external workflow honors it.

No complete estate discovery, dependency completeness, artifact integrity, runtime/key/traffic use, hardware origin, 24/7 staffing, bank acceptance or production readiness claim follows. The remaining external acceptance gate is explicit in [guide 71](../bank-environment/71-linux-relationships-and-validated-sbom.md); local code cannot replace it.
