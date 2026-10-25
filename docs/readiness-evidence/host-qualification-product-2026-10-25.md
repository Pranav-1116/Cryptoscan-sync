# Assigned-human qualification product increment — 2026-10-25

**Delivered: working named-assignment, original public-evidence intake and separate signed-review controls in the existing product. Not delivered: actual external operator execution or bank acceptance.** No real names, approved hosts/channel, original exports or signatures were supplied; no person was contacted, host dispatched or production setting enabled. Do not send credentials or private keys.

Published starting point: `9765b41b` (operator handoff), following native protocol/runtime increment `73818352d629b3dbeced631ebed1542f889a2d43`. This increment builds the product workflow rather than replacing absent external execution with another completed-looking packet.

## What now works

1. **Immutable campaign:** selected-estate policy, release/plan commitments, two distinct pinned public reviewer keys, authenticated policy approver, change reference and required return-channel approval reference. The reference is an administrative record, not verification of bank approval or transport security.
2. **Named responsibilities:** five slots use actual active tenant user IDs/current permissions. Current display names/usernames are resolved from those records. Assessor and bank acceptor must be distinct from each other, assigned operators/verifier and original policy approver, and match their pinned reviewer identity/role. No demonstration users are seeded into runtime.
3. **Original public return:** exact bytes/digests, authenticated assigned submitter, responsibility, original native result and provenance. Native Linux/Windows responsibility, approved plan/source binding, duplicate/private-pattern/binary refusals, per-file/aggregate/history budgets. Negative/gap native results remain negative. Public-only screening is explicitly **not a secret-free guarantee**.
4. **Frozen evidence:** assigned verifier freezes an index covering exactly retained originals, all four qualified native categories and all fourteen existing checks. Changed/missing/unqualified native evidence cannot freeze. Referencing arbitrary worker JSON does not demonstrate worker execution.
5. **Separate external decisions:** no signer or default PASS statement in the application. Each assigned reviewer returns an externally signed, exact-scope, pinned-key decision. Signed REJECT/FAIL/NOT_RUN is retained and blocks acceptance; neither favorable nor unfavorable decisions can be overwritten.
6. **Current state/export:** GET/export rechecks assignments, evidence and signature validity rather than persisting a green report. Revoked authority/expired reviews block; corrupt retained blobs/history refuse. Original downloads preserve existing raw privilege. An auditor receives originals only through separately authorized access/channel, not by silently expanding raw permissions.
7. **Atomic existing storage:** campaign-root locks, expected-revision conflict checks, hash-linked append-only revisions, original blob and chained audit in one transaction. The final history revision is reserved for withdrawal, so budget exhaustion does not prevent a durable stop. No migration/new service is needed.
8. **Existing UI:** **Crypto & key assurance → Host qualification** supplies campaign list/open/refresh, blank approved-policy/channel and assignment editors, original return, freeze, signed decision, withdrawal, original download and public record export. Tenant/auth/storage/resume/history fencing clears private results/drafts and prevents a delayed file read from submitting in a newly selected tenant. Abort is not rollback of an already accepted old-scope write.
9. **Human-only metadata too:** the new subrouter requires a current typed durable human even for list/read/export; machine/API-key and non-durable legacy development principals cannot enter through a weaker metadata route. Generic assurance list/history access for this protected record kind has the same guard, so it cannot bypass the boundary. Existing unrelated collection routes/record kinds are not rewritten.
10. **Operational handoff connected:** [guide 68](../bank-environment/68-assigned-operator-qualification-workflow.md), [API contract](../api-reference/host-qualification-workflow.md), [execution handoff](../runbooks/approved-host-qualification-handoff.md) and [blank intake](../templates/host-qualification-intake.md) explain real responsibilities, scope, return limits, evidence review and explicit stop/retry handling.

## Validation

Counts below are separate, overlapping runs, **not additive totals or genuine external qualification**.

| Gate | Observed result |
|---|---|
| Selected shared-model, inventory/native and neighboring API regression | **1,171 passed, 3 Windows-native skips**, zero failures/errors |
| Final combined acceptance/qualification contracts | **68 passed**: 30 existing acceptance checks + 38 workflow API cases |
| Broader owned PostgreSQL regression during implementation | **130 passed**, zero failures/errors; host evidence/association/collection/worker plus workflow |
| Final owned PostgreSQL qualification/boundary/stop replay | **40 passed**, zero failures/errors, including actual SQL revision races |
| Full frontend confirmation (`--maxWorkers=2`) | **633 passed**, zero failures/errors |
| Focused qualification + authenticated-download privacy | **25 passed**, including 13 new qualification UI cases |
| Frontend TypeScript / production bundle | **PASS / PASS** |
| Ruff / installed Python dependency consistency | **PASS / PASS** |
| Five intake model schemas | Draft 2020-12 schema checks pass; extra fields forbidden |
| Real approved-host returns / genuine reviewer decisions | **Not supplied / not executed** |

The selected 1,171-pass and broader 130-pass runs preceded the last reserved-withdrawal hardening; the final 68/40 runs exercise the finalized workflow, typed metadata guard (including generic history bypass attempts) and budget-stop behavior. No earlier published test counts are relabeled as this increment's runs.

The first default-concurrency full frontend attempt had **632 passes and one failure**: `LaunchReadiness.usability.test.tsx`, “labels retained history separately from an acknowledged write and a newly read current gate,” expected a `<summary>` to be visible. The unchanged file then passed **9/9 in isolation** and the complete suite passed **633/633** with two workers. That existing page/test and the dependency lockfile are unchanged from `9765b41b`; no assertion was weakened, test skipped or workflow modified. The cause of the initial visibility failure is not established, and this is not asserted to be the user's previously mentioned CI failure.

An overbroad all-API-unit sweep was stopped without a final result and is **not counted as a passing full API suite**. Its partial log is retained for transparency; the completed selected regression covers the touched contracts/native paths and neighboring assurance/collection/worker boundaries. The final focused workflow contracts were rerun separately. No remote CI, production performance/HA or bank-native qualification is claimed.

### What the tests actually prove

- Synthetic users have real fixture SQL identities, active tenant memberships and durable typed sessions. Invalid/missing/foreign/disabled users, self-review combinations, wrong pinned reviewer roles and stale revisions refuse.
- Original blob bytes/digests survive authenticated retrieval; private-pattern, duplicate JSON, malformed/oversized/unapproved/wrong-operator inputs do not retain content. Missing originals/native gaps cannot freeze.
- Genuine test-key signatures are checked against exact policy/index/release/tenant/campaign. Wrong/forged signatures refuse; signed rejection persists; old decisions cannot overwrite. Role/membership/active-user revocation and review expiry remove a positive state on read.
- On actual disposable PostgreSQL, two competing original writes at one expected revision yield **201/409**, with one blob/revision; competing reviewer writes yield **200/409**, followed by a deliberate fresh-revision retry, retaining both independent statements. Root locks produce the expected lock timeout on another connection. Audit failure rolls back blob/revision together. A reserved final stop still commits after normal history capacity is exhausted.
- API keys and signed-but-nondurable development sessions are refused on metadata/export as well as writes. Foreign estate reads/exports do not disclose campaigns. Existing raw privilege remains unchanged.
- Browser tests cover selected auth/tenant headers, blank review defaults, exact original bytes/media type, explicit server refusal/rejection, double-click prevention, malformed drafts, delayed fetch/file-read scope changes, visibility/history restoration and unmount.

All identities, native positives, worker-witness JSON and signing keys used in these tests are **synthetic fixtures**. They establish implementation behavior, not real employees, hardware, host execution, organizational independence, transport approval, deployed-worker controls or bank acceptance. Test private keys are disposable/in-memory; no private signer or bank credential is delivered.

Both owned PostgreSQL harness runs report cleanup; no customer deployment URL is used. Build outputs, installed dependencies and temporary database/test state are not committed. The small logs, JUnit records, environment/schema metadata and source/artifact commitments are in [the evidence folder](host-qualification-product-2026-10-25/validation.json); its [manifest](host-qualification-product-2026-10-25/manifest.json) is an integrity/provenance record, not independent authentication or a bank signature.

## Explicit boundaries and next external action

`NOT_DISPATCHED_NO_REMOTE_EXECUTION` and `AUTHENTICATED_API_REQUIRES_BANK_APPROVED_TRANSPORT` remain visible. Even `SCOPED_EXTERNAL_RECORD_VERIFIED` keeps `host_identity_attested`, `full_worker_production_clearance` and `production_execution_qualified` **false**. Signatures establish pinned-key statements over scoped bytes, not hardware origin, measured execution, independent organizations or production admission. No existing production adapter or approval policy is enabled or relaxed.

All six BOMs—NBOM, CBOM, TechBOM, HBOM, VBOM, SBOM—remain evidence projections under their existing validation/provenance rules. This increment invents no observations, converts no UNKNOWN into absence, forces no unsupported completeness, adds no collector, and claims no whole-bank coverage, SLA/uptime or performance-target qualification.

The bank/change owner can now use the product to appoint its real users and record its actual approved channel reference; the named operators then run the existing packet on approved hosts and return original public artifacts. The separate assessor and bank acceptor review those actual environments/originals and supply public signed decisions. Those real operational actions remain pending and cannot be manufactured by this sandbox.

## Replay (approved local validation environment only)

From repository root, with existing declared dependencies and optional `pgserver` available in the approved disposable validation environment:

```bash
python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  shared/shared_models/tests services/inventory/tests \
  services/api/tests/unit/test_qualification_workflow.py \
  services/api/tests/unit/test_collection_foundation.py \
  services/api/tests/unit/test_host_worker.py services/api/tests/unit/test_host_evidence.py \
  services/api/tests/unit/test_host_associations.py \
  services/api/tests/unit/test_assurance_workflows.py \
  services/api/tests/unit/test_assurance_controlled_boundary.py -q

python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-qualification --junitxml=/home/user/qualification-replay.xml

cd frontend
npm run typecheck
npm test -- --maxWorkers=2
npm run build
```

The finalized selected suite has the additional budget-stop case, so a fresh full selected replay may contain one more test than the recorded 1,171-pass run. Use the owned harness, never a customer database URL. Do not run native capture against bank machines merely to replay engineering tests. Publication uses the fixed session branch with `[skip ci]`; CI workflows and production configuration are unchanged.
