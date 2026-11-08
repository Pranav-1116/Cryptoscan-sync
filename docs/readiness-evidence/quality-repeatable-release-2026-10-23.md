# Step 9 — coordinated, source-bound package verification without invented approval

**2026-10-23 UTC.** The operator package builder/verifier is strengthened, not
replaced with another release system. Actual separately reviewed release-candidate
acceptance is **NOT_ESTABLISHED**. Local source publication is not release approval.

## The demonstrated gap

The prior signed package inventory detected byte tampering, but a signer could
rebuild the inventory and validly sign a package whose contract and image-lock
release IDs disagreed. The package also lacked explicit source/dependency/schema
binding: a re-signed changed lockfile remained merely another signed byte set.
Four new adverse checks failed against the old implementation. This increment
adds consistency checks **in addition to**, not instead of, signature trust.
A trusted signer can still lie about a build; cryptography does not make the
assertion true. Separate build attestations and review remain essential.

## Version-2 package contract

`scripts/operator_release.py build` emits `cryptoscan.operator-package/2` and
`source-provenance.json` using `cryptoscan.operator-source-binding/1`:

- Git HEAD commit and tree identifiers, plus **actual tracked worktree** file
  SHA256 map and its canonical snapshot digest. A dirty worktree is disclosed,
  not mislabeled as a clean commit. Untracked input contents are not captured by
  this map; their presence makes the ordinary Git status dirty.
- Byte hashes and copied inputs for `requirements.txt`, `requirements.lock.txt`,
  `frontend/package.json`, `frontend/package-lock.json`, and tracked files under
  `services/database/migrations/`. Migration head is0106.
- Contract hash of the provenance document. The signed image-lock's complete
  inventory binds these files, manifests, compatibility contract, bundled
  verifier/scripts and documentation. Contract and lock release IDs must agree.
- All manifest images remain immutable-digest validated, including API, dedicated
  worker, parser, frontend and sidecars. The legacy reserved Neo4j lock entry is
  **not permission** to enable graph in the supported graph-disabled profile.
- Captured dependency/schema bytes are checked after copying; a final source
  snapshot check refuses a worktree that changes during construction. Staging
  is temporary and no partial output is published when that check fails.

Build from a stable reviewed checkout. Keep site manifests, release output,
attestations, reports and temporary output **outside the checkout** and separate
from each other; output must be new and disjoint from source manifests. Building
under the checkout can itself change Git dirty status and is not a clean-source
release procedure. Ordinary dirty source bindings remain useful for engineering
inspection but cannot satisfy the strict expected-commit release check.

## Verification procedure

Use the existing [operator install/upgrade/recover runbook](../runbooks/operator-install-upgrade-recover.md)
for prerequisites, real registry digests, external signing, offline transfer,
quiescing API/worker and site preflight. Its reference manifest is not deployable
until site values are supplied. There are no real digests or release keys here.

Run verification from a **trusted checkout/installed verifier**, not executable
code in an unverified package. Obtain the authorized public-key fingerprint via
an independently trusted channel. Keep detached signature/public key and reports
outside the inventoried directory. The following is a procedure for a genuine
candidate, **not a command executed against an approved candidate in this lab**:

```bash
# All variables below must be actual approved site/release inputs.
python scripts/operator_release.py verify \
  --package "$RELEASE_PACKAGE" \
  --public-key "$TRUSTED_RELEASE_PUBLIC_KEY" \
  --attestation "$DETACHED_RELEASE_ATTESTATION" \
  --expected-source-commit "$REVIEWED_SOURCE_COMMIT"
```

The optional `--expected-source-commit` must match provenance and requires
`source_dirty:false`. It rejects version-1 unbound packages. Without that
argument, legacy inventory verification remains available but reports
`LEGACY_UNBOUND_NOT_CANDIDATE`; it never silently becomes a source-bound RC.

The current27 package tests include synthetic full-package signing/verification,
changed/missing/extra files and symlinks, invalid mutable/secret/placeholder/CA
manifests, re-signed mismatched release IDs, re-signed Python/Node dependency
edits, dirty expected-source rejection, legacy nonapproval, and source-change
race refusal with staging cleanup. They do **not** prove registry image contents
were built from those sources or that downloaded dependencies match a trusted
wheelhouse. Dependency input binding is not a fresh supply-chain audit.

### Explicit output boundaries

Successful package verification can report `package_inventory:PASS` and
`source_dependency_schema_binding:PASS`, while still emitting:

```json
{
  "image_build_provenance": "NOT_ESTABLISHED",
  "required_test_results": "NOT_ESTABLISHED",
  "separate_review": "NOT_ESTABLISHED",
  "ci_release_decision": "NOT_ESTABLISHED",
  "release_candidate_approved": false,
  "site_preflight": "NOT_RUN",
  "site_qualified": false
}
```

Even real local test logs do not automatically populate these fields: the tool
has not authenticated their producer, candidate binding or independent review.
An optional server-side dry-run checks admission, not actual secret/CA validity,
backup recoverability, image startup or staffed operations.

## Populated upgrade and incompatible rollback — executed

The current native19-case PostgreSQL16.2 suite passed, with23 disclosed warnings
and zero skips. `test_real_postgres_populated_outcome_migration`:

1. Creates a disposable UTF8 database at0105.
2. Inserts QUEUED/RUNNING/FAILED jobs with nontrivial versions/progress markers.
3. Upgrades to head0106 and checks IDs, statuses, versions and payloads survive.
4. Records an UNKNOWN job. Downgrade to0105 **refuses**, with
   `UNKNOWN jobs require reconciliation`.
5. Checks migration head stays0106 and UNKNOWN is not rewritten into success;
   invalid enum values continue to fail.

This tests populated semantics rather than an empty schema alone. Do not roll
back only an API or worker image across this boundary. Quiesce producers and
workers together, fence old attempts, reconcile uncertain external outcomes,
retain UNKNOWN capacity and choose an explicitly compatible roll-forward or
separately witnessed restore/failback. Never delete uncertainty just to make a
downgrade pass. Native signed-in flow, concurrent writers/approvals, withdrawal,
restore SQL-error propagation and synthetic cohort failback also pass.

The new cohort rerun remains a tiny quiesced synthetic SQL/files/key drill,
not a bank backup or joint live PostgreSQL/Redis service recovery. Raw rerun
[trace](quality-usability-release-operations-2026-10-23/trace.json) and
[cohort](quality-usability-release-operations-2026-10-23/cohort.json) records are
retained; they do not replace the broader limitations in the
[earlier executed-recovery report](quality-isolated-recovery-2026-10-23.md).

## Required current evidence before an actual release

Current local evidence is542 frontend cases,15 stubbed-HTTP browser cases,
92 selected release/operations/security cases,248 broader regressions and19
native cases, plus successful typecheck/build. Their exact sources/records are
hashed in the [manifest](quality-usability-release-operations-results-2026-10-23.json).
These results were produced while developing this change; they are not trusted
CI attestations for a final clean OCI candidate.

Before release, a **different authorized reviewer** must establish all of:

- Reviewed clean source commit, dependency lock/wheelhouse provenance, schema
  contract and supported upgrade/rollback paths.
- Real immutable API/worker/parser/frontend/sidecar image digests, build records
  associating each digest with that source/dependencies, and any declared
  platform/architecture-specific manifests.
- Whole coordinated package/signature/inventory and separately verified OCI
  transfer inventory; no mixed component revisions or post-signature edits.
- Required test matrix run for that exact candidate, populated representative
  data, permitted limits and failure/recovery cases, with honest warnings/skips.
- The user-owned CI failure identified and resolved with required checks passing
  for the release revision. `[skip ci]` cannot satisfy this requirement.
- Representative-user acceptance, real roster/support terms, admission/runtime
  and recovery qualification, external assessor/customer decisions as applicable.
- Named independent release decision, retained review evidence, residual-risk
  disposition, rollback authority and explicit go/no-go record.

**None of those human/site/CI approvals is fabricated here.** No actual release
was cut, no registry image pushed, no deployment changed, no main/workflow edited
and no independent reviewer impersonated. Publication to PR34 preserves code and
evidence for the required separate review.
