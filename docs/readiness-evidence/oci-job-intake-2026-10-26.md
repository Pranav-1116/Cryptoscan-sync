# OCI job intake — publication engineering evidence, 2026-10-26

## Decision

**PASS: scoped engineering implementation and publication-candidate regression. NOT production admission or independent bank acceptance.**

The new OCI metadata registry/job/intake path was executed using actual session authentication, selected-estate isolation, existing SQL/audit storage, an ordinary-user local bound-capture CLI and owned synthetic OCI images. No customer system/provider was contacted, image executed or private key/credential requested.

See [Guide 83](../bank-environment/83-tenant-scoped-oci-job-intake.md), [API](../api-reference/oci-job-intake.md) and [operator runbook](../runbooks/oci-job-intake.md).

## Tested tree, not unrelated pending work

The local branch originally pointed at `d70bdf3` while GitHub already contained the foundation through `55a7bca3923d0b58a0ffad85077d58e86835a183`. The user explicitly selected the current working files as the implementation baseline. Local history was aligned to the published tip without changing file contents; original file/link/absence fingerprints were checked after alignment.

The publication candidate is **published `55a7bca3` plus only this increment's owned additions and the two-line main-router inclusion**. A separate source snapshot of that exact candidate was assembled and used for the final broad and PostgreSQL gates below. This avoids testing only the older local baseline and accidentally publishing untested dependency combinations. Unrelated pending edits/deletions are not staged, reverted or shipped. Existing workflows, deployment files and previous native/Windows/TLS/OCI features on GitHub remain untouched.

The [earlier standalone record](offline-oci-image-2026-10-25.md) and its manifest describe the original local test baseline before this intake increment. They remain historical artifacts, not assertions that their old dependency fingerprints describe the current publication tree. The new [integrity manifest](oci-job-intake-2026-10-26/evidence-manifest.json) distinguishes new files from exact published dependency bytes.

## Final executed gates

| Gate | Result |
|---|---|
| Publication candidate: all shared-model tests, all inventory tests, new OCI HTTP contracts, existing collection-foundation HTTP contracts | **1,745 passed / 22 skipped / 7 warnings**, 89.61 seconds |
| Owned PostgreSQL OCI gate on the same publication candidate | **17 passed / 6 warnings**, 27.20 seconds |
| Public API-return models and schemas | Six published OCI model/schema equality tests included; retained original return and projection model/Draft checks PASS |
| Ruff lint/format and dependency consistency | New Python files, plus existing-main syntax/lint and `pip check`, PASS; existing main file not wholesale reformatted |
| Local Markdown links / new text whitespace / staged-file integrity | Checked before commit |

Gates overlap; do not add their counts. No frontend code, database schema/migration or dependency manifest changed. Frontend build/tests, full-repository tests, performance/SLA, physical hardware and customer qualification were not rerun or claimed.

The 22 broad skips are explicit: 10 optional actual-hybrid-provider tests; 10 genuine Windows platform/session/interface tests; 1 opt-in owned native namespace execution test; 1 optional PyOpenSSL-adapter test because that module is not installed. None is a qualification PASS. Existing Pydantic/deprecation and deliberately malformed-fixture serialization warnings remain in the retained logs. The PostgreSQL helper's `XDG_RUNTIME_DIR` fallback warning is an environment warning, not a skipped DB test.

The final gates were recreated after a conversation interruption discarded temporary environments/logs. Implementation files were preserved; final logs and public returns are now retained inside this repository.

## PostgreSQL controls actually exercised

[Tests](../../services/api/tests/unit/test_oci_collection_postgres.py) use fresh synthetic databases on a newly owned local PostgreSQL server, never an existing/customer database. Cases cover:

- completed/partial/failed original capture and all six projections;
- exact-estate isolation, including an unselected platform administrator;
- revoke, scope update, expiry and system/environment drift before intake;
- rollback when consumption, original intake or completion auditing fails;
- concurrent duplicate intake: exactly one 201 and one 409, one original evidence/consumption record;
- concurrent intake versus revoke/update/cancel: serialized outcomes with audit ordering;
- a real first-target-row mutex: competing SQL update hits PostgreSQL lock timeout (`55P03`).

Target mutation/admission consistently locks the first target row before the system row. Same-job operations and revocation cannot race into acceptance after withdrawal. This is tested SQL serialization, not distributed collector attestation or an unbounded fleet concurrency guarantee.

[Reproduction helper](oci-job-intake-2026-10-26/run-owned-postgres.py) uses `pgserver`, an owned temporary directory and per-case disposable DBs, overrides rather than consumes any existing DB URL, and stops/removes its own server/data. [Cleanup record](oci-job-intake-2026-10-26/postgres-cleanup.txt) confirms completion.

## HTTP/CLI controls actually exercised

[HTTP tests](../../services/api/tests/unit/test_oci_collection_api.py) use actual durable test sessions, not a forged tenant dependency. [Bound-capture tests](../../services/inventory/tests/test_oci_job_capture.py) exercise the real reader and CLI.

- Current human trust permission is required for authorization/update/revoke; analysts cannot grant themselves that permission.
- Readonly/auditor/developer sessions can inspect their estate but cannot mutate the workflow. This is permission separation, not a claim of organizationally independent bank review.
- Wrong estate, system, stable identity, authorization revision, expected evidence digest, job/nonce binding or capture time refuses.
- An authorization cannot be issued months before its approved window.
- A repeated job/handoff/intake cannot consume another result; cancelled and terminal jobs cannot accept new returns.
- Missing/failed metadata stays partial/failed, not empty success/absence.
- Original target/job/evidence/consumption row corruption refuses projection; audit failure rolls back all intake records.
- Historical projections remain readable after revoke without accessing an image or running collection.
- The existing 2 MiB streaming cap, duplicate-key refusal and `Cache-Control: no-store` apply to the new API prefix.
- An original standalone evidence object cannot silently be treated as a job-bound capture; a new wrapper binds it to the retained public handoff challenge.
- Production execution-control mode remains fail-closed for this unqualified adapter.

## Retained public witness

[Public witness directory](oci-job-intake-2026-10-26/api-witness/) contains actual test responses and the actual CLI output:

- [target registration/authorization history](oci-job-intake-2026-10-26/api-witness/api-target-history.json);
- [handoff](oci-job-intake-2026-10-26/api-witness/api-handoff.json);
- [original bound CLI return](oci-job-intake-2026-10-26/api-witness/bound-return.json);
- [committed job](oci-job-intake-2026-10-26/api-witness/api-completion.json);
- [read-back original return](oci-job-intake-2026-10-26/api-witness/api-retained-return.json);
- [stored-evidence projections](oci-job-intake-2026-10-26/api-witness/api-projections.json).

These identities, image records, accounts and `system-a`/`prod` labels are **synthetic test scope**, not real production evidence. Actor IDs are random test identities; session tokens, authentication headers, private keys, image binary/config payloads and credentials are not retained. The public nonce is a challenge, not a secret.

The fixture has a known `openssl` package database record, OS declaration and a tiny synthetic ELF-magic file. That is not a real cryptographic library execution. Its three selected metadata inputs parsed; SBOM has two metadata references; TechBOM reuses all three; CBOM/NBOM/HBOM remain unknown and VBOM declared-only. All original evidence completeness/runtime/authenticity limitations remain false/unknown. The retained temporary source paths and completed windows must not be reused as bank targets.

## Integrity and reproduction

[Publication logs](oci-job-intake-2026-10-26/publication-tests.txt), [JUnit](oci-job-intake-2026-10-26/publication-tests.xml), [PostgreSQL logs](oci-job-intake-2026-10-26/postgres-tests.txt), [JUnit](oci-job-intake-2026-10-26/postgres-tests.xml), [static checks](oci-job-intake-2026-10-26/static-checks.txt), [test environment](oci-job-intake-2026-10-26/test-environment.txt) and the [integrity manifest](oci-job-intake-2026-10-26/evidence-manifest.json) identify the exercised source/artifact bytes. The manifest is unsigned integrity data, not source authenticity, protected custody, hardware origin or independent approval.

With the approved Python test environment and all repository service/shared import roots on `PYTHONPATH`:

```bash
python -m pytest shared/shared_models/tests services/inventory/tests \
  services/api/tests/unit/test_oci_collection_api.py \
  services/api/tests/unit/test_collection_foundation.py -q
python docs/readiness-evidence/oci-job-intake-2026-10-26/run-owned-postgres.py
```

`CRYPTOSCAN_OCI_INTAKE_WITNESS_DIR` optionally retains the six public witness files during the actual CLI/API test; it is a test artifact mechanism, not an evidence signer. Never point it at private bank returns.

## Still not closed

Trusted producer/image authenticity; independent original customer image truth and complete software/source coverage; hostile-parser/isolation release review; native Windows/customer container/application/physical-HSM execution; real authoritative estate completeness; bank independent acceptance and controlled-production admission. The public nonce, matching digest, API acceptance, software signatures and test `prod` label do not establish those outcomes.
