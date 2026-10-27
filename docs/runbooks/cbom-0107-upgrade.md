# 0107: bank-local system names and durable CBOM declarations

**2026-10-24 · operator procedure, not deployment approval.**

Read the [implemented contracts and remaining limitations](../operations/production-data-path-hardening.md) and [execution record](../readiness-evidence/production-data-path-2026-10-24.md). This is an additive migration after 0106; historical migrations are not edited.

## Before a rollout

- Obtain the existing customer/change/security approval. Verify backup ownership and an independently rehearsed restore procedure; the controlled sandbox restart here is **not** a backup/restore or failover test.
- Use the reviewed release's constrained dependencies, including `rfc3986-validator`, and a supported maintained production PostgreSQL. The test helper's bundled PostgreSQL 16.2 is not a deployment recommendation.
- Rehearse on an authorized clone with representative size. Migration lock acquisition is limited to **5 seconds**. That is **not** a five-second total runtime limit: index construction can take longer and can block writers. Plan a maintenance window; do not assume online, zero-downtime migration.
- Freeze/drain API imports, workers and other inventory writers. Deploy matching API/worker code together. Mixed old/new writer versions are unsafe: older asset refresh code does not understand the new declaration namespace.
- Inventory legacy import-only/mixed-source rows and historical HIGH/CURRENT stamps for explicit review. Do not claim this migration repairs lost original source context or authenticates old observations.
- Check the target database and revision using the approved secret mechanism. Do not paste connection passwords into tickets, logs or chat.

Useful authorized preflight (all-estate queries require the migrator/DBA role, not a tenant API session):

```sql
SELECT version_num FROM alembic_version;
SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'systems';
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint WHERE conrelid = 'systems'::regclass AND contype = 'u';
-- Before 0107 this should be empty, given the old global constraint.
SELECT name, count(*) FROM systems GROUP BY name HAVING count(*) > 1;
```

## Apply through the normal migration job

From the repository root with its approved Python import environment and external `DATABASE_URL`:

```bash
python -m alembic -c services/database/migrations/alembic.ini upgrade head
python -m alembic -c services/database/migrations/alembic.ini current
```

Expected head: **0107**. Do not use `create_all`, `stamp head`, manual column creation or a schema-ensure bypass to claim the migration ran.

0107 installs:

- `uq_systems_tenant_name`: unique `(tenant_id, name)`;
- `uq_systems_platform_name`: unique `name WHERE tenant_id IS NULL`;
- nonunique `ix_systems_name` remains for lookup;
- the old global `uq_systems_name` constraint / historical unique lookup-index shape is removed.

PostgreSQL DDL is transactional. If a lock timeout occurs, keep writers frozen, inspect blockers through approved operations and retry in the window. Do not delete indexes piecemeal, disable constraints or increase timeout blindly. The retained live test holds a real row lock, observes failure, verifies head **0106** and original uniqueness, then successfully retries.

## Verify before unfreezing

1. Confirm 0107 and the two estate-local unique indexes. Confirm pre-existing row IDs, owners and metadata are unchanged.
2. Start matching API/workers. Runtime migration-head checks must pass; no weakened production settings or control-surface exemptions are supplied by this change.
3. In authorized synthetic estates, test the same name in bank A and B; IDs must differ, each estate must reject its own duplicate and platform NULL scope must remain unique. Foreign system reads must remain 404.
4. Confirm readonly and other non-writer roles receive 403 for import.
5. Import flat **algorithm metadata** through the existing CBOM page. Check committed fingerprint, source basis, LOW confidence, persisted business/PQC context and authenticated native download. Check the metadata-only `cbom.ingest` audit row.
6. Confirm no new scanner timestamp, last-scan ID, CURRENT stamp or cleared failed-scan state. An import is not a scan. Existing scanner evidence and other systems' declaration rows must remain separate.
7. Repeat the import; matching declared asset/link counts must not grow. This is natural-key append/refresh, not exactly-once request processing. Absent components are not retired.
8. Test invalid/oversized/nested/unsupported documents, ambiguous failures and tenant/session/scan-selection changes. The UI must not replay a write or present an old receipt in a new context.

## HTTP outcomes and reconciliation

- **200:** the request's inventory/receipt/audit transaction committed before response.
- **403:** insufficient durable role/estate authority; do not substitute a client-side role setting.
- **413:** more than 2 MiB on the wire; the console additionally caps selected files at 1 MiB.
- **422:** invalid schema/metadata/profile, duplicates/depth/nonfinite JSON, unsupported signature, conflicting declarations or storage field limits. Flat algorithm metadata is the supported import profile; native certificate/key/protocol and nested documents are not silently converted.
- **409:** concurrent first-create/inventory conflict. Reload/reconcile the selected estate before an explicit retry.
- **503**, timeout or lost response: **outcome unconfirmed**. A connection can fail after server commit. Query inventory/receipt fingerprint/audit before retrying; never promise automatic rollback or exactly-once delivery.

Fingerprint: SHA-256 of parsed JSON serialized with sorted keys, UTF-8, compact separators, `ensure_ascii=False`, `allow_nan=False`. It is a server-defined **document fingerprint**, not an original-upload byte hash, RFC8785/JCS signature commitment, trusted issuer attestation or whole-bank completeness proof. Raw source documents are not retained by this metadata-only import.

## Rollback

Prefer a reviewed forward fix. After separate banks use the same name, the old globally unique schema is no longer representable without a business decision.

```sql
SELECT name, count(*) FROM systems GROUP BY name HAVING count(*) > 1;
```

0107 downgrade deliberately refuses when this returns rows. It leaves head/indexes/data intact. **Never delete/rename bank systems just to force a downgrade.** A successful schema downgrade with globally unique names is tested, but does not reverse later imports or make old writer code safe for new namespace data. Application rollback requires review of those semantics as well as schema state, and may require the separately approved restore process. Neither this runbook nor the sandbox evidence authorizes destructive recovery on an existing deployment.
