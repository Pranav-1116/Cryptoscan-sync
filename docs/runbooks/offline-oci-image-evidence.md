# Offline OCI image evidence — operator runbook

See [Guide 68](../bank-environment/68-offline-oci-image-collection.md) for implementation scope and [the contracts](../api-reference/offline-oci-image-evidence.md). This is a standalone offline candidate, **not an admitted HTTP collection job or production approval**.

## 1. Agree the exact target before capture

Use an ordinary Linux account and a bank-approved transfer of an existing OCI image-layout directory. Do not install a privileged runtime, pull a tag or request credentials/private keys for this tool. Keep the approved image bytes independently under the bank's retention controls.

Create a target matching [the target schema](../../shared/shared_models/shared_models/schemas/oci-target-v1.schema.json). The following is a shape example, **not a valid approval or usable manifest digest**:

```json
{
  "schema_version": "cryptoscan.oci-target/v1",
  "target_id": "payments-image-uat-01",
  "system_id": "payments-api",
  "environment": "UAT",
  "authorization_reference": "change/approved-image-review",
  "layout_path": "/approved/payments/oci",
  "manifest_sha256": "REPLACE_WITH_THE_APPROVED_64_LOWERCASE_HEX_MANIFEST_SHA256",
  "architecture": "amd64",
  "not_before": "2026-10-25T10:00:00Z",
  "expires_at": "2026-10-25T11:00:00Z",
  "inputs": [
    {"input_id": "packages", "kind": "DPKG_STATUS", "path": "var/lib/dpkg/status"},
    {"input_id": "os", "kind": "LINUX_OS_RELEASE", "path": "etc/os-release"},
    {"input_id": "tls", "kind": "NGINX_TLS_CONFIG", "path": "etc/nginx/tls.conf"}
  ]
}
```

Choose a current, approved window of at most one day; the example timestamps expire. Explicitly agree which metadata files are expected and what source would establish their expected truth. A missing path is a gap. Symlinked `etc/os-release` is not followed; approve its actual supported regular metadata location separately if appropriate.

An authorized reviewer must validate the typed target and agree its **canonical model digest** using `shared_models.host_collection.digest(OciTarget.model_validate_json(bytes))`. A raw `sha256sum target.json` is different because whitespace/default fields are canonicalized. Obtain that approved digest through an independent trusted channel; do not treat a collector-generated digest or a matching `authorization_reference` string as proof of approval.

The target contains no credentials. `target_id` and `system_id` are declared scope references; this tool does not verify their existence in the tenant database or prove deployment.

## 2. Capture once into a new output

From the repository with its approved Python environment/dependencies available:

```bash
python scripts/collect_oci_evidence.py collect \
  --target /approved/plans/payments-oci.json \
  --approved-target-sha256 "$INDEPENDENTLY_APPROVED_TARGET_SHA256" \
  --output /approved/returns/payments-image-evidence.json
```

Input and output paths must be canonical absolute local paths. Parents must already exist and must not be symlinks. Output is exclusive-create mode 0600; existing files/links are never overwritten. The tool reads only `oci-layout` and the pinned manifest's addressed blobs; it does not enumerate the layout, parse `index.json` or open unreferenced files.

| Exit | Meaning |
|---|---|
| 0 | All explicitly approved metadata inputs parsed; not full image coverage |
| 2 | Original typed evidence retained with partial/failed per-input outcomes |
| 64 | Refused scope, unsafe/missing blob, bad structure/commitment, wrong platform, exhausted whole-image parser budget, or output failure |

Errors are generic and withhold raw image/config/parser bytes. Do not weaken a target, remove a missing input or reset the approval window just to get exit 0. Record the gap and have the authorized reviewer decide whether a new target is appropriate. A refusal is not a statement that the image lacks software or cryptography.

A crash/output write failure can leave a partial newly created output. Do not reuse it as evidence; independently inspect it and create a separately named approved return. No automatic retry, overwrite, append or acceptance marker is implemented.

## 3. Materialize retained evidence without recollection

Agree the canonical retained `OciEvidence` digest through the review process, then:

```bash
python scripts/collect_oci_evidence.py materialize \
  --evidence /approved/returns/payments-image-evidence.json \
  --approved-evidence-sha256 "$AGREED_CANONICAL_EVIDENCE_SHA256" \
  --output /approved/returns/payments-image-views.json
```

This command validates the original typed evidence and commitment, then creates six internal evidence views. It cannot contact the image layout or rescan an endpoint. It does not persist graph edges, export CycloneDX, invoke AI or enable a server collector. Exit 0 is successful **materialization**, not approval of the evidence producer, bank completeness, runtime use or PQC readiness.

A matching hash establishes byte/model integrity only relative to the independently held commitment. A malicious producer can create self-consistent metadata; this verifier does not supply image signature validation, protected producer keys, original-byte re-execution, measured execution or independent bank review.

## 4. Review and retain

Retain the target, original evidence, projections, approved commitments, collector/source release, original approved image blobs and independent expected-truth comparison under the existing evidence retention policy. Do not attach private image/config contents to chat or a public PR.

Review:

- exact authorization, time window, system/environment and manifest/platform;
- each ordered input status, content hash, source layer and fact;
- parsed/approved denominator versus the **explicit** target, never whole-image coverage;
- package records versus actual software presence, and presence versus loaded code/use;
- configured ports/TLS/vendor/base-image declarations versus live observations;
- absence of new operational/HSM/deployment edges or invented complete views.

Keep server/native admission closed. Real customer image truth, supported format review, tenant-isolated ingestion/authorization, revocation/replay tests and independent acceptance are separate gates. The local engineering witness in [the readiness record](../readiness-evidence/offline-oci-image-2026-10-25.md) uses owned synthetic OCI bytes, not customer/container production evidence.
