# Operator packet — offline OCI manifest/config candidate

**Engineering/offline candidate only.** No registry credentials/private keys; no Docker socket, extraction, image execution or production job admission. Read [Guide 77](../bank-environment/77-offline-oci-image-metadata-candidate.md) first. Actual Windows qualification is a separate open operator task; do not report it passed because this Linux metadata candidate runs.

## 1. Agree scope and expected truth first

Record named scope owner, ordinary-user operator and independent reviewer through your existing approved process. None is assigned by this document. Agree exact local staged directory, manifest SHA-256, Linux architecture/variant, environment/host alias, approved window and byte limits. No wildcard, directory walk, remote registry or automatic latest/first-image selection.

The reviewer independently specifies expected manifest/config commitments, layer/diff-ID declarations, platform and declared ports. Distinguish independently agreed expected truth from collector-generated observed output. Files must already exist in a reviewed staging area; acquisition/extraction is outside this command. Keep metadata originals/paths and organizational identifiers in the agreed secure channel, not public issue comments.

## 2. Prepare an exact reviewed target

This JSON is a **template**, not an approval; replace every placeholder and review actual timestamps before use. Manifest/config/layer declarations are not runtime facts.

```json
{
  "target_key": "reviewed-image-metadata",
  "system_id": "<approved-existing-system-id>",
  "environment": "test",
  "owner": "<scope-owner>",
  "collection_method": "container",
  "address": "offline-reviewed-layout",
  "allowed_operations": ["READ_APPROVED_METADATA"],
  "not_before": "<approved-offset-aware-start>",
  "manifest": {
    "approval_reference": "<approved-reference>",
    "host_id": "<reviewed-scoped-alias>",
    "environment": "test",
    "platform": "linux",
    "expires_at": "<approved-offset-aware-expiry>",
    "max_file_bytes": 1048576,
    "max_total_bytes": 16777216,
    "inputs": [{
      "input_id": "image",
      "kind": "OCI_IMAGE_METADATA",
      "path": "oci-layout://local/linux/amd64/manifest/sha256/<reviewed-64-lowercase-hex>/root/home/operator/reviewed-oci-layout"
    }]
  }
}
```

`credential_ref` is absent/null; none is needed or permitted by this wrapper. `read_only` defaults true, exclusions empty. Linux collection host need not match image CPU, but all approved manifest platform/declarations must agree. The default per-input limit charges both four-file samples and selected metadata together; do not silently loosen limits after a refusal.

Use the approved installed/reviewed release and its existing Python dependencies. In the repository validation environment the canonical digest can be calculated as follows (reviewer performs/reviews this before acquisition):

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python - <<'PY'
from pathlib import Path
from shared_models.collection import TargetSpec
from shared_models.tpm_quote_verification import sha
value = TargetSpec.model_validate_json(Path('reviewed-oci-target.json').read_bytes())
print(sha(value))
PY
```

This hashes the normalized validated model including defaults, **not** the pretty-printed raw JSON file. A digest merely detects a changed target; it is not authentication, a release signature or proof of independent human approval. Deliver the reviewed expected value through the agreed trusted channel, not a value recomputed by the acquisition command after editing scope.

## 3. Run once as the approved ordinary user

```bash
python scripts/collect_oci_metadata.py \
  --target reviewed-oci-target.json \
  --approved-target-sha256 "$REVIEWED_CANONICAL_TARGET_SHA256" \
  --output new-oci-metadata-snapshot.json
```

- 0: all approved metadata inputs parsed, **not** image/layer/package/runtime verification.
- 2: retained gaps; preserve the snapshot and original exit status.
- 64: scope/CLI/output/platform refusal; no fallback.

The output is exclusively created, never overwritten. Do not rerun until success, use root, enable a daemon, fetch a missing image, change digest/platform or drop failed inputs without new approval. No credentials/private keys are requested. The candidate emits HostSnapshot, not a native qualification packet or production clearance.

## 4. Retain and review originals through existing custody

Keep reviewed target/expected digest, approved fixture originals, expected-truth record, returned snapshot bytes, command/exit/time and reviewed source-release identifier. Source-lock inclusion alone does not attest which code executed. No metadata snapshot proves trusted publisher provenance or continuous runtime state.

For a development/offline exercise, use existing host approval/intake roles and secure transport. The scope owner approves the exact HostManifest for the existing system, the authorized operator/analyst submits the unchanged snapshot, and the reviewer inspects stored originals. Do not substitute a universal `container` job or tunnel it through `offline_host`; those authorization paths remain 409. No new auto-dispatch/intake service is created.

In **CBOM → Approved host collection**, inspect the approval/snapshot. Check exact manifest/platform/config commitments, layer and port **declarations**, retained evidence references and false package/layer/deployment/vendor flags. Download **OCI image metadata SBOM** explicitly. Check its profile and current snapshot commitment; the schema-valid container component is manifest/config metadata, not a package inventory. Inspect failed-input properties, not merely component count.

## 5. Negative cases on disposable synthetic fixtures only

Obtain prior permission for each negative; never mutate customer inputs. Independently specify expected outcomes before running:

| Case | Expected boundary |
|---|---|
| Wrong approved target digest / expired or future window / credentials / non-OCI input | Whole candidate refuses before collection |
| Wrong manifest digest, size or platform / duplicate selected descriptor | Gap; no first-image/platform fallback |
| Wrong config bytes, symlink/hardlink/special file, changed samples, duplicate/deep JSON | Retained gap; no partial positive |
| Combined per-input/total budget exhaustion | Gap/refusal; no silent truncation or limit increase |
| Layer files absent | Metadata can parse, but all layer/filesystem/package/deployment verification flags stay false |
| Config Env/Cmd/arbitrary secret-like labels | Their values must not appear in snapshot/export |
| All approved images fail | Stored image SBOM refuses, not empty success or image absence |
| Source files removed after intake | Stored inspection/export still uses originals, never rereads local paths |
| Foreign tenant / changed originals / official-schema failure | Refuse; no successful document/audit for failed validation |
| Universal container/offline-host authorization bypass | 409; no execution |

Existing synthetic tests cover these contract boundaries. They are not independent real-image qualification or a bank's adversarial approval.

## Stop and advancement decision

Stop for unexpected reads, raw secrets, new privileges/network calls, widened scope, contradictory commitments, silent missing inputs or promoted verification claims. Preserve evidence and involve the agreed reviewer; no automatic clean bill of health. Layer content/overlay/package handling and workload linkage remain the next Phase 4 engineering work. Real-image independent truth, resource/isolation/cancellation qualification, signed release provenance and explicit admission require separate evidence and decisions.
