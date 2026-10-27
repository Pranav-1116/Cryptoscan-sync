# Operator packet — approved single TLS session candidate

**Active, operator-run engineering candidate; not production clearance.** [Guide 79](../bank-environment/79-approved-single-tls-session-candidate.md) defines the limits and evidence semantics. Existing network scanners are not automatically admitted under this profile. Do not send credentials, private keys or session secrets.

## 1. Agree scope and expected truth before collecting

Through the existing approved channel, name the scope owner, ordinary-user Linux operator and independent reviewer; this document does not assign people or grant network access. Agree:

1. One exact numeric IP + port, canonical ASCII SNI, exact TLS 1.2 **or** 1.3, bounded UTC window and explicit active handshake consent. This may create endpoint logs/security alerts and ordinary handshake load; `read_only: true` means no application write request, **not passive or zero-side-effect**.
2. The expected peer certificate DER SHA-256, obtained from a separately trusted owner/source. Do not perform an unapproved preliminary probe to discover a convenient pin. A rotation, different certificate, SNI or version requires new review, not automatic retry or fallback.
3. Expected negotiated suite/public certificate metadata from independent truth, plus pin mismatch, expiry, denied/unreachable, wrong version and byte/time-limit negatives. Collector-generated output is not independently agreed expected truth.
4. Evidence retention, endpoint logging/incident contact and the secure output directory. Customer names/IPs/target originals belong in that channel, not a public issue comment.

The development tests use only generated synthetic certificates on disposable **owned loopback** servers. They are not bank endpoint acceptance.

## 2. Review the exact public target

Template only — replace placeholders; never treat this as consent:

```json
{
  "target_key": "reviewed-tls-session",
  "system_id": "<approved-existing-system-id>",
  "environment": "test",
  "owner": "<named-scope-owner>",
  "collection_method": "network",
  "address": "<canonical-numeric-IP>:<port>",
  "allowed_operations": ["OBSERVE_APPROVED_TLS_SESSION"],
  "not_before": "<approved-offset-aware-start>",
  "manifest": {
    "approval_reference": "<approved-active-probe-reference>",
    "host_id": "<reviewed-scope-alias-not-an-attested-host>",
    "environment": "test",
    "platform": "linux",
    "expires_at": "<approved-offset-aware-expiry>",
    "max_file_bytes": 131072,
    "max_total_bytes": 131072,
    "inputs": [{
      "input_id": "session",
      "kind": "NETWORK_TLS_SESSION",
      "path": "tls-session://<canonical-numeric-IP>:<port>/sni/<canonical-ASCII-DNS-name>/version/TLSv1.3/peer/sha256/<reviewed-64-lowercase-hex>"
    }]
  }
}
```

For IPv6, both address and resource contain `[<canonical-IP>]:<port>`. `credential_ref` is absent/null, exclusions empty, exactly one input. No DNS target, wildcard, endpoint range, credential reference or application URI. Windows production/native execution is not supplied by this packet.

Use the reviewed release and existing dependencies. Reviewer calculates/reviews the semantic canonical target digest **before acquisition**:

```bash
export PYTHONPATH="$PWD:$PWD/scripts:$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python - <<'PY'
from inventory.qualification_files import read_json
from shared_models.collection import TargetSpec
from shared_models.tpm_quote_verification import sha
print(sha(TargetSpec.model_validate(read_json('reviewed-tls-target.json'))))
PY
```

The digest includes parsed defaults; it is not a raw-file whitespace-sensitive checksum, external signature or bank approval. Retain original target and independently reviewed digest. Use the existing admin/CISO host-scope approval process for the exact manifest **before** collection, if returning into host intake. The whole-target digest and explicit consent remain external review artifacts; the host intake independently binds the manifest only.

## 3. Perform the one approved active session

Only in the agreed window, as an ordinary non-elevated user:

```bash
python scripts/collect_tls_session.py \
  --target reviewed-tls-target.json \
  --approved-target-sha256 '<independently-reviewed-canonical-target-sha256>' \
  --acknowledge-active-tls \
  --output tls-session-snapshot.json
```

No generic `collect_host`/offline-host command activates a probe. No universal network API job execution is enabled. The CLI uses a fresh exact-version TLS context, one numeric TCP connect, no client identity/key, application request, DNS/retry/version fallback, and no CA/OCSP/AIA retrieval.

Exit **0**: parsed session snapshot. Exit **2**: retained valid snapshot with failed receipt; review original reason, not an absence claim. Exit **64**: scope/platform/window/hash/output or unexpected execution refusal; do not automatically retry. Missing required arguments also refuse. The output is reserved exclusively at mode 0600 before connecting; it never overwrites a file/symlink. An unexpected failure after reservation may leave an empty/partial file: preserve it, investigate and seek fresh approval instead of deleting it and retrying blindly. Filesystem failure cannot guarantee a retained successful receipt.

Default profile: combined sent/received wire + DER copy + selected metadata at most 128 KiB; approved lower limits still apply; below 8 KiB refuses before socket allocation. Socket I/O is bounded by approval expiry/8-second monotonic deadline and 2 seconds per call, with 512 driver steps maximum. This is not native-library CPU/memory isolation or qualified worker cancellation.

## 4. Return, compare, import and inspect

Return public snapshot, original target/digest, independent truth comparison and exact operator/reviewer records through the agreed secure channel. No synthetic substitute or invented PASS if actual access/qualification is unavailable. Peer mismatch and timeout stay gaps. A pin match does not validate CA chain, hostname, revocation, originating host, application identity or HSM use.

Existing host intake accepts the snapshot only against its approved manifest/window and retains IMPORTED transport provenance. Optional signing enrollment/custody must use the existing separate workflow; a hash alone does not authenticate measurements. The server does not independently reconstruct the full external target approval from its hash.

Inspect with existing HostEvidencePanel or stored endpoints; stored export never reconnects:

```text
GET /api/v1/host-evidence/approvals/{approval_id}/snapshot
GET /api/v1/host-evidence/approvals/{approval_id}/tls-session/cyclonedx-1.6
```

Review receipt evidence references and incomplete NBOM/CBOM/TechBOM semantics. SBOM/HBOM/VBOM remain UNKNOWN for this fact. Official schema validity does not establish completeness, capability coverage, PQC readiness, source authenticity or bank acceptance. Network production admission, Windows qualification and earlier container blockers remain open.
