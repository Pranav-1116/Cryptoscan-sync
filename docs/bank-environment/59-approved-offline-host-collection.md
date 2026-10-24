# Approved offline host collection — first implementation slice

**2026-10-24 · development intake · Linux synthetic execution · Windows unqualified**

This implements a non-Git collection path, not all ten bank-product requirements.
See the [ten-point delivery/qualification ledger](60-host-first-product-acceptance.md)
and [execution report](../readiness-evidence/host-collection-2026-10-24.md).

## What runs, and what does not

`python scripts/collect_host.py --manifest approved.json --output host-snapshot.json`
reads **only individually listed inputs**, under the caller's existing identity.
It does not clone Git, recurse through directories, run shell commands, execute
binaries, invoke package managers, connect to endpoints, read remote registry,
upload anything, request elevation, or grant itself access.

The manifest is a local operator assertion, **not a signed bank approval or
collector attestation**. Before intake, the server independently checks an
unexpired, one-use, exact-estate approval created by a current admin/CISO human
session. Analysts can import; auditors/viewers can inspect/export but cannot
approve or ingest. Merely changing fields in a local JSON file grants no API
permission. Tenant selection and durable authority are checked on the server.

Collection and API admission are deliberately different controls:

1. Bank operator defines/reviews the explicit local manifest.
2. Admin/CISO approves the same manifest for an existing system in the selected
   estate. Approval expires within 24 hours. Save the returned `subject_id`.
3. Operator runs the collector **after** approval, as an ordinary user.
4. Analyst intentionally imports the metadata snapshot under that approval.
5. Auditor inspects committed source/evidence closure and downloads native1.6.

Nothing executes remotely when the operator clicks **Approve host scope**.
The approval binds declared system/scope metadata, not a proven host identity.
All host intake APIs remain **409 in the controlled production profile**. No
`local-source/v1` allowlist expansion, privileged-container shortcut, Docker
socket, rootful host access or scanner fallback was introduced. There is no
production host worker/isolation qualification in this increment.

## Approved input types

| Input kind | Read surface | Output | Not established |
|---|---|---|---|
| `PUBLIC_CERTIFICATE` | Exactly one PEM/DER public certificate | Public-key family/size where supported, curve, SHA-256 identity fingerprint, certificate signature OID/hash name | Private-key presence, current TLS use, certificate trust/validity, compliance or PQC deployment |
| `NGINX_TLS_CONFIG` | Explicit UTF-8 configuration file | Allowlisted `ssl_protocols` and `ssl_ciphers` tokens; unsupported/include syntax flagged | Effective configuration, inherited/server-block semantics, successful handshake or negotiated suite |
| `BINARY_METADATA` | Explicit regular file | ELF/PE **header magic** and content digest | Fully validated executable, library version, symbols, calls, loaded library or algorithm use |
| `DPKG_STATUS` | Explicit bounded Debian-format status file | `Package`, `Version` for `install ok installed` records | Authentic OS database, running process, transitive SBOM, algorithm use or completeness |
| `WINDOWS_UNINSTALL` | One of two exact local HKLM uninstall branches | Bounded `DisplayName`/`DisplayVersion` only | Runtime use, certificate-store discovery, complete software inventory or Windows qualification |

Windows uninstall paths are exactly:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
```

No uninstall command, install-script execution, arbitrary registry value,
private key, password, certificate body, source snippet or raw configuration is
an output field. These are **sensitive inventory metadata**, not public data;
approved paths/software names can themselves be sensitive. Protect the manifest
and snapshot as bank evidence. No redactor can guarantee that a malicious host
never puts a secret into a nominal metadata/name field; this is not a DLP claim.

## Example manifest and local execution

Use the reviewed Python3.11 dependency environment from `requirements.lock.txt`.
The script uses the repository's canonical import bootstrap; it is not a newly
installed service. Windows dependency/native-API execution still needs its own
qualification; do not infer that a Linux lock installation proves it works there.

Create `approved.json` and set a real reviewed offset-aware expiry within the
next 24 hours. The placeholder below intentionally cannot be admitted as-is:

```json
{
  "schema_version": "cryptoscan.host-manifest/v1",
  "approval_reference": "change/BANK-HOST-17",
  "host_id": "payments-linux-1",
  "environment": "pilot",
  "platform": "linux",
  "expires_at": "REPLACE_WITH_REVIEWED_UTC_EXPIRY_WITHIN_24_HOURS",
  "inputs": [
    {"input_id": "public-cert", "kind": "PUBLIC_CERTIFICATE", "path": "/srv/approved/server-public.pem"},
    {"input_id": "tls-settings", "kind": "NGINX_TLS_CONFIG", "path": "/srv/approved/tls.conf"},
    {"input_id": "library-file", "kind": "BINARY_METADATA", "path": "/srv/approved/libcrypto.so"}
  ],
  "max_file_bytes": 1048576,
  "max_total_bytes": 16777216
}
```

Approve the manifest for an **existing** system through the CBOM page's
**Approved host collection** panel. This page uses the existing authenticated
private-estate API helper; it does not need pasted API credentials. No selection
is uploaded until the operator clicks the corresponding action.

Then, on the approved host, from this source checkout/dependency environment:

```bash
python scripts/collect_host.py --manifest approved.json --output host-snapshot.json
```

- Exit **0**: every listed input produced bounded metadata, **not** a secure or
  complete host verdict.
- Exit **2**: at least one receipt has a collection gap. Preserve the output;
  failure is not an insecurity/compliance verdict.
- Exit **64**: manifest/output handling refused; no success/output presumed.
- Output creation is exclusive, with POSIX mode0600; it never overwrites an
  existing path. Windows permissions additionally require reviewed directory
  ACLs; mode0600 is not a Windows ACL demonstration.

Import `host-snapshot.json` under the saved approval ID, then explicitly inspect
it. There is no automatic upload, retry, background scan or cached sample result.
Private tenant/session/tab-resume changes discard drafts and late responses; a
client display fence does not undo a server commit. Reconcile the approval before
intentionally retrying an uncertain write.

## Bounds and safe file handling

Maximum100 explicit inputs, 1MiB per file, 16MiB total read bytes, 1,000 total
metadata facts; manifests can lower but not raise those caps. Failed parsing
still consumes the read budget. Registry byte counts/digests refer to the
allowlisted normalized value projection, not a raw registry hive. Native value
buffers and subkey/fact counts are independently bounded. Oversized package
stores are refused; do not disable caps or claim full inventory from a subset.

Linux uses descriptor-relative traversal with no-follow for every ancestor and
leaf, nonblocking opens, regular-file/single-link checks, a local filesystem-type
allowlist and before/after descriptor metadata checks. `/proc`, `/sys`, `/dev`,
symlinks, hard links, FIFOs/devices and unsupported mounts are not scan shortcuts.
Root, changed identities and permitted/effective Linux capabilities are refused.
An unreadable directory is denied, not retried with sudo. `LEAST_PRIVILEGE_UNPROVEN` also covers an unavailable identity/privilege API; it does not assert that the caller was observed to be elevated.

Windows code uses local fixed drives only, native read handles, pinned ancestors
with write/delete sharing refused, reparse/single-link checks, bounded registry
value buffers, and token-elevation/enabled-privilege refusal. UNC, device paths,
alternate data streams, traversal and ambiguous DOS names are refused. **These
native Windows protections have not been executed on Windows here.** Reparse,
registry-link, ACL, privilege, sharing/race and supported-filesystem behavior must
be independently reviewed and exercised before any Windows deployment claim.

Neither adapter provides a privileged-writer-proof atomic host snapshot. Disk
stalls, network-backed filesystem layers, collector tampering, clock manipulation,
OS compromise and metadata races outside the stated checks require additional
operating-system/sandbox controls and qualification. No direct application
network calls does not certify a machine's entire storage/network topology.

## Exact API/data path

All paths below are under `/api/v1/host-evidence`:

| Method/path | Authority | Effect |
|---|---|---|
| `POST /approvals` with `{system_id, manifest}` | Current admin/CISO human | Append immutable scoped declaration + chained audit, atomically |
| `GET /approvals/{id}` | Authenticated selected-estate reader | Inspect approved metadata |
| `POST /approvals/{id}/intake` with `{snapshot}` | Current authorized human analyst/admin | Consume approval once; atomic Scan/EvidenceRecord/assurance/audit transaction |
| `GET /approvals/{id}/snapshot` | Selected-estate reader, including auditor/viewer | Verify source, approval, all finding contents/ordering/manifest and critical projections; inspect receipts/evidence IDs |
| `GET /approvals/{id}/cbom` | Same reader | Verify closure, generate and fully validate native CycloneDX1.6; append export audit |

Writes default to10/minute, reads60/minute per limiter identity; the existing
shared limiter/fail-closed production policy is reused. These are code guardrails,
not measured bank capacity or a service SLA. The test environment explicitly
mounts the real limiter for its HTTP refusal witness. Body parsing is capped at
2MiB before JSON parsing, with duplicate-key/depth/non-finite rejection; assurance
storage is separately capped at1.5MB. Responses are `Cache-Control: no-store`.

The authoritative pipeline is the existing `EvidencePipeline` and `BulkInserter`
into `Scan`/`EvidenceRecord`, with an append-only `AssuranceRevision` holding the
exact metadata snapshot and approval. No disconnected inventory service/table
was created. Receipt anchors keep **all** approved inputs, including denials and
unsupported inputs, in the evidence chain. Certificate/config facts get their own
hash-covered source references. Software/binary presence remains in the bounded
snapshot rather than being manufactured into cryptographic-use findings.

Same approval + same snapshot returns the existing verified receipt; a different
snapshot conflicts. Concurrent PostgreSQL requests can commit at most one scan.
Audit persistence failure rolls back the entire intake. Reads check the complete
closure, including tombstones, ownership and denormalized fields; a valid stored
hash alone does not bless changed algorithm/location columns.

The importer does **not** update `System.last_scan_id`, declare current/complete
coverage, create/coalesce `CryptoAsset` rollups, run compliance policy or promote
host facts into the existing six-BOM estate relationship graph. The existing
CBOM page now exposes the scoped host evidence and native export; fleet-wide
rollup/graph integration remains a subsequent qualified increment.

## Evidence vocabulary and export profile

- **OBSERVED**: local collector claim about parsed metadata (not server-verified
  host execution, installed-library use or a verified deployment).
- **DECLARED**: approved system/scope mapping or text configuration contents.
- **IMPORTED**: authoritative server status for this entire offline report.
- **INFERRED**: no inference is performed by this adapter; never promoted to use.
- **UNKNOWN**: unobserved runtime use, effective TLS, missing key size/algorithm,
  library binding/version, host attestation, unsupported inputs and PQC context.

`policy_result=NOT_EVALUATED`, `pqc_assessment=UNKNOWN`,
`whole_host_coverage_verified=false`, `host_identity_attested=false`.
Linux fixture success cannot turn `windows_execution_qualified` or
`production_execution_qualified` true.

Pinned strict contracts ship under
`shared/shared_models/shared_models/schemas/host-{manifest,snapshot}-v1.schema.json`.
Tests compare them to the live models. The exact native export is CycloneDX
**1.6 JSON**, using the existing pinned complete official schemas/offline registry;
not legacy1.5/XML. A deterministic golden file pins the host extension vocabulary.
The custom `cryptoscan:host:<field>` properties correspond exactly to
`HostEvidenceRef` fields: source/local basis, snapshot/approval/system/host/input
identity, environment, ordinal/kind, receipt status/reason, claimed observation
time, source revision, certificate fingerprint/signature hash/curve, configured
protocols/ciphers, unknown library/version/runtime use/PQC, and unevaluated policy.
These are **CryptoScan extension properties**, not official CycloneDX field names.
An EC subject public key is reported as `EC`, not inferred ECDSA/ECDH use.
`certificate_signature_oid` identifies the actual certificate signature field,
not the subject key's runtime role or an application/HSM operation.

Only certificate-derived algorithm metadata and declared TLS configuration enter
the crypto CBOM. Noncrypto receipt anchors, package presence and binary headers do
not become algorithms. The native exporter omits invented inventory dependency
fanout. A TLS-config component with algorithm UNKNOWN remains explicitly a
configuration declaration; it is not a TLS handshake finding. Native1.6 keeps
occurrences/properties; legacy evidence method fields are not copied as native
fields. Schema validity proves neither observation truth, runtime dependencies,
external-tool interoperability, PQC compatibility nor bank acceptance.
