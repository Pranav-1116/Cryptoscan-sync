# Approved TLS session candidate — target and stored export API

[Guide 79](../bank-environment/79-approved-single-tls-session-candidate.md) · [Operator packet](../runbooks/approved-single-tls-session-candidate.md).

No new service, storage table, background discovery or production network-execution endpoint. Existing network-scanner APIs remain legacy capabilities, not qualified universal-adapter admission.

## Target and execution boundary

`NETWORK_TLS_SESSION` is an additive strict host input/fact kind. Exact resource:

```text
tls-session://<numeric-IP>:<port>/sni/<canonical-ASCII-DNS-name>/version/<TLSv1.2|TLSv1.3>/peer/sha256/<64-lowercase-hex>
```

IPv6 is bracketed/canonical. Target `address` must equal its exact numeric socket endpoint. Dedicated operator wrapper additionally requires method `network`, sole operation `OBSERVE_APPROVED_TLS_SESSION`, exactly one input, Linux ordinary-user platform, matching environment, no credentials/exclusion and actual current approved window. The CLI requires reviewed canonical whole-target SHA and active-TLS acknowledgment; the fact retains the target commitment and explicit operation. The snapshot/host intake binds its approved manifest, **not independently authenticated whole-target approval or measurements**.

The existing collection target schema now permits the active operation only for `network`; other methods retain `READ_APPROVED_METADATA`. Legacy `network + READ_APPROVED_METADATA` declarations remain representable, but cannot activate this wrapper. Registration is not authorization. Network universal job authorization remains **409** in every environment. Offline-Linux/API admission explicitly deny this kind as a bypass; generic `collect_host` produces `DENIED / ACTIVE_PROBE_NOT_AUTHORIZED`, not network traffic.

Collector catalog entry: `approved-tls-session/candidate-v1`, state `OPERATOR_ACTIVE_CANDIDATE_NOT_ADMITTED`, `active_probe: true`, `server_execution: false`, `production_execution_qualified: false`. No production environment override or import-result field opens admission.

## Facts and receipts

`TlsSessionFact` has exact numeric address/port, SNI, TLS version, suite/strength, reviewed target SHA, explicit operation, stable scoped endpoint+SNI identity and selected-fact commitment. Nested `TlsPeerCertificate` contains only fingerprint/public algorithm/key size/curve/certificate-signature hash/OID. Protocol parent algorithm, actual app/library use, negotiated group and server signature scheme stay UNKNOWN. Certificate public-key metadata does not identify key exchange or software.

Successful facts require:

- `negotiated_session_observed: true`, `peer_fingerprint_matched: true`.
- `certificate_chain_validated`, `hostname_validated`, `revocation_checked`, `all_tls_versions_tested`, `application_data_sent`, `application_identity_verified`: **false**.
- Exact approved resource binding, source/selected commitment and combined wire+DER+selected-byte reconciliation.
- Valid nested certificate shape, fixed supported TLS 1.3 suite/strength pairs and explicit unsupported/unknown fields, not guessed use.

Failures never retain facts or content hashes. New reason/status pairs:

| Reason | Status |
|---|---|
| `TLS_TIMEOUT` | `UNAVAILABLE` |
| `TLS_CONNECT_FAILED` | `UNAVAILABLE` |
| `TLS_HANDSHAKE_FAILED` | `UNAVAILABLE` |
| `TLS_PEER_PIN_MISMATCH` | `INVALID` |
| `ACTIVE_PROBE_NOT_AUTHORIZED` | `DENIED` |

Existing `LIMIT`, expiry, platform and access refusals remain. Missing peer certificate is a handshake gap, not byte exhaustion. No failure means asset absence, no TLS or inability to negotiate a different version.

The existing eight-surface coverage report uses its compatible `network_listeners` network-evidence slot while retaining the exact `NETWORK_TLS_SESSION` input kind; it does not label a TLS handshake as an observed OS listener table. Complete surface/asset absence flags remain false. All six BOM counters remain, with only NBOM/CBOM/TechBOM contributions for this fact.

## Stored export

```http
GET /api/v1/host-evidence/approvals/{approval_id}/tls-session/cyclonedx-1.6
```

Uses the same tenant/RBAC, approval/intake/scan/original-evidence consistency checks as existing host exports. Reads retained originals only. No socket, DNS, collector, host reread, new scan or new evidence records. Viewer/auditor access remains tenant-scoped; unselected administrator does not gain cross-tenant read.

A successful response is `application/vnd.cyclonedx+json`, attachment `tls-session-{approval_id}-cyclonedx-1.6.json`, `Cache-Control: no-store`. It must pass the existing pinned **official CycloneDX 1.6** offline validator before return/success audit.

Profile: `cryptoscan:profile = PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN`.

- `services`: stable scoped numeric endpoint+SNI references, with approved numeric `tls://` endpoint and explicit session observation/certificate references. This is not verified application identity.
- `components`: separate protocol-observation and peer-certificate cryptographic assets. Certificate metadata with the same fingerprint deduplicates only when descriptions agree. Different descriptions refuse.
- Observation/reference properties retain evidence IDs, input ID, selected SHA, snapshot SHA, reviewed external target SHA/operation, IMPORTED transport and local OBSERVED claim. The full external target is not reconstructed/authenticated by these properties.
- `compositions.aggregate = incomplete`; projection domains NBOM/CBOM/TechBOM, false inventory/production completeness, retained failed-input status/reason.
- No package inventory, supplier inference, negotiated-group/signature invention, CA/hostname/revocation verdict or operational `dependencies` fanout. Old host CBOM/OCI/container exports remain their existing profiles, not aliases for this export.

Successful export appends `host.tls-session.export` with approval/snapshot/document commitments and exact profile. A read-only original-integrity check still occurs before materializing/auditing.

| Status | Meaning |
|---|---|
| Existing 401/403/404 | Authentication/role/tenant visibility or missing retained intake |
| 409 | No parsed approved TLS session, inconsistent references/metadata or changed originals; all-failed input is not successful empty inventory |
| 503 | Official schema validation failed; no document/success audit |

## Existing frontend, no discovery dashboard

HostEvidencePanel validates bounded/allowlisted session and nested certificate metadata, displays one negotiated version/suite and public certificate key metadata with explicit trust/app/group/other-version limitations. It rejects promoted use/chain/hostname/completeness and extra nested secret-like fields. Download requires explicit click, live response, correct profile and current snapshot commitment; existing private-scope/generation fencing still applies. No display/read/download action initiates collection.

Formal schema validity is not source authenticity, full discovery, capability/absence evidence, runtime application use, PQC readiness, independent bank acceptance or production admission.
