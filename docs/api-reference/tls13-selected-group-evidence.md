# TLS 1.3 selected-group evidence — additive API contract

[Guide 80](../bank-environment/80-tls13-selected-group-evidence.md) · [Operator packet](../runbooks/tls13-selected-group-evidence.md) · [Base session API](tls-session-candidate.md).

## Input and admission

New strict input/fact kind: `NETWORK_TLS13_KEY_SHARE`.

```text
tls-key-share://<numeric-IP>:<port>/sni/<canonical-ASCII-name>/version/TLSv1.3/peer/sha256/<expected-peer-SHA256>
```

Same reviewed network operation and exact scope/window/credentials/platform boundaries as the old single-session candidate; **additional explicit operator wrapper/CLI opt-in** is required. TLS 1.2 is refused for this resource. Generic host collection does not activate networking. Offline-host tunneling and all network universal-job admission remain 409; no import, environment override or all-positive fixture opens production execution.

Catalog entry `approved-tls13-key-share/candidate-v1` is `OPERATOR_ACTIVE_CANDIDATE_NOT_ADMITTED`, active, with false server-execution/production qualification. This is an additional profile, not replacement qualification for the legacy network scanner or old session profile.

## Typed facts

`TlsKeyShareFact` extends the prior session metadata as an **additive new discriminator**, preserving the old fact schema/defaults. Additional fields:

| Field | Meaning |
|---|---|
| `selected_group_id` | Observed uint16 ID in the final ServerHello key_share |
| `key_exchange_group` | Pinned label or UNKNOWN; matched to the raw ID |
| `group_classification` | REGISTERED_CLASSICAL_GROUP_SELECTED / REGISTERED_HYBRID_GROUP_SELECTED / UNRECOGNIZED_GROUP |
| `group_classification_basis` | PINNED_REGISTRY_MAPPING_NOT_IMPLEMENTATION_PROOF |
| `server_hello_hex` / `server_hello_sha256` | Exact bounded public final handshake message and commitment; independently reparsed on import |
| `hello_retry_request_seen` | Local capture's retry observation, not a standalone successful selection |
| `capture_basis` | FINAL_SERVER_HELLO_SAME_PINNED_COMPLETED_HANDSHAKE |
| `pqc_implementation_verified` / `pqc_readiness_verified` / `all_groups_tested` | Always false |

TLS version fixed 1.3; selected cipher ID must match the engine-reported suite. Raw hello may not be HRR. Known classical public-share sizes, extension framing/uniqueness, group/name/classification/hash and byte counts reconcile. All values remain imported measurement claims, not independently authenticated source/executable/target-consent proof. Public ServerHello retention is a privacy/correlation consideration even though no private key/session secret is retained.

Existing base flags remain false for CA/hostname/revocation/application identity/all-version testing and application data sent. Runtime/application/HSM use, server signature scheme and overall PQC assessment remain UNKNOWN. A hybrid group registration is not a verified implementation, PQC signature or bank-readiness verdict. No complete SBOM/HBOM/VBOM is created.

## Same stored-only endpoint and profile

```http
GET /api/v1/host-evidence/approvals/{approval_id}/tls-session/cyclonedx-1.6
```

The existing `PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN` profile now includes new fact variants. Protocol component properties include selected group ID/label, classification/basis, final public hello/hash and explicit false PQC/capability flags. Existing session/certificate/service/evidence references and IMPORTED/local OBSERVED distinction remain. Official pinned CycloneDX 1.6 validation is mandatory before a successful audit/return. No new scan/evidence record, collector call or socket on export.

Tenant/RBAC/original-integrity checks, incomplete composition, no operational dependency fanout, no-store attachment and successful export audit are unchanged. Changed originals, no consistent successful session or missing evidence refuse; official validation failure is 503 with no success audit. Malformed wire data is a failed input, not `NO_PQC`, absent TLS or a complete empty inventory.

Existing UI validates bounded raw selected-group structure and false readiness/use flags, displays group separately from the certificate and cipher, and keeps explicit profile/current-snapshot download fences. It has no active-probe or production-admission button.
