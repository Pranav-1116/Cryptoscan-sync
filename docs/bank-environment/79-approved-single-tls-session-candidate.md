# 79. Phase 5 — approved single TLS session candidate

**Build the next missing adapter, not another scanner/database.** Phases 1–4 already have candidate engineering. This increment adds one explicit, operator-run TLS session through the existing target, strict facts, receipts, evidence custody, scoped identity, projections and UI. It does not finish external Windows/container qualification, admit network production jobs, or claim the universal architecture complete.

[Operator packet](../runbooks/approved-single-tls-session-candidate.md) · [API contract](../api-reference/tls-session-candidate.md) · [Local validation](../readiness-evidence/tls-session-candidate-2026-10-25.md) · [Ordered architecture ledger](69-phasewise-universal-collection-build.md).

## 1. Exact authorization before active work

The `ApprovedTlsSessionCollector` accepts **one** Linux `NETWORK_TLS_SESSION` input in a reviewed `TargetSpec`:

```text
collection_method: network
allowed_operations: [OBSERVE_APPROVED_TLS_SESSION]
address: <exact numeric IP:port; bracket IPv6>
credential_ref: null
manifest.environment: identical to target.environment
not_before <= actual UTC time < manifest.expires_at
resource: tls-session://<numeric-IP>:<port>/sni/<canonical-ASCII-DNS-name>/version/<TLSv1.2|TLSv1.3>/peer/sha256/<expected-64-lowercase-hex>
```

IPv6 uses brackets, e.g. `[::1]:443`; canonical numeric addresses only. No DNS resolution, wildcard SNI, implicit IDNA conversion, CIDR, multicast/unspecified destination, mapped/scoped/link-local IPv6, port range, alternate target, credential reference or excluded input. SNI is a **reviewed request name**, not proof that the peer owns that name. The numeric socket destination prevents an implicit DNS lookup/rebinding step; it does not authenticate the network path or originating collector.

The CLI requires both an independently reviewed canonical **whole-target SHA-256** and `--acknowledge-active-tls`. It reserves an exclusive mode-0600 output before connecting; an existing/symlink output refuses without a handshake. The fact retains the reviewed target commitment and explicit active operation. Target originals must be kept for external review: the host intake independently binds the approved **manifest**, not the complete external TargetSpec, execution identity or consent process.

A legacy registry declaration `network + READ_APPROVED_METADATA` remains representable for backward compatibility, **but cannot activate this collector**. The active operation cannot be used with another collection method. Bare `inventory.host.collect` returns `DENIED / ACTIVE_PROBE_NOT_AUTHORIZED`; offline-Linux and API authorization reject attempts to tunnel this kind. Network job authorization stays **409**, even for a test environment. No environment flag or successful imported return opens production admission.

## 2. One connection, bounded TLS transport

The candidate uses a fresh standard-library `SSLContext`/`SSLObject` with **MemoryBIO**, direct numeric-family TCP socket and exact minimum=maximum TLS version. A constrained setup helper is also exposed by the existing network handshaker; its legacy discovery/handshake behavior is not silently relabeled or invoked by this candidate. Public certificate parsing reuses the existing inventory parser; no subprocess/OpenSSL command, trust download or separate database is added.

| Control | Actual behavior |
|---|---|
| Connection count | At most one TCP connect; no DNS, reconnect, alternate endpoint, version fallback, cipher enumeration probes or HTTP request. A TLS HelloRetryRequest may continue the **same** handshake. |
| I/O deadline | Up to 8 monotonic seconds from engine setup, capped by approval expiry; each socket call also has at most 2 seconds. Deadline/expiry checked between state-machine steps and before returning a positive observation. This is not a process-isolation or hard CPU-preemption guarantee. |
| State-machine limit | At most 512 handshake driver steps; not 512 connection attempts. |
| Combined bytes | At most **131,072 bytes**, or the smaller approved per-input/remaining-total budget: actual sent wire bytes + actual received wire bytes + peer DER copy + canonical selected metadata. Per-input budget below 8,192 refuses before socket allocation. DER at most 65,536 bytes. Existing outer manifest limits remain. |
| Byte accounting | Partial sends and every received chunk count. MemoryBIO avoids calling an opaque blocking handshaker with only a leaf-certificate size check. Failed receipts retain charged work; no positive fact/hash survives a failed probe. |
| TLS profile | Exactly TLS 1.2 or 1.3. Default local OpenSSL cipher/group offers, no exhaustive capability test. The three supported standard TLS 1.3 suite names have consistent strength checks. |
| Credentials/secrets | No client certificate/private key, client auth credential, TLS key log or session reuse. Ephemeral TLS state is internal and never exported. No CA/revocation/AIA/OCSP retrieval. |
| Application traffic | No application payload/request is sent; no application protocol is parsed. A peer can coalesce additional encrypted records with handshake traffic; received wire bytes still count. |
| Cleanup | Raw socket closes on success, failure, timeout, pin mismatch or budget refusal. No extra TLS shutdown round-trip. |

The SHA-256 pin is compared against the exact received peer DER **before** public metadata parsing. `CERT_NONE` is intentional: the result explicitly says **CA chain not validated, hostname not validated, revocation not checked**. Matching a public certificate fingerprint is not certificate/private-key custody assurance, approved peer identity, host attestation, freshness beyond the claimed collection window, or proof that the expected pin was obtained through a trusted process.

Socket/byte limits do not qualify OpenSSL native memory behavior, worker resource isolation, cancellation, HA, performance or a bank deployment. These remain production-hardening gates.

## 3. Facts, identity and evidence — not a new BOM source

One successful `TlsSessionFact` contains:

- Exact numeric destination, port, SNI, negotiated TLS version, OpenSSL suite name and reported symmetric strength.
- Public peer certificate SHA-256, public-key algorithm/size/curve and certificate-signature OID/hash metadata. No certificate body, subject/issuer names, SAN list, private keys or session secrets.
- Wire/DER byte counts, reviewed-target commitment, canonical selected-fact commitment and explicit confidence/limitation flags.
- Stable **scoped endpoint+SNI** identity, `tls-endpoint:<numeric endpoint>:sni:<reviewed name>`. Version/certificate changes do not become a different endpoint identity. Certificate identity is separately its DER SHA-256 in the export; an observation reference is not a globally authenticated asset identity.

A certificate's RSA/EC public key is **not** the negotiated key-exchange group, TLS signature scheme, application crypto library or HSM use. Those remain UNKNOWN. Parent algorithm/runtime/operation/PQC fields remain UNKNOWN and policy NOT_EVALUATED. One TLS 1.3 success cannot establish that TLS 1.2/1.0 is impossible, all ciphers are safe, or a listener's owning application has been verified.

Receipt resource binding requires exact endpoint/SNI/version/pin; selected-content hashes and combined byte counts reconcile. Impossible protocol/suite/strength pairs, changed pins, missing certificate fields, promoted trust/use flags and resealed out-of-scope facts refuse. These integrity checks do **not** authenticate an untrusted operator's measurements. Imported transport stays **IMPORTED**, separate from the collector's local **OBSERVED** claim. Existing optional signing identity controls remain separate; a signing key does not attest the executable/host.

## 4. Six projections, with no forced completeness

| Projection | Contribution of this fact | What stays unproven |
|---|---|---|
| **NBOM** | One exact negotiated remote TLS session; endpoint+SNI reference and retained evidence | OS listener inventory, all protocols/ports/versions/ciphers, network topology or application ownership |
| **CBOM** | Observed protocol/suite plus public peer-certificate metadata, kept separate | Negotiated key-exchange/signature details, all crypto use, chain/revocation validity, HSM/private-key custody or PQC readiness |
| **TechBOM** | Scoped endpoint/session/certificate references backed by existing evidence | Verified deployment or operational application/library relationships |
| **SBOM** | **No contribution / UNKNOWN** | Packages, versions, loaded software or complete service software inventory |
| **HBOM** | **No contribution / UNKNOWN** | Hardware, TPM/HSM possession, firmware or application hardware use |
| **VBOM** | **No contribution / UNKNOWN** | Vendor identity, supplier assurance or vendor PQC claims |

The compatible eight-slot coverage model maps the kind into the existing `network_listeners` network-evidence slot, listing its actual input kind and outcome. It is **not an OS listener-table success or whole-surface coverage claim**; complete-surface coverage and asset absence flags remain false. All six BOM counters remain present; only NBOM/CBOM/TechBOM receive this observation. Global cross-source identity/certificate graph hydration and native process↔listener↔application linkage remain Phase 9 work, not an invented edge.

The existing stored-evidence API now exports an incomplete **official-schema-validated CycloneDX 1.6** document with one endpoint service, protocol observation and peer certificate component. Each relationship is an explicit observation/reference property with receipt evidence IDs, snapshot SHA and provenance; no fabricated operational `dependencies` fanout. The endpoint reads retained originals only and never reconnects. Existing host CBOM and other exports remain separate, unchanged profiles.

## 5. Failure is a gap, never absence

`TLS_CONNECT_FAILED`, `TLS_TIMEOUT` and `TLS_HANDSHAKE_FAILED` are UNAVAILABLE; pin mismatch is INVALID; limits are BUDGET_EXCEEDED; missing active authority is DENIED. Generic platform/expiry refusals remain. There is no `NO_TLS`, `LEGACY_TLS_IMPOSSIBLE` or empty-complete SBOM result. All-failed stored session exports refuse rather than returning a successful empty NBOM. Partial imported snapshots retain original failed input status/reason in export properties.

## 6. What is still next

This is an owned-loopback-tested **Linux operator candidate**. Independent agreed truth on actual authorized endpoints, certificate-rotation/ACL/IPv6/provider/timeout negatives, release review, resource-isolated/cancellable qualified executor, complete-target custody review and explicit server-owned admission remain open. Native Windows TLS execution is not qualified; earlier Windows/container blockers remain. Do not contact bank/customer systems or publish private endpoint/organizational identifiers without separate approval. **Do not send credentials or private keys.**
