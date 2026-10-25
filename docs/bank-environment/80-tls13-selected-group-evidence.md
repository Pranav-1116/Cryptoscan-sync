# 80. TLS 1.3 selected-group evidence — closing one specific unknown

The request names several different gaps: broader TLS/PQC evidence, application/HSM operation use, complete software coverage, and actual Windows/container qualification. They cannot safely be converted into PASS flags by adding code or repeating synthetic tests. **This increment implements direct TLS 1.3 selected-key-share evidence.** It does not claim the other gaps are complete.

[Operator packet](../runbooks/tls13-selected-group-evidence.md) · [API](../api-reference/tls13-selected-group-evidence.md) · [Retained validation](../readiness-evidence/tls13-key-share-2026-10-25.md) · [Previous single-session profile](79-approved-single-tls-session-candidate.md).

## What changes from UNKNOWN

The old profile sees version, cipher and peer certificate, but intentionally leaves key exchange UNKNOWN. A cipher such as `TLS_AES_256_GCM_SHA384` does **not** identify the key-exchange group. An RSA certificate also does not mean RSA key exchange.

The new explicit profile captures the **final public TLS 1.3 ServerHello on the same numeric TCP connection**, then requires the existing TLS engine to complete its exact-version handshake and match the independently reviewed peer certificate pin. It extracts the ServerHello `key_share` selected group, checks the TLS 1.3 selected-version extension and matches the wire cipher ID to the engine's negotiated cipher.

For the owned test server this directly observes **X25519, group ID 29**, separately from the RSA certificate. This is one negotiated selection, not a claim that the endpoint supports only classical groups or lacks PQC.

## Explicit profile, no silent promotion of old evidence

```text
kind: NETWORK_TLS13_KEY_SHARE
resource: tls-key-share://<numeric-IP>:<port>/sni/<canonical-name>/version/TLSv1.3/peer/sha256/<reviewed-peer-SHA256>
method: network
operation: OBSERVE_APPROVED_TLS_SESSION
CLI: existing collect_tls_session.py + --include-key-share
```

All existing exact endpoint/SNI/pin/window/environment/no-credentials safeguards remain. The new kind/resource and full reviewed target digest express explicit consent to retain public ServerHello evidence. Without `--include-key-share`, the old operator wrapper rejects it before connecting. Bare host collection cannot activate it. Offline-host tunneling and network API job authorization stay blocked, regardless of a successful imported return. This adds no automatic discovery, reconnect, group/cipher/version enumeration, HTTP request, credentials, new service or new database.

Existing `NETWORK_TLS_SESSION` facts and their schema/defaults remain unchanged. Old snapshots cannot be promoted to observed key exchange by looking at certificates/cipher names; collecting this evidence requires a newly approved measurement.

## Evidence and bounded parser

`TlsKeyShareFact` is a new, strict, additive fact variant. It retains the existing session/certificate/source/identity fields and adds:

- `selected_group_id`: the observed uint16 NamedGroup codepoint.
- `key_exchange_group`: pinned registry label, or UNKNOWN for an unrecognized codepoint.
- `group_classification`: registered classical selection, registered hybrid selection, or unrecognized. This is a **derived registry interpretation**, explicitly marked `PINNED_REGISTRY_MAPPING_NOT_IMPLEMENTATION_PROOF`.
- Exact bounded public `server_hello_hex`, its SHA-256 and whether the local reader saw a HelloRetryRequest.
- False `pqc_implementation_verified`, `pqc_readiness_verified`, `all_groups_tested`; application/operation use and overall PQC assessment still UNKNOWN.

The raw ServerHello contains only public handshake data, including the server random, legacy compatibility session ID and ephemeral **public** key share. These may still be sensitive correlation/endpoint metadata; retain them in the agreed secure evidence channel. No private key, shared secret, TLS key log, application payload or decrypted CertificateVerify is captured. CertificateVerify signature scheme remains UNKNOWN.

Parser controls:

1. Incremental TCP and TLS record/handshake framing, not a substring search or private Python/OpenSSL callback.
2. At most 16,384 bytes per incoming feed/record payload, 32,773 pending record bytes, 4,096 handshake bytes and 128 public records before final ServerHello. Approval/8-second I/O deadline, 2-second socket calls and 512 driver steps remain.
3. Validate handshake/extension lengths, TLS 1.3 version, suite ID, zero compression, unique allowed extensions, nonempty selected share and known classical share lengths. Unsupported formats fail closed, not as absence.
4. HelloRetryRequest's reserved random identifies a **request**, not a completed selection. At most one retry; requested group and selected cipher must agree with the final ServerHello. Compatibility CCS is tolerated. No positive fact until final ServerHello **and** the real pinned handshake complete.
5. Stop public framing at final ServerHello; later encrypted records/application data are not parsed. Coalesced received wire bytes still count under the existing byte cap.
6. Combined 128 KiB cap (or smaller approved limit) now includes actual sent+received wire, peer DER copy, retained final ServerHello copy and canonical selected fact bytes. Snapshot commitments/counts reconcile. This is not an OpenSSL native-RSS/isolation guarantee.

Stored imports reparse the public ServerHello and reject retry-as-final, changed selected group/name/classification/cipher/hash, false readiness/use flags and receipt byte-count tampering. These are structural/integrity controls, **not authentication of an untrusted operator's measurement or proof of whole-target consent**. Transport remains IMPORTED; local OBSERVED is the collector claim. The original public target/digest must still be retained separately from host-manifest intake.

## Registry mapping and PQC honesty

Known classical labels cover the supported fixed EC/X25519/X448/FFDHE registrations. Three hybrid codepoints are interpreted using the pinned OpenSSL 3.5.0 registry header:

| Codepoint | Label | Interpretation |
|---|---|---|
| `0x11EB` / 4587 | SecP256r1MLKEM768 | Registered hybrid group selected, not verified implementation/readiness |
| `0x11EC` / 4588 | X25519MLKEM768 | Same |
| `0x11ED` / 4589 | SecP384r1MLKEM1024 | Same |

Source: [OpenSSL `tlsgroups.h`, commit 636dfadc70ce26f2473870570bfd9ec352806b1d](https://github.com/openssl/openssl/blob/636dfadc70ce26f2473870570bfd9ec352806b1d/include/internal/tlsgroups.h), resolved from annotated `openssl-3.5.0` tag `02192e014a72972a398eee3106f0ec369eabc1f1`. Framing follows [RFC 8446 ServerHello](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3) and [key_share](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8).

**Actual hybrid negotiation was not demonstrated in this sandbox.** Hybrid codepoint cases are synthetic parser vectors, not functional KEM/interoperability/FIPS/provider/side-channel/production tests. Unknown IDs are not guessed classical or quantum-safe. A successful classical session does not prove lack of hybrid support; a selected hybrid registration does not establish crypto-library compliance, application migration compatibility, PQC signatures or overall bank PQC readiness.

## Existing evidence pipeline and six BOMs

No separate scanner result database or BOM-first source is introduced. The existing HostSnapshot/receipt/evidence/intake/projection/UI pipeline accepts the additive type. NBOM/CBOM/TechBOM receive the observation; SBOM/HBOM/VBOM get no invented contribution.

The existing stored-only `/tls-session/cyclonedx-1.6` route includes selected-group/raw-hello commitments and interpretation basis on its protocol component, preserves receipt evidence IDs and provenance, and still passes official CycloneDX 1.6 validation. It does not reconnect or create scans/evidence. Composition stays incomplete; no operational dependency fanout or software/HSM-use claim. Existing UI shows the wire-selected group, registry classification and limitations, rejecting promoted fields and stale/wrong-snapshot downloads.

## What the other requested gaps actually need

| Requested gap | Status after this increment | Required defensible evidence |
|---|---|---|
| Non-loopback endpoint acceptance | Adapter supports exact approved numeric endpoints; tests remain owned loopback | Named authorized scope, independently agreed endpoint/pin/version/group truth, permitted operator run and independent retained return. No customer endpoint was supplied or contacted. |
| Broader TLS capability | One selected group now directly observed; exhaustive capability UNKNOWN | Separately approved version/group/cipher matrix and failed-attempt denominator, provider/tool limitations and time-bounded accepted truth. One handshake cannot prove absence. |
| PQC implementation/readiness | Registry interpretation implemented; actual hybrid execution and readiness not qualified | Actual compatible provider/client/server, functional hybrid and signature tests, independent implementation/release/compliance review and app/deployment acceptance. |
| Application/HSM use | **Not implemented by this TLS capture; UNKNOWN** | Time/operation-bound application trace, authenticated module/session/key-public-ID correlation and independently reviewed operation outcome. HSM presence, registered provider or TLS group is insufficient; never request private keys. |
| Complete software inventory | Existing scoped package/binary/container collectors remain incomplete | Agreed asset/rootfs/runtime/language scope, every requested surface's success/failure denominator and independent truth. A TLS endpoint cannot supply a complete SBOM. |
| Actual Windows/container qualification | Existing operator workflow remains open, **not PASS** | Genuine native/platform/image executions, reviewed original returns and negative truth, runtime-image binding where claimed, qualified release/executor and independent approval. Linux tests or more synthetic fixtures cannot substitute. |

See [Windows operator workflow](68-assigned-operator-qualification-workflow.md), [container candidate and blockers](78-verified-oci-content-and-runtime-candidate.md) and the [phase ledger](69-phasewise-universal-collection-build.md). This increment does not remove those gates or enable production jobs.
