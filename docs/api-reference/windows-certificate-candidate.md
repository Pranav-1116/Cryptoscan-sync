# Windows public-certificate-store candidate input

This extends the existing offline host metadata contract; **no new execution endpoint** is added.

```text
kind: WINDOWS_CERTIFICATE
path: windows-cert://{current-user|local-machine}/{MY|ROOT|CA}/sha1/{40 lowercase hex}/sha256/{64 lowercase hex}
```

The exact local store and both digests must be approved in the manifest before collection. Wildcards, remote locations, arbitrary store/provider names, subject-name searches, query strings, uppercase/missing digests and encoded aliases refuse. SHA-1 selects the Windows native hash index only; SHA-256 is mandatory and both values are recomputed from the returned public DER. The selector does not become a SHA-1 crypto-use finding or a trust statement.

## Receipt and fact

- `PARSED / METADATA_ONLY`: exactly one existing `HostFact(kind="CERTIFICATE", purpose="PUBLIC_KEY_METADATA", local_basis="OBSERVED")`.
- Both the fact `fingerprint_sha256` and receipt `content_sha256` must match the approved SHA-256 URI segment; altered bindings fail model/intake validation.
- Algorithm/key-size/curve/signature fields describe parsed public-certificate metadata, not native key operations, effective TLS, trust, revocation status, hardware/key origin or production application use.
- `runtime_use` stays UNKNOWN; qualification/attestation flags stay false.
- Failed reads have no positive facts/content digest. Denied, missing, changed, malformed, ambiguous, over-budget, unavailable and wrong-platform outcomes remain gaps, not `NO_ASSET`.
- The charged byte count reserves native-call buffers plus DER-copy bytes; it is not a native provider allocation or network-traffic measurement.

The raw certificate body is transient local input, not a new raw snapshot field. Existing v1 defaults/fact shape do not change. The input enum is extended in five published JSON Schemas; older clients pinned to the previous enum will reject the new kind. Schema path strings alone do not replace runtime canonical-resource validation.

## Candidate collection and existing intake

Use the reviewed Windows target-spec CLI with `--windows-candidate`, or the existing explicitly scoped legacy/library path on actual ordinary-user Windows. Linux refuses native acquisition. The privilege/time/byte/fact guards apply before native calls. Certificate-store access uses fixed read-only/existing local store flags, System32 DLL loading and two bounded-result native finds; no enumeration/private-key/mutation API is exposed. Native provider internal allocation and elapsed-time cancellation remain qualification gates.

The existing `/api/v1/host-evidence/approvals` → approved intake → snapshot/CBOM flow can retain these **IMPORTED candidate receipts**. It does not execute a collector. Existing CBOM export rechecks original custody, validates against pinned official CycloneDX 1.6 schemas and adds the normal `host.export` audit event. No source is rescanned on read/export.

Universal `/api/v1/collection/targets/{id}/authorize` remains blocked for Windows targets. This input does not expand production workers, remote SSH/WinRM/API modes or the production execution allowlist. The existing native Windows acceptance packet's OS/SCM scope is not silently treated as qualification of this new certificate interface.

See [guide 72](../bank-environment/72-phase-three-windows-public-certificate-candidate.md) for phase order, independent expected truth, native fixture commands and remaining gates. No credentials or private keys are required in chat or exported evidence.
