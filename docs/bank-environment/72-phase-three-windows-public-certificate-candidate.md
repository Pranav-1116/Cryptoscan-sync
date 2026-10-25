# 72. Phase-wise build — Windows public certificate candidate

## Current position

Continue the ordered architecture, not six independent scanners. Foundation and bounded Linux implementation were delivered in guides 62–71. This increment advances **Phase 3 engineering** without claiming that external Linux/Windows qualification has completed or enabling Windows production jobs.

| Phase | Current implementation boundary |
|---|---|
| 1 — Foundation | Scoped registry/authorization/jobs, typed evidence, original custody and deterministic projections implemented; existing execution/qualification gates remain |
| 2 — Linux | Bounded input profiles, evidence-linked software/relationship views and officially validated incomplete CycloneDX software/crypto exports implemented; real operator acceptance and unsupported relationships remain explicit |
| 3 — Windows | Existing OS/uninstall/file/SCM candidates plus **new exact local public-certificate-store lookup**; native qualification open, universal Windows job authorization still blocked |
| 4 — Containers | Next ordered adapter work after Windows engineering/acceptance gates; existing standalone capabilities are not universal admission |
| 5 — Network | Separate controlled endpoint/session evidence; a Windows certificate is not a negotiated TLS session |
| 6 — Cloud | Future approved account/API adapters, not inferred from host metadata |
| 7 — HSM/hardware | Metadata, hardware identity and operations need their own approved interfaces; no HSM/key-use claim from a certificate |
| 8 — Vendor | Declared/imported supplier evidence must retain basis/revision; issuer identity is not vendor attribution |
| 9 — Correlation | Linux exact metadata joins exist; global physical identity/estate-wide graph is not completed by this increment |
| 10 — Hardening | Existing controls retained; no new claim of HA, complete DR, production clearance or 24/7 staffing |

A BOM remains a projection of evidence, never the source of truth. This Windows candidate emits the existing `CERTIFICATE` fact with original provenance; it does not manufacture a separate BOM or relationships during collection.

## What was built

New `WINDOWS_CERTIFICATE` input with one canonical resource:

```text
windows-cert://current-user/MY/sha1/{40-lowercase-hex}/sha256/{64-lowercase-hex}
```

Locations: `current-user` or `local-machine`. Stores: exactly `MY`, `ROOT` or `CA`. No remote host, arbitrary provider/store path, URI encoding/query, wildcard, subject-name search or enumeration option.

Example input shape (replace both public-certificate digests with independently reviewed values):

```json
{
  "input_id": "payment-public-certificate",
  "kind": "WINDOWS_CERTIFICATE",
  "path": "windows-cert://current-user/MY/sha1/{reviewed-sha1}/sha256/{reviewed-sha256}"
}
```

Braced placeholders are documentation only and **will be rejected** by the real parser. Generate both digests from the same canonical single public DER certificate, not from PEM text. Remove display whitespace and lowercase both hexadecimal values before building the URI. SHA-1 is only the Windows lookup selector—not a trusted identity, signature algorithm, security approval or cryptographic-use finding. The mandatory SHA-256 and SHA-1 are independently checked against the returned DER before facts are emitted.

### Native read boundary

- Loads `crypt32.dll` using `LOAD_LIBRARY_SEARCH_SYSTEM32`, with explicit function prototypes and fixed 32-bit DWORD/pointer-width structures.
- `CertOpenStore(CERT_STORE_PROV_SYSTEM_W)` uses only explicit local location, `CERT_STORE_READONLY_FLAG` and `CERT_STORE_OPEN_EXISTING_FLAG`. No store creation or mutation.
- `CertFindCertificateInStore(CERT_FIND_SHA1_HASH)` selects the exact approved locator. A second find detects ambiguity; a second match refuses rather than silently choosing one.
- Checks native encoding, non-null DER pointer and length before Python copy; reserves fixed caller buffers and charges bounded DER bytes. The byte count is a conservative charged budget, **not network/store traffic measurement**.
- Both hashes must match. Strict existing canonical single-certificate DER parsing produces public-key family/size/curve/signature metadata. No private-key/PFX export, certificate-chain validation, revocation fetch, trust grade, signing operation, key handle or provider-capability claim.
- Previous-context ownership follows the documented native API transfer rule, including error paths. Remaining contexts and store handles close in `finally`; explicit cleanup failure refuses a positive result.
- Denial, missing certificate/store, unknown native error, malformed bytes, changed binding, duplicate match, expiry, elevation and exhausted budget never emit positive certificate facts or `NO_ASSET`.

The native provider may allocate/search internally before returning a context, and its API calls have no independently enforced wall-clock cancellation worker in this candidate. Bounded Python copying does **not** prove bounded native allocation, native latency, zero OS-provider activity or production isolation. These remain native execution/security gates.

## Evidence, contracts and existing product flow

The existing v1 fact/envelope defaults are unchanged. The input-kind enum is extended, with five corresponding published JSON Schemas regenerated. Older clients with pinned enums will reject this new candidate kind; no compatibility with those old clients is claimed. All existing-kind schema shapes/defaults remain unchanged. Runtime validation is stricter than the schema's generic path string: it enforces canonical resource grammar, exact single fact, fingerprint and DER-content commitments.

For a parsed store input, the emitted fingerprint **and receipt content SHA-256** must equal the approved resource digest. Raw public DER is transient local parsing input, not uploaded as a raw certificate body in the snapshot. The existing snapshot/evidence chain stores allowlisted metadata, digests and the approved URI. Hashes still do not establish host authenticity.

An explicitly approved candidate snapshot can use the existing non-production host-evidence approval/intake/inspection/CBOM workflow. Intake remains **IMPORTED** transport; local certificate metadata remains **OBSERVED** only in the interface-specific sense. Existing CBOM export validates against the pinned official CycloneDX 1.6 schemas and records its normal `host.export` audit event. Inspection/export does not query Windows again.

No new dashboard/service/DB table or upload endpoint. The existing host-evidence UI can inspect these existing certificate facts without a new fact shape. Universal registry authorization still rejects Windows targets as future executable capabilities; no remote worker, production allowlist, native-review gate or human approval was bypassed.

### Honest BOM contributions

This input supports public-certificate metadata in the existing host CBOM and evidence/host-system custody. It does **not** establish software inventory, a TLS endpoint/session, hardware origin, HSM key use or a vendor. Windows universal job/materializer admission remains blocked, so this is not a claim that a complete Windows SBOM/NBOM/HBOM/VBOM/TechBOM is now emitted. A future admitted Windows envelope can reuse the same certificate fact for justified projections without re-reading its source.

## Operator-owned native fixture

No Windows host, credential or private key was supplied or contacted here. Operators must select an already-existing public certificate in an authorized fixture store; this code never imports one into a bank store.

1. Prepare/review canonical public DER and its SHA-1/SHA-256 independently. Example read-only hashing on an approved Windows fixture:
   ```powershell
   certutil -hashfile reviewed-public.der SHA1
   certutil -hashfile reviewed-public.der SHA256
   ```
   These hashes are lookup/binding inputs, not signatures or a bank approval.
2. Add the exact input to the reviewed Windows target/manifest and add expected `CERTIFICATE`, fingerprint, known public-key metadata, local basis and `runtime_use: UNKNOWN` to the exact fixture plan. Do not generate expected truth by copying a collector result after execution.
3. Run the existing ordinary-user candidate fixture runner, which refuses unavailable Windows rather than emulating it:
   ```powershell
   python scripts/qualify_host_profile.py --target reviewed-windows-target.json --expectations reviewed-windows-plan.json --windows-candidate --output new-certificate-fixture-result.json
   ```
4. For the existing signed/custodied Windows native-evidence workflow, retain the required reviewed OS/SCM inputs **and** the new certificate input in the exact target/plan. A prior OS/SCM-only scoped result does not qualify this new reader. Follow guides 67–68 and the operator-assigned packet, with a fresh approved release/source lock; no signatures are generated here.
5. Independently exercise current-user/local-machine access, missing/denied certificate/store, duplicate/collision cases, native allocation/latency, handle cleanup, elevated-token refusal and cancellation/isolation. Portable mocked errors do not prove real ACL denials.

Optional native test: set `CRYPTOSCAN_WINDOWS_CERTIFICATE_RESOURCE` to the reviewed exact resource and run `services/inventory/tests/test_windows_certificates.py` as an actual ordinary Windows user. Missing Windows or missing operator fixture is a **skip**, never a native pass.

## Evidence sources and remaining work

Constants/ABI reference: [mingw-w64 wincrypt.h at pinned revision 99144bb19f57a51f7ed82c5c9c1457647565c36b](https://github.com/mingw-w64/mingw-w64/blob/99144bb19f57a51f7ed82c5c9c1457647565c36b/mingw-w64-headers/include/wincrypt.h).
Previous-context ownership: [Microsoft SDK API documentation source](https://github.com/MicrosoftDocs/sdk-api/blob/881e4f423aa11669cf6549c8d10edd6d463deb19/sdk-api-src/content/wincrypt/nf-wincrypt-certfindcertificateinstore.md), `pPrevCertContext` and remarks. No SDK source archive is added to the product.

[Local readiness record](../readiness-evidence/windows-certificate-candidate-2026-10-25.md) separates portable contracts, SQL custody and frontend regression from native skips. Remaining Phase 3 implementation/acceptance includes loaded DLL/process identity, CNG/CAPI provider metadata, negotiated TLS/listener attribution, TPM/firmware and actual native denial/isolation/cancellation evidence. Those are not replaced by this certificate lookup. Proceed phase-wise; do not assert Windows production readiness or silently skip the remaining gates.
