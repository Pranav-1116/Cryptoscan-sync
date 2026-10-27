# 04 — How scanning produces all six BOMs

[FAQ index](README.md) · Questions Q037–Q048.

## Q037. Does CryptoScan run six separate scans for six BOMs?

No. The intended and implemented foundation pattern is: approved collection → typed facts/errors → retained evidence → central normalization/identity → justified relationships → supported projections.

A public certificate can inform crypto metadata; a listener can inform network metadata; the same observation may also contribute to TechBOM. Reuse the same evidence reference rather than collecting it once per BOM. However, one session does not magically contain every type of evidence: extra authorized sources may be needed, and some projections remain empty/partial.

## Q038. How does SBOM collection actually work?

Supported software inputs identify packages/dependencies or file/mapped-path metadata in their specific scope. Retain source revision/artifact identity when genuinely supplied, collection method, timestamp, package/version facts and evidence references.

The Linux software path separates installed packages, binary presence and mapped paths. Its CycloneDX 1.6 software export is validated against pinned official schemas with incomplete composition. It does not invent licenses, package URLs, artifact hashes or a dependency graph when those were not established. Installation alone is not runtime use, and a mapped filename is not a package/version match.

## Q039. How does CBOM detection actually work?

Depending on the admitted source, deterministic parsing can identify source crypto constructs, public certificate parameters or declared crypto configuration. Each observation must retain its source/meaning rather than be promoted to production usage.

For example, a certificate's RSA public key size describes that public certificate. A source callsite describes code in a snapshot. A config directive is DECLARED configuration. Windows DLL names and CNG registration labels in the current candidates **do not emit crypto-use components**; their algorithm/use stays UNKNOWN. Distinguish capability, implementation, invocation, key parameters and real traffic.

## Q040. How does NBOM collection work?

NBOM concerns supported network observations or declarations: endpoints, addresses, ports, protocols, TLS session/certificate information and observation time. A host listener fact is narrower than a negotiated TLS session; an active endpoint collector needs separate admission and probe approval.

Port 443 does not prove TLS, a local listener does not prove external reachability, and a single TLS 1.3 handshake does not prove older protocols are impossible. Certificate-to-listener/process attribution requires its own evidence. The universal network adapter is not made production-qualified merely by these data types.

## Q041. How does HBOM collection work?

HBOM records supported hardware/security-hardware metadata with explicit provenance. Current narrow Linux examples include CPU topology fields, available DMI strings and a kernel-reported TPM major version. Separate approved HSM/hardware evidence paths can retain supplied product/firmware/mode details.

These do not automatically prove physical asset identity, serial authenticity, hardware-backed key origin, certification or application use. TPM quote/enrollment/replay tooling is a separate evidence workflow; having that code is not proof that an arbitrary host supplied a valid hardware attestation.

## Q042. How does VBOM collection work?

VBOM represents suppliers/products/revisions and supplier dependencies supported by original evidence. Sources may include bank records, approved supplier SBOM/CBOM, questionnaires or reviewed declarations.

Imported documents remain IMPORTED, and a vendor's PQC claim remains a declaration unless independently established through an approved interface. Supplier signature/origin checks and quarantine/review do not certify the supplier's statements. A certificate issuer, package name or fixed Microsoft provider name is not automatic vendor attribution or contract evidence.

## Q043. How does TechBOM combine the other five BOMs?

TechBOM is an integration/relationship view, not another collector. It connects scoped systems, software, crypto, endpoints, hardware and vendors where evidence or a permitted reviewed association supports the link.

Each node/edge needs identity, provenance, evidence reference, time/freshness and relationship meaning. Existing Linux exact metadata joins and reviewed associations are bounded; they are not a complete attested global estate graph. A direct host metadata slot is not automatically the real-world physical/software asset identity.

## Q044. How can one fact contribute to more than one BOM?

Examples of current scoped domain classification:

| Fact | Supported contribution | What is not added automatically |
|---|---|---|
| Installed package | SBOM + TechBOM | Actual crypto invocation or deployed dependency |
| Public certificate | CBOM + TechBOM | Served endpoint, private key or HSM origin |
| TCP listener | NBOM + TechBOM | Negotiated TLS or application ownership |
| Narrow hardware metadata | HBOM + TechBOM | Application/hardware-key operation |
| Windows module path | SBOM + TechBOM metadata classification | Package version, DLL authenticity or algorithm use |
| CNG registration metadata | TechBOM metadata classification | Tested capability, CBOM algorithm-use component or vendor authenticity |

Classification/reference counts are not necessarily a materialized standardized document or production-admitted Windows export. Vendor contribution requires separate supported evidence; it is not guessed from these rows.

## Q045. Are all six outputs standardized CycloneDX documents?

No. Do not equate shared BOM-domain counts, application JSON views and standardized exports. Selected existing software/crypto exports validate against pinned official CycloneDX 1.6 schemas. Other views have their own internal contracts and readiness boundaries.

Schema validation proves structural compliance, not complete discovery, correctness of the supplied claims, deployment, authenticity or bank acceptance. A valid empty/incomplete BOM must still disclose unsupported or failed source coverage. Do not label an internal NBOM/HBOM/VBOM/TechBOM JSON projection as standardized without its actual validated format.

## Q046. How are duplicate assets and changing versions handled?

Use scoped stable identifiers and the appropriate source identity: target/system, release artifact digest when established, certificate fingerprint, package identity, or exact process incarnation. Preserve observations/revisions rather than invent a new real-world asset each day or collapsing everything by name.

The current foundation's stable metadata-slot identity is explicitly **not attested global asset identity**. Reconcile upgrades and cross-source matches only under supported rules; ambiguous packages or paths must remain ambiguous. A hash of path text is not a hash of file contents.

## Q047. How are relationships such as “Payments API uses an HSM” proven?

Require evidence for that exact relationship and its meaning. It might be an explicitly reviewed declaration, imported supplier/bank record, supported metadata inference or a separately qualified operation observation. Preserve which one it is; do not promote DECLARED/INFERRED/IMPORTED into OBSERVED invocation.

HSM presence, a PKCS#11 library filename, a certificate or co-existing host records are insufficient. If no supported relationship exists, show UNKNOWN/unestablished. A dependency line in a diagram is not proof of a live cryptographic operation.

## Q048. How are failures, coverage and partial BOMs reported?

Keep each approved input's actual status, reason and emitted facts. Failed/denied/unreachable/unsupported/unrequested is not NO_ASSET. An overall partial result must retain the missing surfaces.

The existing surface metric is **parsed approved inputs ÷ approved inputs**, not the percentage of all bank assets found. No denominator means no meaningful completeness percentage. Reference counts across BOMs overlap and must not be summed as distinct assets. Re-materialization reads the same committed evidence; a fresh scan requires new authorized collection and evidence.

### References

[Six-BOM evidence paths](../bank-environment/49-six-bom-evidence-paths.md) · [Linux software export/relationships](../bank-environment/71-linux-relationships-and-validated-sbom.md) · [coverage semantics](../bank-environment/69-phasewise-universal-collection-build.md) · [CNG limits](../bank-environment/74-phase-three-windows-cng-registration-candidate.md)
