# Synthetic banking CBOM and planning report

**2026-10-24. This is not a customer reference, bank scan, comparable-bank
engagement or performance result.** Eight manually supplied metadata records
exercise the existing generator and planning engine. No detector was run to
produce these eight rows. Eight inputs → eight exported assets is a conversion
check, **not discovery recall or estate completeness**.

## Open the actual outputs

- [Native CycloneDX 1.6 JSON](cbom.cyclonedx16.json): full pinned upstream JSON
  schema validation plus local-reference integrity, not just the old subset.
- [Machine-readable report](report.json): actual planning-engine output over
  these synthetic inputs, with explicit qualification limits.
- [Input records and business systems](inputs.json): reviewable source of every
  assertion. Owners, classifications, retention and locations are invented
  fixture context, not discovered or independently verified facts.

| Synthetic record | Purpose of the example | Important boundary |
|---|---|---|
| Payments RSA-2048 | Confidentiality migration / retention | No live TLS handshake or observed key use |
| Payments ECDSA | Authentication/signing migration | Signature migration is not ciphertext HNDL |
| Ledger AES-256-GCM | Algorithm, key-size and mode metadata | No deployment/correct-use claim |
| Lab ML-KEM-768 | FIPS 203 parameter identity | Candidate name, not negotiated use or module validation |
| Lab ML-DSA-65 | FIPS 204 parameter identity | No actual signing/throughput exercise |
| Lab SLH-DSA-SHA2-128s | Full FIPS 205 parameter identity | No native signing or certificate pilot |
| Supplier opaque crypto | Explicit unknown supplier implementation | Not reverse-engineered SaaS visibility |
| Legacy 3DES | Classically weak crypto requiring review | Not a third Shor-vulnerable asymmetric algorithm |

## How to read the result

The existing model returns eight sites, three migration-review sites (two
Shor-vulnerable and one classically broken), three algorithm candidates,
**zero verified-ready sites**, and one unknown algorithm. Use `by_threat_type` to distinguish the two Shor cases from legacy 3DES;
the human summary now says “migration-review candidates”, not that all three
are Shor-vulnerable.

Mosca uses the model's **2030 assumption**, a fixture date of 2026-10-24 and
maximum supplied retention of 12 years. Migration duration is unknown. This
is a scenario, not a quantum-arrival forecast, bank deadline or current
regulatory interpretation. The report's prose and scores remain heuristic
planning output, not risk acceptance. No global accuracy percentage is inferred.

`compositions.aggregate = incomplete` deliberately refuses a complete inventory
claim. This example supplies no dependency graph; the generator does not invent
runtime dependency links from simple inventory membership. Existing system and
portfolio API tests separately exercise declared relationships and their
incoming/outgoing direction; these still do not prove replacement compatibility.

## Format and confidentiality limits

The native export is a **metadata profile**, not a lossless arbitrary-document
converter: names/IDs, native algorithm properties, source occurrences and
allowlisted business properties are carried. Raw snippets, arbitrary detector
payloads, key values and certificate bodies are not copied. OIDs from the legacy
family table, fabricated confidence, and certification claims are not promoted.
Metadata itself can be sensitive: authorize/redact labels and paths under the
bank's policy before export. No blanket zero-sensitive-data-egress claim follows.

FIPS parameter-set identifiers (for example `768`, `65`, `SHA2-128s`) are not
public-key sizes or security-bit counts. The registry now marks its catalog
public-key lengths explicitly as `public_key_bytes`; an input record's legacy
`key_size` field is retained separately with **unestablished unit provenance**
for PQC, rather than being substituted for the native parameter-set identifier.

Full schema validation is not independent schema/tool interoperability approval.
This pass supports JSON; native 1.6 XML is explicitly refused. Legacy 1.5 JSON/XML
remain compatibility paths and are **not newly qualified CycloneDX CBOM formats**.

## Reproduce without overwriting retained examples

From the repository root, in the locked Python environment:

```bash
python docs/readiness-evidence/bank-original45-2026-10-24/reproduce-sample.py /external/synthetic-output
```

The runner reads only the committed synthetic fixture and writes a different
output directory. It uses a fixed fixture timestamp, not a claimed observation
time. It performs no scan, DB connection, network request, HSM operation or key
generation. Compare the output bytes against these examples; do not replace
retained evidence to hide a mismatch.
